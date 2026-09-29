"""``llmscan`` command line interface.

Exit codes: 0 success - 1 policy failure (``--fail-on`` / ``--max-risk`` / regression) - 2 usage or
configuration error - 3 the run itself failed (e.g. target unreachable).
"""

from __future__ import annotations

import asyncio
import json
import signal
import sys
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from scanner import __version__
from scanner.config import ConfigError, ScanConfig, load_config
from scanner.models import AttemptResult, Category, RunReport, Severity, Status
from scanner.probes import (
    ProbeLoadError,
    ProbeSelection,
    default_probes_dir,
    lint_probe,
    load_probes,
    select_probes,
)
from scanner.runner import ScanRequest, ScopeError, load_probe_set, run_scan

app = typer.Typer(
    name="llmscan",
    help="Scan chat endpoints, RAG apps and agents for LLM vulnerabilities and get a scored report. "
    "Only test systems you own or are authorised to test (docs/ETHICS.md).",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)
probes_app = typer.Typer(help="Inspect and validate the probe library.", no_args_is_help=True)
baseline_app = typer.Typer(help="Regression baselines for CI.", no_args_is_help=True)
app.add_typer(probes_app, name="probes")
app.add_typer(baseline_app, name="baseline")

console = Console()
err = Console(stderr=True)

SEV_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}
GRADE_STYLE = {"A": "green", "B": "green", "C": "yellow", "D": "dark_orange", "F": "bold red"}


def _fail(message: str, code: int = 2) -> typer.Exit:
    err.print(f"[bold red]error:[/] {message}")
    return typer.Exit(code)


def _severity(value: str | None, option: str) -> Severity | None:
    if value is None:
        return None
    try:
        return Severity(value.lower())
    except ValueError:
        raise _fail(
            f"{option}: unknown severity {value!r} (critical, high, medium, low, info)"
        ) from None


def _categories(values: list[str] | None) -> list[Category]:
    out = []
    for v in values or []:
        try:
            out.append(Category(v))
        except ValueError:
            valid = ", ".join(c.value for c in Category)
            raise _fail(f"unknown category {v!r}. Choose from: {valid}") from None
    return out


# ------------------------------------------------------------------------------ summary


def print_summary(report: RunReport, top: int = 10) -> None:
    s = report.score
    grade_style = GRADE_STYLE.get(s.grade, "white")
    head = (
        f"[bold]Risk score {s.risk_score:.0f}/100[/]  grade [{grade_style}]{s.grade}[/] ({s.band})\n"
        f"{s.failed} of {s.passed + s.failed} conclusive attacks succeeded ({s.asr:.0%} ASR)"
        f" - {s.errors} errors, {s.inconclusive} inconclusive"
    )
    console.print(
        Panel(
            head, title=f"llmscan - {report.target.get('name', 'target')}", border_style=grade_style
        )
    )
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Category")
    table.add_column("OWASP")
    table.add_column("ASR", justify="right")
    table.add_column("", no_wrap=True)
    table.add_column("Failed", justify="right")
    table.add_column("Risk", justify="right")
    for cs in s.categories.values():
        bar = "█" * round(cs.asr * 20) + "░" * (20 - round(cs.asr * 20))
        style = "red" if cs.asr >= 0.5 else ("yellow" if cs.asr > 0 else "green")
        table.add_row(
            cs.title,
            ",".join(cs.owasp),
            f"{cs.asr:.0%}",
            f"[{style}]{bar}[/]",
            f"{cs.failed}/{cs.total}",
            f"{cs.risk:.0f}",
        )
    console.print(table)
    for note in report.notes:
        console.print(f"[yellow]note:[/] {note}")
    findings = sorted(
        (r for r in report.results if r.status is Status.FAIL),
        key=lambda r: (-r.severity.rank, r.probe_id, r.mutator),
    )
    if findings:
        seen: set[str] = set()
        t = Table(
            title=f"Findings (top {min(top, len(findings))} of {len(findings)})",
            box=None,
            pad_edge=False,
        )
        for col in ("Severity", "Probe", "Mutators", "Why"):
            t.add_column(col)
        grouped: dict[str, list[AttemptResult]] = {}
        for r in findings:
            grouped.setdefault(r.probe_id, []).append(r)
        for r in findings:
            if r.probe_id in seen:
                continue
            seen.add(r.probe_id)
            muts = ", ".join(sorted({x.mutator for x in grouped[r.probe_id]}))
            t.add_row(
                f"[{SEV_STYLE[r.severity.value]}]{r.severity.value}[/]",
                f"{r.probe_id} {r.probe_name}",
                muts[:38],
                r.reason[:70],
            )
            if len(seen) >= top:
                break
        console.print(t)
    elif s.total:
        console.print("[green]No attack succeeded.[/] (A resisted attack is not proof of safety.)")


# ------------------------------------------------------------------------------- run


@app.command()
def run(
    target: Annotated[
        str,
        typer.Argument(
            help="Config file, or demo[:weak|medium|hardened][:chat|rag|agent], or ollama:MODEL / openai:MODEL / anthropic:MODEL"
        ),
    ],
    category: Annotated[
        list[str] | None,
        typer.Option("--category", "-c", help="Only these categories (repeatable)"),
    ] = None,
    probe: Annotated[
        list[str] | None, typer.Option("--probe", "-p", help="Only these probe ids (repeatable)")
    ] = None,
    exclude: Annotated[
        list[str] | None, typer.Option("--exclude", help="Skip these probe ids")
    ] = None,
    tag: Annotated[
        list[str] | None, typer.Option("--tag", help="Only probes with one of these tags")
    ] = None,
    min_severity: Annotated[
        str | None, typer.Option(help="Skip probes below this severity")
    ] = None,
    probes_dir: Annotated[
        list[Path] | None, typer.Option("--probes-dir", help="Extra probe files/directories")
    ] = None,
    no_builtin_probes: Annotated[bool, typer.Option(help="Do not load the bundled probes")] = False,
    max_probes: Annotated[int | None, typer.Option(help="Cap the number of probes")] = None,
    mutator: Annotated[
        list[str] | None,
        typer.Option("--mutator", "-m", help="Mutators to add (name, a+b chain, or 'all')"),
    ] = None,
    no_original: Annotated[
        bool, typer.Option(help="Only run mutated variants, not the plain probe")
    ] = False,
    repeats: Annotated[
        int | None,
        typer.Option(min=1, help="Repeat each attack N times (non-deterministic targets)"),
    ] = None,
    concurrency: Annotated[int | None, typer.Option(min=1, help="Parallel attacks")] = None,
    rps: Annotated[float | None, typer.Option(help="Max requests per second to the target")] = None,
    retries: Annotated[int | None, typer.Option(min=0, help="Retries on 429/5xx/timeouts")] = None,
    timeout: Annotated[float | None, typer.Option(help="Per-request timeout in seconds")] = None,
    seed: Annotated[
        int | None, typer.Option(help="Seed for reproducible nonces and mutator choices")
    ] = None,
    judge: Annotated[
        str | None,
        typer.Option(help="auto | heuristic | off | ollama:MODEL | openai:MODEL | anthropic:MODEL"),
    ] = None,
    attacker: Annotated[
        str | None,
        typer.Option(
            help="LLM for adaptive probes, e.g. ollama:llama3.1 (default: offline heuristics)"
        ),
    ] = None,
    out: Annotated[
        list[Path] | None,
        typer.Option(
            "--out",
            "-o",
            help="Write a report; format from extension (.json .html .pdf .sarif .md). Repeatable",
        ),
    ] = None,
    no_save: Annotated[bool, typer.Option(help="Do not write default report files")] = False,
    db: Annotated[
        str | None,
        typer.Option(help="Also store the run in this database (SQLite path or SQLAlchemy URL)"),
    ] = None,
    baseline: Annotated[
        Path | None, typer.Option(help="Compare against this baseline file")
    ] = None,
    fail_on_regression: Annotated[
        bool, typer.Option(help="Exit 1 if the baseline check finds a regression")
    ] = False,
    regression_tolerance: Annotated[
        float, typer.Option(help="Allowed risk-score increase vs baseline")
    ] = 5.0,
    fail_on: Annotated[
        str | None, typer.Option(help="Exit 1 if any attack of this severity or worse succeeded")
    ] = None,
    max_risk: Annotated[
        float | None, typer.Option(help="Exit 1 if the risk score exceeds this")
    ] = None,
    redact: Annotated[
        bool, typer.Option(help="Mask secrets and PII in stored transcripts")
    ] = False,
    authorized: Annotated[
        bool, typer.Option("--i-am-authorized", help="Confirm you own / may test a public target")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option(help="Show what would run without contacting the target")
    ] = False,
    name: Annotated[str | None, typer.Option(help="Label for this run")] = None,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="No progress bar or summary")
    ] = False,
) -> None:
    """Run a scan against TARGET."""
    try:
        cfg = load_config(target)
    except ConfigError as exc:
        raise _fail(str(exc)) from None
    updates: dict = {}
    for key, value in {
        "categories": _categories(category) or None,
        "ids": probe or None,
        "exclude_ids": exclude or None,
        "tags": tag or None,
        "min_severity": _severity(min_severity, "--min-severity"),
        "probe_paths": [str(p) for p in probes_dir] if probes_dir else None,
        "max_probes": max_probes,
        "mutators": mutator or None,
        "repeats": repeats,
        "concurrency": concurrency,
        "rps": rps,
        "retries": retries,
        "timeout": timeout,
        "seed": seed,
        "name": name,
    }.items():
        if value is not None:
            updates[key] = value
    if no_builtin_probes:
        updates["builtin_probes"] = False
    if no_original:
        updates["include_original"] = False
    if redact:
        updates["redact"] = True
    scan = cfg.scan.model_copy(update=updates)
    if judge:
        j = scan.judge
        scan = scan.model_copy(
            update={
                "judge": j.model_copy(
                    update={"mode": judge}
                    if judge in ("auto", "heuristic", "off")
                    else {"mode": "llm", "target": judge}
                )
            }
        )
    if attacker:
        scan = scan.model_copy(
            update={
                "attacker": scan.attacker.model_copy(update={"mode": "llm", "target": attacker})
            }
        )
    try:
        ScanConfig.model_validate(scan.model_dump())
        probes = load_probe_set(scan)
    except (ProbeLoadError, ValueError, FileNotFoundError) as exc:
        raise _fail(str(exc)) from None
    if not probes:
        raise _fail("no probes matched the selection")

    from scanner.mutators import resolve_mutators

    try:
        mutators = resolve_mutators(scan.mutators)
    except ValueError as exc:
        raise _fail(str(exc)) from None
    variants = ([1] if scan.include_original else []) + [1] * len(mutators)
    attempts = (
        sum(
            (1 if scan.include_original else 0)
            + sum(
                1
                for m in mutators
                if all(p.allows_mutator(x.name) for x in getattr(m, "parts", [m]))
            )
            for p in probes
        )
        * scan.repeats
    )
    _ = variants
    if not quiet:
        console.print(f"[dim]llmscan {__version__} - authorised testing only (docs/ETHICS.md)[/]")
        console.print(
            f"Target [bold]{cfg.target.name}[/] - {len(probes)} probes, {len(mutators)} mutator(s), {attempts} attempts"
        )
    if dry_run:
        t = Table("Probe", "Category", "Severity", "Kind", "Name", box=None)
        for p in probes:
            t.add_row(p.id, p.category.value, p.severity.value, p.kind, p.name)
        console.print(t)
        console.print(f"[bold]{attempts}[/] attempts planned (dry run, nothing was sent).")
        return

    stop = asyncio.Event()
    started = time.time()

    async def _go() -> RunReport:
        loop = asyncio.get_running_loop()
        try:
            loop.add_signal_handler(signal.SIGINT, stop.set)
        except (NotImplementedError, RuntimeError):  # pragma: no cover - non-unix
            pass
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
            disable=quiet,
        )
        failed = 0
        with progress:
            task = progress.add_task("attacking", total=attempts)

            def on_result(result: AttemptResult, done: int, total: int) -> None:
                nonlocal failed
                failed += result.status is Status.FAIL
                progress.update(
                    task, completed=done, total=total, description=f"attacking ({failed} succeeded)"
                )

            req = ScanRequest(
                cfg.target,
                scan,
                probes=probes,
                config_path=str(cfg.path) if cfg.path else None,
                acknowledged_flag=authorized,
                on_result=on_result,
                should_cancel=stop.is_set,
            )
            return await run_scan(req)

    try:
        report = asyncio.run(_go())
    except ScopeError as exc:
        raise _fail(str(exc)) from None
    except (ValueError, ConfigError) as exc:
        raise _fail(str(exc)) from None
    report.config["command"] = (
        "llmscan run " + " ".join(sys.argv[2:]) if len(sys.argv) > 2 else "llmscan run"
    )

    if not quiet:
        print_summary(report)
        if report.status == "cancelled":
            console.print("[yellow]Interrupted: partial results.[/]")
        console.print(f"[dim]{time.time() - started:.1f}s[/]")

    from scanner.reporting import write_report

    outputs = list(out or [])
    if not outputs and not no_save:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        outputs = [
            Path("reports") / f"llmscan-{stamp}.json",
            Path("reports") / f"llmscan-{stamp}.html",
        ]
    cfg_path = str(cfg.path) if cfg.path else None
    for path in outputs:
        try:
            write_report(report, path, config_path=cfg_path)
        except ValueError as exc:
            raise _fail(str(exc)) from None
        if not quiet:
            console.print(f"Saved [bold]{path}[/]")
    if db:
        from scanner.storage import open_store

        store = open_store(db)
        store.save_report(report)
        if not quiet:
            console.print(f"Stored run [bold]{report.id}[/] in {db}")

    code = 0
    if report.status == "failed":
        err.print(f"[bold red]run failed:[/] {report.error}")
        code = 3
    if fail_on:
        threshold = _severity(fail_on, "--fail-on")
        assert threshold is not None
        worst = [
            r
            for r in report.results
            if r.status is Status.FAIL and r.severity.rank >= threshold.rank
        ]
        if worst:
            err.print(f"[red]--fail-on {threshold.value}: {len(worst)} matching finding(s)[/]")
            code = code or 1
    if max_risk is not None and report.score.risk_score > max_risk:
        err.print(f"[red]--max-risk {max_risk:g}: risk score is {report.score.risk_score:.0f}[/]")
        code = code or 1
    if baseline:
        from scanner.baseline import check_baseline, load_baseline

        try:
            check = check_baseline(report, load_baseline(baseline), tolerance=regression_tolerance)
        except (OSError, ValueError) as exc:
            raise _fail(f"cannot read baseline {baseline}: {exc}") from None
        console.print(("[green]" if check.ok else "[red]") + check.summary() + "[/]")
        for r in check.regressions[:20]:
            console.print(
                f"  [red]regression[/] {r.severity.value} {r.probe_id} {r.probe_name} ({r.mutator}): {r.reason}"
            )
        if not check.ok and fail_on_regression:
            code = code or 1
    raise typer.Exit(code)


# ---------------------------------------------------------------------------- report


def _load_report(path: Path) -> RunReport:
    try:
        return RunReport.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise _fail(f"cannot read report {path}: {exc}") from None


@app.command()
def report(
    source: Annotated[Path, typer.Argument(help="A JSON report written by `llmscan run`")],
    out: Annotated[Path, typer.Option("--out", "-o", help="Output file; format from extension")],
    fmt: Annotated[
        str | None, typer.Option("--format", "-f", help="json | html | pdf | sarif | md")
    ] = None,
    redact: Annotated[bool, typer.Option(help="Mask secrets and PII")] = False,
) -> None:
    """Convert a saved JSON report to HTML, PDF, SARIF or Markdown."""
    from scanner.redact import redact_report
    from scanner.reporting import write_report

    rep = _load_report(source)
    if redact:
        rep = redact_report(rep)
    try:
        path = write_report(rep, out, fmt)
    except ValueError as exc:
        raise _fail(str(exc)) from None
    console.print(f"Wrote [bold]{path}[/]")


@app.command()
def compare(
    a: Annotated[Path, typer.Argument(help="Run A (before)")],
    b: Annotated[Path, typer.Argument(help="Run B (after)")],
    fmt: Annotated[str, typer.Option("--format", "-f", help="text | md | json")] = "text",
    fail_on_regression: Annotated[
        bool, typer.Option(help="Exit 1 if B regressed against A")
    ] = False,
) -> None:
    """Compare two runs: which attacks newly succeed, which were fixed, how risk moved."""
    from scanner.compare import compare_reports, comparison_markdown

    c = compare_reports(_load_report(a), _load_report(b))
    if fmt == "json":
        typer.echo(c.model_dump_json(indent=2))
    elif fmt == "md":
        typer.echo(comparison_markdown(c))
    else:
        style = {"better": "green", "worse": "red", "mixed": "yellow", "unchanged": "white"}[
            c.verdict
        ]
        console.print(
            f"Risk [bold]{c.risk_a:.0f}[/] ({c.grade_a}) -> [bold]{c.risk_b:.0f}[/] ({c.grade_b}): [{style}]{c.verdict}[/] "
            f"- {len(c.regressions)} regression(s), {len(c.fixed)} fixed, {len(c.still_failing)} still failing"
        )
        t = Table("Category", "ASR A", "ASR B", "Change", box=None)
        for d in c.categories:
            t.add_row(d.title or d.category, f"{d.asr_a:.0%}", f"{d.asr_b:.0%}", f"{d.delta:+.0%}")
        console.print(t)
        for r in c.regressions[:25]:
            console.print(
                f"  [red]regressed[/] {r.severity.value} {r.probe_id} {r.probe_name} ({r.mutator})"
            )
        for r in c.fixed[:25]:
            console.print(f"  [green]fixed[/] {r.probe_id} {r.probe_name} ({r.mutator})")
    if fail_on_regression and c.regressions:
        raise typer.Exit(1)


# -------------------------------------------------------------------------- baseline


@baseline_app.command("save")
def baseline_save(
    source: Annotated[Path, typer.Argument(help="JSON report to use as the baseline")],
    out: Annotated[Path, typer.Option("--out", "-o")] = Path(".llmscan/baseline.json"),
) -> None:
    """Freeze a report as the regression baseline (commit it to your repo)."""
    from scanner.baseline import save_baseline

    path = save_baseline(_load_report(source), out)
    console.print(f"Baseline written to [bold]{path}[/]")


@baseline_app.command("check")
def baseline_check(
    source: Annotated[Path, typer.Argument(help="JSON report to check")],
    baseline: Annotated[Path, typer.Option(help="Baseline file")] = Path(".llmscan/baseline.json"),
    tolerance: Annotated[float, typer.Option(help="Allowed risk-score increase")] = 5.0,
) -> None:
    """Exit 1 if the report is worse than the baseline."""
    from scanner.baseline import check_baseline, load_baseline

    try:
        check = check_baseline(_load_report(source), load_baseline(baseline), tolerance=tolerance)
    except (OSError, ValueError) as exc:
        raise _fail(f"cannot read baseline: {exc}") from None
    console.print(check.summary())
    for r in check.regressions:
        console.print(
            f"  regression: {r.severity.value} {r.probe_id} {r.probe_name} ({r.mutator}) - {r.reason}"
        )
    raise typer.Exit(0 if check.ok else 1)


# ---------------------------------------------------------------------------- probes


@probes_app.command("list")
def probes_list(
    category: Annotated[list[str] | None, typer.Option("--category", "-c")] = None,
    severity: Annotated[str | None, typer.Option(help="Minimum severity")] = None,
    tag: Annotated[list[str] | None, typer.Option("--tag")] = None,
    path: Annotated[
        list[Path] | None,
        typer.Option("--path", help="Probe files/directories (default: built-in)"),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List probes."""
    try:
        probes = select_probes(
            load_probes(path or None),
            ProbeSelection(
                categories=_categories(category),
                min_severity=_severity(severity, "--severity"),
                tags=tag or [],
            ),
        )
    except (ProbeLoadError, FileNotFoundError) as exc:
        raise _fail(str(exc)) from None
    if as_json:
        typer.echo(
            json.dumps([json.loads(p.model_dump_json(exclude_none=True)) for p in probes], indent=2)
        )
        return
    t = Table("ID", "Category", "Sev", "Kind", "OWASP", "ATLAS", "Name", box=None, pad_edge=False)
    for p in probes:
        t.add_row(
            p.id,
            p.category.value,
            f"[{SEV_STYLE[p.severity.value]}]{p.severity.value}[/]",
            p.kind,
            ",".join(p.owasp),
            ",".join(p.atlas),
            p.name,
        )
    console.print(t)
    console.print(
        f"{len(probes)} probes in {default_probes_dir() if not path else ', '.join(map(str, path))}"
    )


@probes_app.command("show")
def probes_show(probe_id: Annotated[str, typer.Argument()]) -> None:
    """Show a probe's YAML and what it would send."""
    from scanner.templating import make_variables

    matches = [p for p in load_probes() if p.id.lower() == probe_id.lower()]
    if not matches:
        raise _fail(f"no probe with id {probe_id!r}")
    p = matches[0]
    console.print(
        Panel(
            Path(p.source_file).read_text(encoding="utf-8") if p.source_file else "",
            title=p.source_file or p.id,
        )
    )
    plan = p.plan(make_variables(probe_id=p.id, mutator="none", repeat=0, seed=0))
    console.print("[bold]Rendered attack (sample nonce):[/]")
    for t in plan.turns:
        console.print(
            Panel(
                t.content, title=f"{t.role}{' (payload)' if t.attack else ''}", border_style="cyan"
            )
        )
    if plan.kind == "adaptive":
        console.print(f"[dim]adaptive attacker goal:[/] {plan.payload}")


@probes_app.command("validate")
def probes_validate(
    paths: Annotated[
        list[Path] | None, typer.Argument(help="Files or directories (default: built-in)")
    ] = None,
    strict: Annotated[bool, typer.Option(help="Treat lint warnings as errors")] = False,
) -> None:
    """Validate probe files and print quality warnings."""
    try:
        probes = load_probes(paths or None)
    except (ProbeLoadError, FileNotFoundError) as exc:
        err.print(f"[bold red]{exc}[/]")
        raise typer.Exit(1) from None
    warnings = 0
    for p in probes:
        for w in lint_probe(p):
            warnings += 1
            console.print(f"[yellow]warning[/] {p.id}: {w}")
    console.print(f"[green]{len(probes)} probes valid[/], {warnings} warning(s)")
    raise typer.Exit(1 if strict and warnings else 0)


@probes_app.command("schema")
def probes_schema() -> None:
    """Print the JSON Schema of a probe file (for editor validation)."""
    from scanner.probes import Probe

    typer.echo(json.dumps(Probe.model_json_schema(), indent=2))


@app.command()
def mutators() -> None:
    """List available mutators."""
    from scanner.mutators import REGISTRY

    t = Table("Name", "Description", box=None)
    for name, cls in REGISTRY.items():
        t.add_row(name, cls.description)
    console.print(t)
    console.print(
        "Chain with '+', e.g. [bold]-m roleplay+base64[/] (roleplay first, then base64). Use [bold]-m all[/] for every mutator."
    )


# --------------------------------------------------------------------------- judge


@app.command("judge-eval")
def judge_eval(
    dataset: Annotated[Path, typer.Argument(help="JSONL of hand-labelled responses")],
    judge: Annotated[
        str, typer.Option(help="heuristic | ollama:MODEL | openai:MODEL | anthropic:MODEL")
    ] = "heuristic",
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write the full evaluation as JSON")
    ] = None,
) -> None:
    """Measure the judge against hand labels: precision, recall, F1 and disagreements."""
    from scanner.judge_eval import evaluate_dataset, format_evaluation, load_dataset

    try:
        rows = load_dataset(dataset)
        result = asyncio.run(evaluate_dataset(rows, judge))
    except (OSError, ValueError, ConfigError) as exc:
        raise _fail(str(exc)) from None
    console.print(format_evaluation(result))
    if out:
        out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"Wrote [bold]{out}[/]")


# --------------------------------------------------------------------- servers etc.


@app.command("demo-target")
def demo_target(
    host: Annotated[str, typer.Option(help="Bind address (keep it local!)")] = "127.0.0.1",
    port: Annotated[int, typer.Option()] = 9000,
    level: Annotated[
        str, typer.Option(help="Level served at the root: weak | medium | hardened")
    ] = "weak",
) -> None:
    """Start the deliberately vulnerable demo app (all three levels are served)."""
    try:
        import uvicorn
    except ImportError:
        raise _fail(
            "install the server extra: pip install 'llm-security-scanner[server]'"
        ) from None
    import os

    os.environ["TARGET_LEVEL"] = level
    console.print(
        f"[yellow]Deliberately vulnerable demo on http://{host}:{port}[/] (/weak /medium /hardened) - never expose it"
    )
    uvicorn.run("targets.vulnerable_app.main:app", host=host, port=port, log_level="warning")


@app.command()
def serve(
    host: Annotated[str, typer.Option()] = "127.0.0.1",
    port: Annotated[int, typer.Option()] = 8000,
    reload: Annotated[bool, typer.Option()] = False,
) -> None:
    """Start the REST API (FastAPI)."""
    try:
        import uvicorn
    except ImportError:
        raise _fail(
            "install the server extra: pip install 'llm-security-scanner[server]'"
        ) from None
    uvicorn.run("api.main:app", host=host, port=port, reload=reload)


INIT_TEMPLATE = """\
# llmscan.yaml - run with:  llmscan run llmscan.yaml
# Only scan systems you own or are authorised to test (docs/ETHICS.md).
target:
  type: http                       # http | openai | anthropic | ollama
  name: my-chatbot
  url: http://localhost:8080/api/chat
  method: POST
  headers:
    Content-Type: application/json
  auth:                            # none | bearer | basic | header
    type: bearer
    token: ${CHATBOT_TOKEN}        # environment variable, never commit secrets
  body:                            # {{prompt}} {{messages}} {{system}} {{conversation_id}}
    message: "{{prompt}}"
    session: "{{conversation_id}}"
  response_path: $.reply           # where the answer is in the JSON response
  # tool_calls_path: $.tool_calls  # optional: lets agent probes see tool calls
  canaries:                        # plant these secrets in your test deployment's system prompt / docs
    system: CANARY-change-me-1234
  system_prompt_fragments: []      # phrases from your real system prompt (leak detection)
  known_sensitive: []              # PII / secrets seeded in test data that must never leak
scan:
  min_severity: low
  mutators: [base64, roleplay]     # or `all`
  concurrency: 4
  rps: 5
  seed: 1
  judge:
    mode: auto                     # auto | heuristic | off | llm (set target: ollama:llama3.1)
  authorization:
    acknowledged: false            # set true (and describe it) for public hosts you are allowed to test
    note: "own staging deployment"
"""


@app.command()
def init(out: Annotated[Path | None, typer.Option("--out", "-o")] = None) -> None:
    """Print (or write) a commented starter config."""
    if out:
        if out.exists():
            raise _fail(f"{out} already exists")
        out.write_text(INIT_TEMPLATE, encoding="utf-8")
        console.print(f"Wrote [bold]{out}[/]")
    else:
        typer.echo(INIT_TEMPLATE)


@app.command()
def version() -> None:
    """Show version and bundled probe count."""
    try:
        n = len(load_probes())
    except Exception:
        n = 0
    console.print(f"llmscan {__version__} - {n} bundled probes")


def main() -> None:
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
