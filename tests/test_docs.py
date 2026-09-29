"""Documentation must not rot: links resolve, the generated catalogue is fresh, and every command,
flag and make target the docs mention really exists."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import typer

from scanner.cli import app

ROOT = Path(__file__).resolve().parents[1]
DOCS = sorted([*ROOT.glob("docs/*.md"), ROOT / "README.md"])
CLI = typer.main.get_command(app)  # duck-typed: Typer's group class is not always a click.Group
assert hasattr(CLI, "commands")


def test_generated_probe_catalogue_is_up_to_date():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_probe_docs.py"), "--check"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_relative_links_resolve(doc: Path):
    for target in re.findall(
        r"\]\((?!https?://|mailto:|#)([^)#\s]+)(?:#[^)]*)?\)", doc.read_text(encoding="utf-8")
    ):
        assert (doc.parent / target).resolve().exists(), f"{doc.name}: broken link to {target}"


def cli_mentions(doc: Path):
    """(command path, flags) for every `llmscan ...` span in the doc."""
    for span in re.findall(r"`(llmscan [^`\n]+)`", doc.read_text(encoding="utf-8")):
        words = span.split()[1:]
        yield span, words


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_documented_cli_commands_and_flags_exist(doc: Path):
    for span, words in cli_mentions(doc):
        command = CLI.commands.get(words[0]) if words else None
        assert command is not None, f"{doc.name}: `{span}` names an unknown command"
        if hasattr(command, "commands") and len(words) > 1 and not words[1].startswith("-"):
            command = command.commands.get(words[1])
            assert command is not None, f"{doc.name}: `{span}` names an unknown subcommand"
        known = {opt for p in command.params for opt in (*p.opts, *p.secondary_opts)}
        for flag in (w for w in words if w.startswith("--")):
            assert flag.split("=")[0] in known, f"{doc.name}: `{span}` uses unknown flag {flag}"


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_documented_make_targets_exist(doc: Path):
    targets = set(re.findall(r"^([a-z][a-z-]*):", (ROOT / "Makefile").read_text(), re.M))
    for target in re.findall(r"`make ([a-z-]+)`", doc.read_text(encoding="utf-8")):
        assert target in targets, f"{doc.name}: `make {target}` is not a Makefile target"


def test_docs_referenced_from_code_exist():
    referenced = set()
    for path in [
        *ROOT.glob("scanner/**/*.py"),
        *ROOT.glob("api/**/*.py"),
        *ROOT.glob("scripts/*.py"),
    ]:
        referenced |= set(re.findall(r"docs/([A-Z_]+\.md)", path.read_text(encoding="utf-8")))
    missing = sorted(name for name in referenced if not (ROOT / "docs" / name).exists())
    assert not missing, f"referenced but missing: {missing}"
