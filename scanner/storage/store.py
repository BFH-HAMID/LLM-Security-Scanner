"""Persistence facade used by the CLI (``--db``) and the API."""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, delete, func, select, update
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from scanner import __version__
from scanner.models import AttemptResult, RunReport, ScoreCard, Status, ToolInfo, utcnow
from scanner.storage.models import ApiKeyRow, Base, ProjectRow, ResultRow, RunRow, TargetRow

DEFAULT_PROJECT = "default"
KEY_PREFIX = "llmscan_"


def normalize_url(url: str) -> str:
    """Turn a path or a bare postgres URL into a SQLAlchemy URL with an installed driver."""
    if "://" not in url:
        return f"sqlite:///{Path(url).expanduser()}"
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://") :]
    return url


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class Store:
    def __init__(self, url: str, *, echo: bool = False):
        self.url = normalize_url(url)
        parsed = make_url(self.url)
        kwargs: dict[str, Any] = {"echo": echo, "future": True}
        if parsed.get_backend_name() == "sqlite":
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
            if parsed.database in (None, "", ":memory:"):
                kwargs["poolclass"] = StaticPool  # one shared in-memory connection
            else:
                Path(parsed.database).parent.mkdir(parents=True, exist_ok=True)
        else:
            kwargs["pool_pre_ping"] = True
        self.engine: Engine = create_engine(self.url, **kwargs)
        if parsed.get_backend_name() == "sqlite":
            from sqlalchemy import event

            @event.listens_for(self.engine, "connect")
            def _pragmas(conn: Any, _rec: Any) -> None:  # pragma: no cover - trivial
                cur = conn.cursor()
                cur.execute("PRAGMA foreign_keys=ON")
                cur.execute("PRAGMA journal_mode=WAL")
                cur.close()

        Base.metadata.create_all(self.engine)
        self._Session = sessionmaker(self.engine, expire_on_commit=False)

    @contextmanager
    def session(self) -> Iterator[Session]:
        s = self._Session()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    def close(self) -> None:
        self.engine.dispose()

    # ---------------------------------------------------------------- projects / keys

    def ensure_project(self, name: str = DEFAULT_PROJECT, description: str = "") -> ProjectRow:
        with self.session() as s:
            row = s.scalar(select(ProjectRow).where(ProjectRow.name == name))
            if row is None:
                row = ProjectRow(name=name, description=description)
                s.add(row)
                s.flush()
            return row

    def create_project(self, name: str, description: str = "") -> ProjectRow:
        with self.session() as s:
            if s.scalar(select(ProjectRow).where(ProjectRow.name == name)):
                raise ValueError(f"project {name!r} already exists")
            row = ProjectRow(name=name, description=description)
            s.add(row)
            s.flush()
            return row

    def list_projects(self) -> list[ProjectRow]:
        with self.session() as s:
            return list(s.scalars(select(ProjectRow).order_by(ProjectRow.created_at)))

    def get_project(self, project_id: str) -> ProjectRow | None:
        with self.session() as s:
            return s.get(ProjectRow, project_id)

    def create_api_key(
        self, project_id: str, name: str, *, is_admin: bool = False, key: str | None = None
    ) -> tuple[ApiKeyRow, str]:
        """Create a key. The plaintext is returned once and only its SHA-256 is stored."""
        plaintext = key or KEY_PREFIX + secrets.token_urlsafe(32)
        with self.session() as s:
            row = ApiKeyRow(
                project_id=project_id,
                name=name,
                prefix=plaintext[:12],
                key_hash=hash_key(plaintext),
                is_admin=is_admin,
            )
            s.add(row)
            s.flush()
            return row, plaintext

    def verify_api_key(self, plaintext: str) -> ApiKeyRow | None:
        digest = hash_key(plaintext)
        with self.session() as s:
            row = s.scalar(select(ApiKeyRow).where(ApiKeyRow.key_hash == digest))
            if row is None or row.revoked:
                return None
            row.last_used_at = utcnow()
            return row

    def has_api_keys(self) -> bool:
        with self.session() as s:
            return (s.scalar(select(func.count()).select_from(ApiKeyRow)) or 0) > 0

    def list_api_keys(self, project_id: str) -> list[ApiKeyRow]:
        with self.session() as s:
            return list(
                s.scalars(
                    select(ApiKeyRow)
                    .where(ApiKeyRow.project_id == project_id)
                    .order_by(ApiKeyRow.created_at)
                )
            )

    def revoke_api_key(self, project_id: str, key_id: str) -> bool:
        with self.session() as s:
            res = s.execute(
                update(ApiKeyRow)
                .where(ApiKeyRow.id == key_id, ApiKeyRow.project_id == project_id)
                .values(revoked=True)
            )
            return bool(res.rowcount)

    # ------------------------------------------------------------------------ targets

    def create_target(self, project_id: str, name: str, config: dict[str, Any]) -> TargetRow:
        with self.session() as s:
            row = TargetRow(project_id=project_id, name=name, config=config)
            s.add(row)
            s.flush()
            return row

    def get_target(self, project_id: str, target_id: str) -> TargetRow | None:
        with self.session() as s:
            row = s.get(TargetRow, target_id)
            return row if row and row.project_id == project_id else None

    def list_targets(self, project_id: str) -> list[TargetRow]:
        with self.session() as s:
            return list(
                s.scalars(
                    select(TargetRow)
                    .where(TargetRow.project_id == project_id)
                    .order_by(TargetRow.created_at)
                )
            )

    def update_target(
        self,
        project_id: str,
        target_id: str,
        *,
        name: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> TargetRow | None:
        with self.session() as s:
            row = s.get(TargetRow, target_id)
            if row is None or row.project_id != project_id:
                return None
            if name is not None:
                row.name = name
            if config is not None:
                row.config = config
            s.flush()
            return row

    def delete_target(self, project_id: str, target_id: str) -> bool:
        with self.session() as s:
            row = s.get(TargetRow, target_id)
            if row is None or row.project_id != project_id:
                return False
            s.delete(row)
            return True

    def set_baseline(self, project_id: str, target_id: str, run_id: str | None) -> bool:
        with self.session() as s:
            row = s.get(TargetRow, target_id)
            if row is None or row.project_id != project_id:
                return False
            row.baseline_run_id = run_id
            return True

    # -------------------------------------------------------------------------- runs

    def create_run(
        self,
        project_id: str,
        *,
        target_id: str | None,
        scan_config: dict[str, Any],
        target_summary: dict[str, Any],
        name: str | None = None,
        authorization: dict[str, Any] | None = None,
        status: str = "queued",
    ) -> RunRow:
        with self.session() as s:
            row = RunRow(
                project_id=project_id,
                target_id=target_id,
                name=name,
                scan_config=scan_config,
                target_summary=target_summary,
                authorization=authorization,
                status=status,
                tool_version=__version__,
            )
            s.add(row)
            s.flush()
            return row

    def get_run(self, project_id: str | None, run_id: str) -> RunRow | None:
        with self.session() as s:
            row = s.get(RunRow, run_id)
            if row is None or (project_id is not None and row.project_id != project_id):
                return None
            return row

    def list_runs(
        self,
        project_id: str,
        *,
        target_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[RunRow], int]:
        with self.session() as s:
            q = select(RunRow).where(RunRow.project_id == project_id)
            if target_id:
                q = q.where(RunRow.target_id == target_id)
            if status:
                q = q.where(RunRow.status == status)
            total = s.scalar(select(func.count()).select_from(q.subquery())) or 0
            rows = list(s.scalars(q.order_by(RunRow.created_at.desc()).limit(limit).offset(offset)))
            return rows, total

    def mark_running(self, run_id: str) -> None:
        with self.session() as s:
            s.execute(
                update(RunRow)
                .where(RunRow.id == run_id)
                .values(status="running", started_at=utcnow())
            )

    def set_progress(self, run_id: str, done: int, total: int, findings: int) -> None:
        with self.session() as s:
            s.execute(
                update(RunRow)
                .where(RunRow.id == run_id)
                .values(progress_done=done, progress_total=total, findings=findings)
            )

    def request_cancel(self, project_id: str, run_id: str) -> bool:
        with self.session() as s:
            row = s.get(RunRow, run_id)
            if row is None or row.project_id != project_id:
                return False
            if row.status in ("queued", "running"):
                row.cancel_requested = True
                if row.status == "queued":
                    row.status = "cancelled"
                    row.finished_at = utcnow()
            return True

    def is_cancel_requested(self, run_id: str) -> bool:
        with self.session() as s:
            return bool(s.scalar(select(RunRow.cancel_requested).where(RunRow.id == run_id)))

    def delete_run(self, project_id: str, run_id: str) -> bool:
        with self.session() as s:
            row = s.get(RunRow, run_id)
            if row is None or row.project_id != project_id:
                return False
            s.execute(
                update(TargetRow)
                .where(TargetRow.baseline_run_id == run_id)
                .values(baseline_run_id=None)
            )
            s.delete(row)
            return True

    # ----------------------------------------------------------------------- results

    def add_result(self, run_id: str, result: AttemptResult) -> None:
        with self.session() as s:
            s.merge(_result_row(run_id, result))

    def finish_run(self, run_id: str, report: RunReport, *, save_results: bool = False) -> None:
        with self.session() as s:
            if save_results:
                for r in report.results:
                    s.merge(_result_row(run_id, r))
            s.execute(
                update(RunRow)
                .where(RunRow.id == run_id)
                .values(
                    status=report.status,
                    score=report.score.model_dump(mode="json"),
                    risk_score=report.score.risk_score,
                    grade=report.score.grade,
                    findings=report.score.failed,
                    progress_done=report.score.total,
                    progress_total=max(report.score.total, 0),
                    duration_s=report.duration_s,
                    error=report.error,
                    authorization=report.authorization,
                    target_summary=report.target,
                    scan_config=report.config,
                    started_at=report.started_at,
                    finished_at=report.finished_at or utcnow(),
                )
            )

    def fail_run(self, run_id: str, error: str) -> None:
        with self.session() as s:
            s.execute(
                update(RunRow)
                .where(RunRow.id == run_id)
                .values(status="failed", error=error[:4000], finished_at=utcnow())
            )

    def save_report(
        self, report: RunReport, *, project_id: str | None = None, target_id: str | None = None
    ) -> str:
        """Store a finished report (used by ``llmscan run --db``). Returns the run id."""
        pid = project_id or self.ensure_project().id
        with self.session() as s:
            row = RunRow(
                id=report.id,
                project_id=pid,
                target_id=target_id,
                name=report.name,
                status=report.status,
                scan_config=report.config,
                target_summary=report.target,
                authorization=report.authorization,
                tool_version=report.tool.version,
                created_at=report.started_at,
            )
            s.merge(row)
        self.finish_run(report.id, report, save_results=True)
        return report.id

    def query_results(
        self,
        run_id: str,
        *,
        status: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        probe_id: str | None = None,
        mutator: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> tuple[list[AttemptResult], int]:
        with self.session() as s:
            q = select(ResultRow).where(ResultRow.run_id == run_id)
            for column, value in (
                (ResultRow.status, status),
                (ResultRow.category, category),
                (ResultRow.severity, severity),
                (ResultRow.probe_id, probe_id),
                (ResultRow.mutator, mutator),
            ):
                if value:
                    q = q.where(column == value)
            total = s.scalar(select(func.count()).select_from(q.subquery())) or 0
            rows = s.scalars(
                q.order_by(
                    ResultRow.category, ResultRow.probe_id, ResultRow.mutator, ResultRow.repeat
                )
                .limit(limit)
                .offset(offset)
            )
            return [AttemptResult.model_validate(r.data) for r in rows], total

    def get_result(self, run_id: str, result_id: str) -> AttemptResult | None:
        with self.session() as s:
            row = s.get(ResultRow, result_id)
            if row is None or row.run_id != run_id:
                return None
            return AttemptResult.model_validate(row.data)

    def load_report(self, run_id: str, project_id: str | None = None) -> RunReport | None:
        """Rebuild the portable :class:`RunReport` (for exports, comparisons and baselines)."""
        with self.session() as s:
            run = s.get(RunRow, run_id)
            if run is None or (project_id is not None and run.project_id != project_id):
                return None
            rows = list(s.scalars(select(ResultRow).where(ResultRow.run_id == run_id)))
            results = [AttemptResult.model_validate(r.data) for r in rows]
            order = {c: i for i, c in enumerate(_category_order())}
            results.sort(
                key=lambda r: (order.get(r.category.value, 99), r.probe_id, r.mutator, r.repeat)
            )
            score = ScoreCard.model_validate(run.score) if run.score else _score(results)
            return RunReport(
                id=run.id,
                name=run.name,
                status=run.status,  # type: ignore[arg-type]
                target=run.target_summary or {},
                config=run.scan_config or {},
                authorization=run.authorization,
                started_at=run.started_at or run.created_at,
                finished_at=run.finished_at,
                duration_s=run.duration_s,
                score=score,
                results=results,
                error=run.error,
                tool=ToolInfo(version=run.tool_version),
            )

    def purge(self, older_than_days: int) -> int:
        """Delete finished runs older than N days (data-retention helper)."""
        cutoff = utcnow() - dt.timedelta(days=older_than_days)
        with self.session() as s:
            ids = list(
                s.scalars(
                    select(RunRow.id).where(
                        RunRow.created_at < cutoff,
                        RunRow.status.in_(("completed", "failed", "cancelled")),
                    )
                )
            )
            if ids:
                s.execute(
                    update(TargetRow)
                    .where(TargetRow.baseline_run_id.in_(ids))
                    .values(baseline_run_id=None)
                )
                s.execute(delete(ResultRow).where(ResultRow.run_id.in_(ids)))
                s.execute(delete(RunRow).where(RunRow.id.in_(ids)))
            return len(ids)


def _category_order() -> list[str]:
    from scanner.models import Category

    return [c.value for c in Category]


def _score(results: list[AttemptResult]) -> ScoreCard:
    from scanner.scoring import score

    return score(results)


def _result_row(run_id: str, r: AttemptResult) -> ResultRow:
    return ResultRow(
        id=r.id,
        run_id=run_id,
        probe_id=r.probe_id,
        probe_name=r.probe_name[:200],
        category=r.category.value,
        severity=r.severity.value,
        mutator=r.mutator[:80],
        repeat=r.repeat,
        status=r.status.value,
        confidence=r.confidence,
        reason=r.reason,
        latency_ms=r.latency_ms,
        started_at=r.started_at,
        data=r.model_dump(mode="json"),
    )


def open_store(url: str | None = None) -> Store:
    """Open the store at ``url`` (path or SQLAlchemy URL), ``$DATABASE_URL`` or ``./llmscan.db``."""
    import os

    return Store(url or os.environ.get("DATABASE_URL") or "llmscan.db")


__all__ = ["DEFAULT_PROJECT", "Status", "Store", "hash_key", "normalize_url", "open_store"]
