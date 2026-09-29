"""SQLAlchemy schema. JSON columns become JSONB on PostgreSQL and plain JSON on SQLite."""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from scanner.models import new_id, utcnow

JSONType = JSON().with_variant(JSONB(), "postgresql")


class UTCDateTime(TypeDecorator):
    """Timezone-aware UTC datetimes on every backend (SQLite drops tzinfo)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: dt.datetime | None, dialect: Any) -> dt.datetime | None:
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=dt.UTC)
        return value.astimezone(dt.UTC) if value is not None else None

    def process_result_value(self, value: dt.datetime | None, dialect: Any) -> dt.datetime | None:
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=dt.UTC)
        return value


class Base(DeclarativeBase):
    pass


class ProjectRow(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow)


class ApiKeyRow(Base):
    __tablename__ = "api_keys"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(120))
    prefix: Mapped[str] = mapped_column(String(16))
    key_hash: Mapped[str] = mapped_column(
        String(64), unique=True
    )  # sha256 of the key, never the key
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_used_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)


class TargetRow(Base):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(120))
    config: Mapped[dict[str, Any]] = mapped_column(JSONType)
    baseline_run_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class RunRow(Base):
    __tablename__ = "runs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    # The scan settings as requested. Immutable: the worker re-reads it, so it is never overwritten.
    scan_config: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    # Facts derived while running (probe count, canary names, config file, command line ...).
    summary: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    # Coverage warnings ("no tool call observed", "judge abstained ...") - part of the honest result.
    notes: Mapped[list[str]] = mapped_column(JSONType, default=list)
    target_summary: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    # Snapshot of the target config the worker executes. Internal: never exposed by the API.
    target_config: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    authorization: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    score: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    grade: Mapped[str | None] = mapped_column(String(2), nullable=True)
    findings: Mapped[int] = mapped_column(Integer, default=0)
    progress_done: Mapped[int] = mapped_column(Integer, default=0)
    progress_total: Mapped[int] = mapped_column(Integer, default=0)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_s: Mapped[float] = mapped_column(Float, default=0.0)
    tool_version: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    started_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(UTCDateTime, nullable=True)

    results: Mapped[list[ResultRow]] = relationship(
        back_populates="run", cascade="all, delete-orphan", passive_deletes=True
    )


class ResultRow(Base):
    """Every attempt (pass, fail, error, inconclusive) - findings are the ``fail`` rows."""

    __tablename__ = "results"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    probe_id: Mapped[str] = mapped_column(String(16))
    probe_name: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(40))
    severity: Mapped[str] = mapped_column(String(10))
    mutator: Mapped[str] = mapped_column(String(80), default="none")
    repeat: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(14))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    reason: Mapped[str] = mapped_column(Text, default="")
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[dt.datetime] = mapped_column(UTCDateTime, default=utcnow)
    data: Mapped[dict[str, Any]] = mapped_column(JSONType)  # the full AttemptResult document

    run: Mapped[RunRow] = relationship(back_populates="results")

    __table_args__ = (
        Index("ix_results_run_status", "run_id", "status"),
        Index("ix_results_run_probe", "run_id", "probe_id"),
    )
