"""Request / response models of the REST API."""

from __future__ import annotations

import datetime as dt
from typing import Any

from pydantic import BaseModel, Field

from scanner.config import AuthorizationConfig


class TargetIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    config: dict[str, Any]


class TargetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    config: dict[str, Any] | None = None


class TargetOut(BaseModel):
    id: str
    name: str
    type: str
    config: dict[str, Any]  # secrets masked
    baseline_run_id: str | None = None
    created_at: dt.datetime
    updated_at: dt.datetime


class RunCreate(BaseModel):
    target_id: str | None = None
    target: dict[str, Any] | None = Field(
        default=None, description="Inline target config (alternative to target_id)"
    )
    name: str | None = Field(default=None, max_length=200)
    scan: dict[str, Any] = Field(
        default_factory=dict, description="Subset of ScanConfig: categories, mutators, repeats, ..."
    )
    authorization: AuthorizationConfig | None = None


class Progress(BaseModel):
    done: int
    total: int


class RunOut(BaseModel):
    id: str
    name: str | None
    status: str
    target_id: str | None
    target: dict[str, Any]
    risk_score: float | None
    grade: str | None
    findings: int
    progress: Progress
    error: str | None
    duration_s: float
    created_at: dt.datetime
    started_at: dt.datetime | None
    finished_at: dt.datetime | None


class RunDetail(RunOut):
    score: dict[str, Any] | None = None
    notes: list[str] = Field(default_factory=list)
    authorization: dict[str, Any] | None = None
    scan: dict[str, Any] = Field(default_factory=dict)  # as requested (never changes)
    summary: dict[str, Any] = Field(default_factory=dict)  # facts recorded when the run finished


class RunList(BaseModel):
    items: list[RunOut]
    total: int


class BaselineSet(BaseModel):
    run_id: str


class KeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    is_admin: bool = False


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
