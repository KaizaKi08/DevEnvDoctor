"""Validated data structures shared by diagnostics and report generation."""

import platform as platform_info
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from dev_env_doctor import __version__

NonBlankString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class Severity(StrEnum):
    """Severity levels supported by diagnostic results."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class ProcessCleanupStatus(StrEnum):
    """Internal confirmation for a direct child and its managed output readers.

    NOT_STARTED means no child was successfully created. CONFIRMED requires
    observed direct-child exit and all managed readers ended; UNCONFIRMED
    means either condition is unknown. No value describes descendant cleanup.
    """

    NOT_STARTED = "not_started"
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"


class StrictModel(BaseModel):
    """Base model that rejects undeclared fields."""

    model_config = ConfigDict(extra="forbid")


class DiagnosticResult(StrictModel):
    """A concise, validated result from one diagnostic rule."""

    rule_id: NonBlankString
    title: NonBlankString
    severity: Severity
    summary: NonBlankString
    evidence: list[str] = Field(default_factory=list)
    suggestion: str = ""
    status: Literal["found", "passed", "skipped", "error"] = "found"


class ScanMetadata(StrictModel):
    """Non-sensitive metadata describing one scan."""

    scan_time: datetime = Field(default_factory=lambda: datetime.now().astimezone())
    app_version: NonBlankString = __version__
    platform: NonBlankString = Field(default_factory=platform_info.platform)
    python_version: NonBlankString = Field(default_factory=platform_info.python_version)

    @field_validator("scan_time")
    @classmethod
    def require_timezone_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("scan_time must include a timezone")
        return value


class ScanReport(StrictModel):
    """Versioned collection of scan metadata and diagnostic results."""

    schema_version: NonBlankString = "1.0"
    metadata: ScanMetadata = Field(default_factory=ScanMetadata)
    diagnostics: list[DiagnosticResult] = Field(default_factory=list)
