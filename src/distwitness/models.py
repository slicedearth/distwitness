"""Versioned typed contracts shared by collection, comparison, and rendering."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from distwitness.normalise import normalise_package_name

RECORD_SCHEMA_VERSION: Literal[1] = 1
PACKAGE_SCHEMA_VERSION: Literal[2] = 2
STATE_SCHEMA_VERSION: Literal[3] = 3
BoundedText = Annotated[str, Field(max_length=2000)]
HttpUrlText = Annotated[str, Field(max_length=512, pattern=r"^https?://")]
SourceName = Literal["pypi", "pypi_integrity", "osv"]
SourceHealthStatus = Literal["available", "partial", "degraded", "not_checked"]


class StrictModel(BaseModel):
    """Base model that rejects schema drift and mutable extra state."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ProvenanceState(StrEnum):
    """Source states exposed without collapsing unknown into absent."""

    PRESENT = "present"
    ABSENT = "absent"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"
    REQUEST_FAILED = "request_failed"
    MALFORMED_RESPONSE = "malformed_response"


class DataConfidence(StrEnum):
    """Confidence in whether the source evidence supports an event."""

    CONFIRMED = "confirmed"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


class ReviewPriority(StrEnum):
    """Human review priority, deliberately not a risk score."""

    INFORMATIONAL = "informational"
    REVIEW = "review"
    URGENT = "urgent"


class SourceError(StrictModel):
    """Bounded source failure suitable for persistence and public display."""

    source: SourceName
    package_name: str | None = None
    code: str = Field(max_length=80)
    message: BoundedText
    occurred_at: datetime
    retryable: bool
    source_url: HttpUrlText | None = None


class PackageConfig(StrictModel):
    """One package in the watchlist."""

    name: str
    include_prereleases: bool | None = None
    file_size_change_percent: float | None = Field(default=None, ge=1, le=1000)
    file_size_change_min_bytes: int | None = Field(default=None, ge=0, le=1_000_000_000)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        normalise_package_name(value)
        return value

    @property
    def normalised_name(self) -> str:
        """Return the PEP 503-normalised distribution name."""

        return normalise_package_name(self.name)


class ProjectConfig(StrictModel):
    """Repository-wide monitoring policy."""

    title: str = Field(min_length=1, max_length=100)
    retention_days: int = Field(default=180, ge=1, le=3650)
    max_packages: int = Field(default=50, ge=1, le=100)
    include_prereleases_by_default: bool = False
    file_size_change_percent: float = Field(default=40, ge=1, le=1000)
    file_size_change_min_bytes: int = Field(default=100_000, ge=0, le=1_000_000_000)
    user_agent: str = Field(
        default="DistWitness/0.4 (+https://github.com/slicedearth/distwitness)",
        min_length=10,
        max_length=200,
    )


class WatchlistConfig(StrictModel):
    """Validated root configuration."""

    project: ProjectConfig
    packages: tuple[PackageConfig, ...]


class ProvenanceSnapshot(StrictModel):
    """Compact provenance observation for one release file."""

    state: ProvenanceState
    publishers: tuple[str, ...] = ()
    attestation_count: int = Field(default=0, ge=0, le=10_000)
    source_url: HttpUrlText
    observed_at: datetime


class ReleaseFileSnapshot(StrictModel):
    """Normalised immutable metadata for one distribution file."""

    filename: str = Field(min_length=1, max_length=300)
    sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    size: int = Field(ge=0, le=20_000_000_000)
    package_type: str = Field(max_length=80)
    upload_time: datetime | None = None
    python_version: str | None = Field(default=None, max_length=80)
    python_tags: tuple[str, ...] = ()
    requires_python: str | None = Field(default=None, max_length=500)
    yanked: bool = False
    yanked_reason: str | None = Field(default=None, max_length=500)
    provenance: ProvenanceSnapshot


class ReleaseSnapshot(StrictModel):
    """Selected release and its compact file metadata."""

    version: str = Field(min_length=1, max_length=200)
    yanked: bool
    all_files_yanked: bool
    files: tuple[ReleaseFileSnapshot, ...]
    source_url: HttpUrlText
    source_timestamp: datetime | None = None


class VulnerabilityReference(StrictModel):
    """Sanitised OSV reference without advisory body text."""

    type: str = Field(max_length=40)
    url: HttpUrlText


class VulnerabilitySnapshot(StrictModel):
    """Compact advisory metadata affecting the exact selected version."""

    id: str = Field(min_length=1, max_length=120)
    aliases: tuple[str, ...] = ()
    affected_package: str
    affected_version: str
    severity_type: str | None = Field(default=None, max_length=40)
    severity_score: str | None = Field(default=None, max_length=160)
    severity_label: Literal["low", "medium", "high", "critical"] | None = None
    published: datetime | None = None
    modified: datetime | None = None
    references: tuple[VulnerabilityReference, ...] = ()
    source_url: HttpUrlText


class PackageSnapshot(StrictModel):
    """Compact current observation for one configured package."""

    schema_version: Literal[2] = PACKAGE_SCHEMA_VERSION
    name: str
    display_name: str = Field(max_length=100)
    collected_at: datetime
    release_discovery: Literal["legacy-project-json", "pypi-index-v1"]
    index_api_version: str | None = Field(
        default=None,
        max_length=20,
        pattern=r"^[0-9]+\.[0-9]+$",
    )
    release: ReleaseSnapshot
    requires_python: str | None = Field(default=None, max_length=500)
    requires_dist: tuple[str, ...] = ()
    license_expression: str | None = Field(default=None, max_length=500)
    declared_license: str | None = Field(default=None, max_length=500)
    license_classifiers: tuple[str, ...] = ()
    project_urls: dict[str, str] = Field(default_factory=dict)
    vulnerabilities: tuple[VulnerabilitySnapshot, ...] = ()
    source_errors: tuple[SourceError, ...] = ()

    @model_validator(mode="after")
    def validate_release_discovery(self) -> Self:
        """Keep the discovery method and negotiated API version consistent."""

        if self.release_discovery == "pypi-index-v1":
            if self.index_api_version is None:
                raise ValueError("Index discovery requires an API version")
        elif self.index_api_version is not None:
            raise ValueError("legacy discovery cannot declare an Index API version")
        return self


class ChangeEvent(StrictModel):
    """Deterministic evidence-backed review event."""

    schema_version: Literal[1] = RECORD_SCHEMA_VERSION
    id: str = Field(pattern=r"^[a-f0-9]{64}$")
    event_type: str = Field(max_length=80)
    package_name: str
    old_value: Any | None = None
    new_value: Any | None = None
    detected_at: datetime
    source_timestamp: datetime | None = None
    review_priority: ReviewPriority
    explanation: BoundedText
    source_links: tuple[HttpUrlText, ...]
    evidence: dict[str, Any] = Field(default_factory=dict)
    data_confidence: DataConfidence


class RunResult(StrictModel):
    """Summary of a scan/build attempt."""

    schema_version: Literal[1] = RECORD_SCHEMA_VERSION
    started_at: datetime
    completed_at: datetime
    successful_packages: tuple[str, ...]
    failed_packages: tuple[str, ...]
    events_created: int = Field(ge=0)
    source_errors: tuple[SourceError, ...] = ()
    output_built: bool
    dry_run: bool


class SourceHealthObservation(StrictModel):
    """One aggregate source observation from a completed collection run."""

    schema_version: Literal[1] = RECORD_SCHEMA_VERSION
    source: SourceName
    observed_at: datetime
    status: SourceHealthStatus
    checked_packages: int = Field(ge=0, le=100)
    successful_packages: int = Field(ge=0, le=100)
    error_count: int = Field(ge=0, le=100_000)
    retryable_error_count: int = Field(ge=0, le=100_000)

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        """Keep aggregate counts internally consistent."""

        if self.successful_packages > self.checked_packages:
            raise ValueError("successful package checks exceed checked packages")
        if self.retryable_error_count > self.error_count:
            raise ValueError("retryable source errors exceed total source errors")
        if self.status == "available" and (
            self.checked_packages == 0
            or self.successful_packages != self.checked_packages
            or self.error_count != 0
        ):
            raise ValueError(
                "available source health requires complete error-free checks"
            )
        if self.status == "not_checked" and (
            self.checked_packages != 0
            or self.successful_packages != 0
            or self.error_count != 0
        ):
            raise ValueError("not-checked source health cannot contain check results")
        if self.status in {"partial", "degraded"} and (
            self.checked_packages == 0
            or self.successful_packages >= self.checked_packages
            or self.error_count == 0
        ):
            raise ValueError(
                "incomplete source health requires checked packages and errors"
            )
        if self.status == "partial" and self.retryable_error_count != self.error_count:
            raise ValueError("partial source health requires only retryable errors")
        if self.status == "degraded" and self.retryable_error_count == self.error_count:
            raise ValueError("degraded source health requires a non-retryable error")
        return self


class StateDocument(StrictModel):
    """Single versioned persistence unit written atomically."""

    schema_version: Literal[3] = STATE_SCHEMA_VERSION
    snapshots: dict[str, PackageSnapshot] = Field(default_factory=dict)
    events: tuple[ChangeEvent, ...] = ()
    source_health_history: Annotated[
        tuple[SourceHealthObservation, ...],
        Field(max_length=10_000),
    ] = ()
    last_run: RunResult | None = None
    last_successful_run: datetime | None = None

    @model_validator(mode="after")
    def validate_health_run_groups(self) -> Self:
        """Reject incomplete or duplicate health groups in persisted state."""

        required_sources: set[SourceName] = {"pypi", "pypi_integrity", "osv"}
        sources_by_run: dict[datetime, set[SourceName]] = {}
        for observation in self.source_health_history:
            sources = sources_by_run.setdefault(observation.observed_at, set())
            if observation.source in sources:
                raise ValueError("source-health run contains a duplicate source")
            sources.add(observation.source)
        if any(sources != required_sources for sources in sources_by_run.values()):
            raise ValueError("source-health run group is incomplete")
        return self
