"""Pydantic request/response schemas. Request models forbid unknown fields."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

T = TypeVar("T")
ScannerName = Literal["semgrep", "trivy", "trivy-image"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class ErrorBody(BaseModel):
    error: str
    detail: Any = None
    request_id: str | None = None


# ---- auth / users
class LoginRequest(Strict):
    email: str = Field(max_length=320)
    password: str = Field(max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime


class UserCreate(Strict):
    email: EmailStr
    full_name: str = Field(default="", max_length=200)
    password: str = Field(max_length=256)
    role: Literal["admin", "security_engineer", "developer"] = "developer"


class UserUpdate(Strict):
    role: Literal["admin", "security_engineer", "developer"] | None = None
    is_active: bool | None = None


# ---- projects / repositories
class ProjectCreate(Strict):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=2000)


class ProjectOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    description: str
    created_at: datetime


class MemberAdd(Strict):
    user_id: str


class RepositoryCreate(Strict):
    project_id: str
    full_name: str = Field(min_length=3, max_length=300, pattern=r"^[A-Za-z0-9_.\-/]+$")
    ci_provider: Literal["github", "gitlab", "other"] = "github"
    default_branch: str = Field(default="main", min_length=1, max_length=200)
    clone_url: str = Field(default="", max_length=500)
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    internet_facing: bool = False


class RepositoryUpdate(Strict):
    default_branch: str | None = Field(default=None, min_length=1, max_length=200)
    criticality: Literal["low", "medium", "high", "critical"] | None = None
    internet_facing: bool | None = None
    clone_url: str | None = Field(default=None, max_length=500)


class RepositoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    project_id: str
    full_name: str
    ci_provider: str
    default_branch: str
    clone_url: str
    criticality: str
    internet_facing: bool
    ingest_token_prefix: str
    created_at: datetime


class RepositoryCreated(RepositoryOut):
    ingest_token: str = Field(description="Shown exactly once. Store it as a CI secret.")


# ---- scans / ingestion
class ScannerSubmission(Strict):
    scanner: ScannerName
    status: Literal["succeeded", "failed", "timeout", "missing", "skipped"]
    scan_mode: str = Field(default="", max_length=64)
    exit_code: int | None = None
    version: str | None = Field(default=None, max_length=64)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = Field(default=None, max_length=8000)
    stderr_tail: str | None = Field(default=None, max_length=8000)
    report: dict[str, Any] | list[Any] | None = None


class IngestRequest(Strict):
    commit_sha: str = Field(min_length=7, max_length=64, pattern=r"^[0-9a-fA-F]+$")
    branch: str = Field(min_length=1, max_length=255)
    base_branch: str | None = Field(default=None, max_length=255)
    pr_number: int | None = Field(default=None, ge=1)
    build_id: str | None = Field(default=None, max_length=128)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:\-]+$")
    scanners: list[ScannerSubmission] = Field(min_length=1, max_length=8)

    @field_validator("scanners")
    @classmethod
    def _unique(cls, v: list[ScannerSubmission]) -> list[ScannerSubmission]:
        names = [s.scanner for s in v]
        if len(names) != len(set(names)):
            raise ValueError("each scanner may be submitted once per scan")
        return v


class ScanStart(Strict):
    commit_sha: str = Field(min_length=7, max_length=64, pattern=r"^[0-9a-fA-F]+$")
    branch: str = Field(min_length=1, max_length=255)
    base_branch: str | None = Field(default=None, max_length=255)
    pr_number: int | None = Field(default=None, ge=1)
    build_id: str | None = Field(default=None, max_length=128)
    idempotency_key: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9._:\-]+$")


class ScanReport(Strict):
    scanners: list[ScannerSubmission] = Field(min_length=1, max_length=8)


class ExecutionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    scanner: str
    scan_mode: str
    status: str
    exit_code: int | None
    version: str | None
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: int | None
    error: str | None
    stderr_tail: str | None
    parse_error: str | None
    findings_count: int
    report_sha256: str | None


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    repository_id: str
    repository: str | None = None
    commit_sha: str
    branch: str
    base_branch: str | None
    pr_number: int | None
    build_id: str | None
    environment: str
    status: str
    decision: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ScanDetail(ScanOut):
    executions: list[ExecutionOut]
    evaluation: dict[str, Any] | None
    severity_counts: dict[str, int]
    new_counts: dict[str, int]


class IngestResponse(BaseModel):
    scan_id: str
    status: str
    decision: str
    summary: str
    idempotent_replay: bool
    report_url: str
    exit_code: int = Field(description="Suggested CI exit code: 0 pass, 1 fail, 0 warn unless warn-as-failure")


# ---- findings
class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    repository_id: str
    branch: str
    scanner: str
    scanner_finding_id: str
    category: str
    title: str
    severity: str
    confidence: str | None
    vuln_id: str | None
    package_name: str | None
    installed_version: str | None
    fixed_version: str | None
    file_path: str | None
    line: int | None
    known_exploited: bool | None
    risk_score: float
    status: str
    effective_status: str = ""
    first_seen_at: datetime
    last_seen_at: datetime


class FindingDetail(FindingOut):
    description: str
    scanner_severity: str | None
    cwe: list[str]
    references: list[str]
    remediation: str
    evidence: dict[str, Any]
    resource: str | None
    epss: float | None
    risk_factors: dict[str, Any]
    fingerprint: str
    resolved_at: datetime | None
    suppression: dict[str, Any] | None = None
    history: list[dict[str, Any]] = []


class FindingStatusUpdate(Strict):
    status: Literal["open", "acknowledged"]
    note: str = Field(default="", max_length=2000)


class SuppressionCreate(Strict):
    reason: str = Field(min_length=10, max_length=2000)
    expires_at: datetime


# ---- policies
class PolicyCreate(Strict):
    name: str = Field(min_length=2, max_length=120)
    project_id: str | None = None
    document: dict[str, Any]
    change_note: str = Field(default="", max_length=1000)


class PolicyNewVersion(Strict):
    document: dict[str, Any]
    change_note: str = Field(default="", max_length=1000)


class PolicyPreviewRequest(Strict):
    scan_id: str
    document: dict[str, Any] | None = None  # draft; defaults to the policy's current version


class PolicyVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    version: int
    document: dict[str, Any]
    change_note: str
    created_by: str | None
    created_at: datetime


class PolicyOut(BaseModel):
    id: str
    name: str
    project_id: str | None
    is_active: bool
    current_version: int
    created_at: datetime
    document: dict[str, Any]


class WebhookCreate(Strict):
    name: str = Field(min_length=2, max_length=120)
    url: str = Field(max_length=1000)
    project_id: str | None = None
    notify_on: list[Literal["PASS", "WARN", "FAIL"]] = Field(default=["FAIL"])
    enabled: bool = True


class IntegrationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    kind: str
    name: str
    project_id: str | None
    url: str
    notify_on: list[str]
    enabled: bool
    last_status: str | None
    last_error: str | None
    last_attempt_at: datetime | None
