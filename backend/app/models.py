"""SQLAlchemy 2.x models. All timestamps are timezone-aware UTC."""
from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base

JsonType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


class Role(enum.StrEnum):
    ADMIN = "admin"
    SECURITY_ENGINEER = "security_engineer"
    DEVELOPER = "developer"


class Severity(enum.StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class Decision(enum.StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class ScanStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ExecStatus(enum.StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"
    MISSING = "missing"  # executable not available
    SKIPPED = "skipped"


class FindingStatus(enum.StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"  # effective status only, derived from an active Suppression


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default=Role.DEVELOPER.value)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    repositories: Mapped[list[Repository]] = relationship(back_populates="project")


class ProjectMember(Base):
    __tablename__ = "project_members"
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)


class Repository(Base):
    __tablename__ = "repositories"
    __table_args__ = (UniqueConstraint("project_id", "full_name", name="uq_repo_project_name"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    full_name: Mapped[str] = mapped_column(String(300))  # e.g. org/repo
    ci_provider: Mapped[str] = mapped_column(String(32), default="github")
    default_branch: Mapped[str] = mapped_column(String(200), default="main")
    clone_url: Mapped[str] = mapped_column(String(500), default="")
    criticality: Mapped[str] = mapped_column(String(16), default="medium")  # low|medium|high|critical
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    ingest_token_hash: Mapped[str] = mapped_column(String(64), index=True)
    ingest_token_prefix: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    project: Mapped[Project] = relationship(back_populates="repositories")


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        UniqueConstraint("repository_id", "idempotency_key", name="uq_scan_idempotency"),
        Index("ix_scans_repo_created", "repository_id", "created_at"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(128))
    commit_sha: Mapped[str] = mapped_column(String(64))
    branch: Mapped[str] = mapped_column(String(255))
    base_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    pr_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    build_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    environment: Mapped[str] = mapped_column(String(32), default="development")
    status: Mapped[str] = mapped_column(String(16), default=ScanStatus.QUEUED.value)
    decision: Mapped[str | None] = mapped_column(String(8), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executions: Mapped[list[ScannerExecution]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    evaluation: Mapped[PolicyEvaluation | None] = relationship(back_populates="scan", uselist=False)


class ScannerExecution(Base):
    __tablename__ = "scanner_executions"
    __table_args__ = (UniqueConstraint("scan_id", "scanner", name="uq_exec_scan_scanner"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    scanner: Mapped[str] = mapped_column(String(32))
    scan_mode: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(16))
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr_tail: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parse_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    raw_report: Mapped[Any | None] = mapped_column(JsonType, nullable=True)
    scan: Mapped[Scan] = relationship(back_populates="executions")


class Finding(Base):
    """A finding's identity and lifecycle, scoped to (repository, branch, fingerprint)."""
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("repository_id", "branch", "fingerprint", name="uq_finding_identity"),
        Index("ix_findings_repo_branch_status", "repository_id", "branch", "status"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    branch: Mapped[str] = mapped_column(String(255))
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    scanner: Mapped[str] = mapped_column(String(32))
    scanner_finding_id: Mapped[str] = mapped_column(String(300))
    category: Mapped[str] = mapped_column(String(24))  # sast|dependency|container|misconfig|secret
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(12))
    scanner_severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    vuln_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    cwe: Mapped[list[str]] = mapped_column(JsonType, default=list)
    package_name: Mapped[str | None] = mapped_column(String(300), nullable=True)
    installed_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(300), nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resource: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    references: Mapped[list[str]] = mapped_column(JsonType, default=list)
    remediation: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    known_exploited: Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # None = unknown
    epss: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_factors: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    status: Mapped[str] = mapped_column(String(16), default=FindingStatus.OPEN.value)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    first_seen_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_seen_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ScanFinding(Base):
    __tablename__ = "scan_findings"
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(12))
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_new: Mapped[bool] = mapped_column(Boolean, default=False)  # not present on base branch at scan time
    new_state: Mapped[str] = mapped_column(String(12), default="unknown")  # new|existing|unknown
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)


class Suppression(Base):
    __tablename__ = "suppressions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repository_id: Mapped[str] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(36))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(36), nullable=True)


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120))
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    current_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    versions: Mapped[list[PolicyVersion]] = relationship(back_populates="policy", order_by="PolicyVersion.version")


class PolicyVersion(Base):
    __tablename__ = "policy_versions"
    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policy_version"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    document: Mapped[dict[str, Any]] = mapped_column(JsonType)
    change_note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    policy: Mapped[Policy] = relationship(back_populates="versions")


class PolicyEvaluation(Base):
    __tablename__ = "policy_evaluations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), unique=True)
    policy_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    policy_name: Mapped[str] = mapped_column(String(120))
    policy_version: Mapped[int] = mapped_column(Integer)
    decision: Mapped[str] = mapped_column(String(8))
    result: Mapped[dict[str, Any]] = mapped_column(JsonType)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    scan: Mapped[Scan] = relationship(back_populates="evaluation")


class IntegrationConfig(Base):
    __tablename__ = "integration_configs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(32))  # webhook
    name: Mapped[str] = mapped_column(String(120))
    project_id: Mapped[str | None] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)
    url: Mapped[str] = mapped_column(String(1000))
    notify_on: Mapped[list[str]] = mapped_column(JsonType, default=lambda: ["FAIL"])
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(320))  # user email or "repo-token:<repo id>"
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str] = mapped_column(String(32), default="")
    target_id: Mapped[str] = mapped_column(String(64), default="")
    project_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


class VulnIntel(Base):
    """Cache of externally sourced vulnerability intelligence (currently CISA KEV)."""
    __tablename__ = "vuln_intel"
    cve_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    data: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
