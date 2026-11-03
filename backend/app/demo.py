"""Optional demo dataset (PG_SEED_DEMO_DATA=true, development only). It ingests the repository's REAL scanner
fixtures through the normal ingestion path, into a clearly named 'DEMO' project."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Project, Repository, ScanStatus
from app.schemas import IngestRequest, ScannerSubmission
from app.security import generate_ingest_token
from app.services import ingest

FIX = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def seed_demo(db: Session) -> None:
    if db.scalar(select(Project).where(Project.name == "DEMO (sample data)")):
        return
    proj = Project(name="DEMO (sample data)", description="Seeded demo data - safe to delete. Never enable in production.")
    db.add(proj)
    db.flush()
    _, digest, prefix = generate_ingest_token()
    repo = Repository(project_id=proj.id, full_name="demo/vulnerable-app", ci_provider="github", default_branch="main",
                      ingest_token_hash=digest, ingest_token_prefix=prefix, criticality="high", internet_facing=True)
    db.add(repo)
    db.commit()
    now = datetime.now(UTC)
    semgrep = json.loads((FIX / "semgrep_real.json").read_text())
    trivy_cfg = json.loads((FIX / "trivy_config_secret_real.json").read_text())
    trivy_deps = json.loads((FIX / "trivy_vulns_synthetic.json").read_text())
    req = IngestRequest(commit_sha="a" * 40, branch="main", build_id="demo-1", scanners=[
        ScannerSubmission(scanner="semgrep", status="succeeded", report=semgrep, started_at=now, finished_at=now),
        ScannerSubmission(scanner="trivy", status="succeeded", report=trivy_deps, started_at=now, finished_at=now)])
    scan, _ = ingest.get_or_create_scan(db, repo, key="demo-1", commit_sha=req.commit_sha, branch="main", base_branch=None,
                                        pr_number=None, build_id="demo-1", status=ScanStatus.RUNNING)
    ingest.ingest_results(db, repo, scan, req.scanners, actor="demo-seed")
    _ = trivy_cfg
