from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db, session_factory
from app.deps import accessible_project_ids, client_ip, current_user, ensure_repo_access, repo_from_token, require_roles
from app.models import PolicyEvaluation, Repository, Role, Scan, ScanStatus, User
from app.schemas import (
    ExecutionOut, IngestRequest, IngestResponse, Page, ScanDetail, ScanOut, ScanReport, ScanStart,
)
from app.services import audit, ingest, policy_store, report, webhooks

router = APIRouter(tags=["scans"])
FINAL = {ScanStatus.COMPLETED.value, ScanStatus.FAILED.value, ScanStatus.CANCELLED.value}


def _scan_for_user(db: Session, user: User, scan_id: str) -> tuple[Scan, Repository]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan not found")
    return scan, ensure_repo_access(db, user, scan.repository_id)


def _response(scan: Scan, replay: bool, db: Session) -> IngestResponse:
    ev = db.scalar(select(PolicyEvaluation).where(PolicyEvaluation.scan_id == scan.id))
    decision = scan.decision or "FAIL"  # fail closed if somehow absent
    return IngestResponse(scan_id=scan.id, status=scan.status, decision=decision, summary=ev.result["summary"] if ev else "",
                          idempotent_replay=replay, report_url=f"{get_settings().public_base_url.rstrip('/')}/scans/{scan.id}",
                          exit_code=1 if decision == "FAIL" else 0)


def _notify(scan_id: str) -> None:
    with session_factory()() as db:
        scan = db.get(Scan, scan_id)
        if scan:
            repo = db.get(Repository, scan.repository_id)
            if repo:
                webhooks.notify_scan(db, scan, repo)


@router.post("/ingest", response_model=IngestResponse)
def ingest_endpoint(body: IngestRequest, request: Request, response: Response, bg: BackgroundTasks,
                    repo: Repository = Depends(repo_from_token), db: Session = Depends(get_db)):
    key = body.idempotency_key or ingest.derive_idempotency_key(body)
    scan, created = ingest.get_or_create_scan(db, repo, key=key, commit_sha=body.commit_sha, branch=body.branch,
                                             base_branch=body.base_branch, pr_number=body.pr_number, build_id=body.build_id,
                                             status=ScanStatus.RUNNING)
    if not created and scan.status in FINAL:
        db.commit()
        response.status_code = 200
        return _response(scan, True, db)
    scan = ingest.ingest_results(db, repo, scan, body.scanners, actor=f"repo-token:{repo.id}", ip=client_ip(request))
    bg.add_task(_notify, scan.id)
    response.status_code = 201 if created else 200
    return _response(scan, False, db)


@router.post("/scans", response_model=ScanOut, status_code=201)
def start_scan(body: ScanStart, response: Response, repo: Repository = Depends(repo_from_token), db: Session = Depends(get_db)):
    scan, created = ingest.get_or_create_scan(db, repo, key=body.idempotency_key, commit_sha=body.commit_sha, branch=body.branch,
                                             base_branch=body.base_branch, pr_number=body.pr_number, build_id=body.build_id,
                                             status=ScanStatus.RUNNING)
    db.commit()
    response.status_code = 201 if created else 200
    return ScanOut.model_validate(scan)


@router.post("/scans/{scan_id}/report", response_model=IngestResponse)
def submit_report(scan_id: str, body: ScanReport, request: Request, bg: BackgroundTasks,
                  repo: Repository = Depends(repo_from_token), db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if scan is None or scan.repository_id != repo.id:
        raise HTTPException(404, "Scan not found")
    if scan.status in FINAL:
        if scan.status == ScanStatus.CANCELLED.value:
            raise HTTPException(409, "Scan was cancelled")
        return _response(scan, True, db)
    scan = ingest.ingest_results(db, repo, scan, body.scanners, actor=f"repo-token:{repo.id}", ip=client_ip(request))
    bg.add_task(_notify, scan.id)
    return _response(scan, False, db)


@router.post("/scans/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(scan_id: str, request: Request, repo: Repository = Depends(repo_from_token), db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if scan is None or scan.repository_id != repo.id:
        raise HTTPException(404, "Scan not found")
    if scan.status not in (ScanStatus.QUEUED.value, ScanStatus.RUNNING.value):
        raise HTTPException(409, f"Scan is already {scan.status}")
    scan.status = ScanStatus.CANCELLED.value
    from datetime import UTC, datetime
    scan.finished_at = datetime.now(UTC)
    audit.record(db, actor=f"repo-token:{repo.id}", action="scan.cancelled", target_type="scan", target_id=scan.id,
                 project_id=repo.project_id, ip=client_ip(request))
    db.commit()
    return ScanOut.model_validate(scan)


@router.post("/scans/{scan_id}/reevaluate", response_model=IngestResponse)
def reevaluate(scan_id: str, request: Request, db: Session = Depends(get_db),
               user: User = Depends(require_roles(Role.ADMIN, Role.SECURITY_ENGINEER))):
    scan, repo = _scan_for_user(db, user, scan_id)
    if scan.status not in (ScanStatus.COMPLETED.value, ScanStatus.FAILED.value):
        raise HTTPException(409, "Only finished scans can be re-evaluated")
    old = scan.decision
    policy_store.evaluate_and_store(db, scan, repo.project_id)
    audit.record(db, actor=user.email, action="scan.reevaluated", target_type="scan", target_id=scan.id, project_id=repo.project_id,
                 details={"from": old, "to": scan.decision}, ip=client_ip(request))
    db.commit()
    return _response(scan, False, db)


def _scan_out(s: Scan, names: dict[str, str]) -> ScanOut:
    o = ScanOut.model_validate(s)
    o.repository = names.get(s.repository_id)
    return o


@router.get("/scans", response_model=Page[ScanOut])
def list_scans(repository_id: str | None = None, branch: str | None = None, decision: str | None = None, status: str | None = None,
               limit: int = Query(25, ge=1, le=200), offset: int = Query(0, ge=0), db: Session = Depends(get_db),
               user: User = Depends(current_user)):
    ids = accessible_project_ids(db, user)
    q = select(Scan).join(Repository, Repository.id == Scan.repository_id)
    if ids is not None:
        q = q.where(Repository.project_id.in_(ids))
    for col, val in ((Scan.repository_id, repository_id), (Scan.branch, branch), (Scan.decision, decision), (Scan.status, status)):
        if val:
            q = q.where(col == val)
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    scans = db.scalars(q.order_by(Scan.created_at.desc()).limit(limit).offset(offset)).all()
    names = {r.id: r.full_name for r in db.scalars(select(Repository).where(Repository.id.in_({s.repository_id for s in scans})))} if scans else {}
    return Page[ScanOut](items=[_scan_out(s, names) for s in scans], total=total, limit=limit, offset=offset)


@router.get("/scans/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    scan, repo = _scan_for_user(db, user, scan_id)
    ev = db.scalar(select(PolicyEvaluation).where(PolicyEvaluation.scan_id == scan.id))
    base = ScanOut.model_validate(scan).model_dump()
    base["repository"] = repo.full_name
    return ScanDetail(**base, executions=[ExecutionOut.model_validate(e) for e in sorted(scan.executions, key=lambda e: e.scanner)],
                      evaluation=ev.result if ev else None, severity_counts=report.severity_counts(db, scan.id),
                      new_counts=report.severity_counts(db, scan.id, only_new=True))


@router.get("/scans/{scan_id}/report.json")
def report_json(scan_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)) -> Response:
    import json
    scan, _ = _scan_for_user(db, user, scan_id)
    body = json.dumps(report.build_json_report(db, scan), indent=2)
    return Response(body, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="pipelineguard-{scan.id}.json"'})


@router.get("/scans/{scan_id}/report.md")
def report_md(scan_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)) -> Response:
    scan, _ = _scan_for_user(db, user, scan_id)
    return Response(report.build_markdown(report.build_json_report(db, scan)), media_type="text/markdown; charset=utf-8")


@router.get("/ci/scans/{scan_id}/report.md")
def ci_report_md(scan_id: str, repo: Repository = Depends(repo_from_token), db: Session = Depends(get_db)) -> Response:
    """Markdown summary for the CI job that submitted the scan (used for pull-request comments)."""
    scan = db.get(Scan, scan_id)
    if scan is None or scan.repository_id != repo.id:
        raise HTTPException(404, "Scan not found")
    return Response(report.build_markdown(report.build_json_report(db, scan)), media_type="text/markdown; charset=utf-8")


__all__ = ["router", "Any"]
