from collections import defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, literal_column, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import accessible_project_ids, active_suppression_clause, current_user
from app.models import Finding, FindingStatus, Repository, Scan, ScanFinding, User
from app.services.policy import SEV_RANK

router = APIRouter(tags=["dashboard"])


def _day(col):
    # literal (not a bound parameter) so SELECT and GROUP BY render identical SQL
    return func.date_trunc(literal_column("'day'"), col)
OPEN = [FindingStatus.OPEN.value, FindingStatus.ACKNOWLEDGED.value]


def _repo_ids(db: Session, user: User) -> list[str]:
    ids = accessible_project_ids(db, user)
    q = select(Repository.id)
    if ids is not None:
        q = q.where(Repository.project_id.in_(ids))
    return list(db.scalars(q))


@router.get("/dashboard/overview")
def overview(window_days: int = Query(30, ge=1, le=365), db: Session = Depends(get_db), user: User = Depends(current_user)):
    repo_ids = _repo_ids(db, user)
    since = datetime.now(UTC) - timedelta(days=window_days)
    if not repo_ids:
        return {"repositories": 0, "scans": {"total": 0, "window": 0}, "open_findings": {s: 0 for s in SEV_RANK}, "suppressed_findings": 0,
                "decisions": {"PASS": 0, "WARN": 0, "FAIL": 0}, "pass_rate": None, "new_in_window": 0, "resolved_in_window": 0,
                "recent_scans": [], "recent_failures": [], "top_remediation": [], "window_days": window_days}
    scans_q = select(Scan).where(Scan.repository_id.in_(repo_ids))
    total_scans = db.scalar(select(func.count()).select_from(scans_q.subquery())) or 0
    window_scans = db.scalar(select(func.count()).select_from(scans_q.where(Scan.created_at >= since).subquery())) or 0
    dec = dict(db.execute(select(Scan.decision, func.count()).where(Scan.repository_id.in_(repo_ids), Scan.created_at >= since,
                                                                    Scan.decision.is_not(None)).group_by(Scan.decision)).all())
    decisions = {k: dec.get(k, 0) for k in ("PASS", "WARN", "FAIL")}
    decided = sum(decisions.values())
    # "Open findings" = default-branch findings that are open/acknowledged and not actively suppressed.
    base = (Finding.repository_id.in_(repo_ids), Finding.branch == Repository.default_branch, Finding.repository_id == Repository.id)
    open_rows = db.execute(select(Finding.severity, func.count()).where(*base, Finding.status.in_(OPEN), ~active_suppression_clause())
                           .group_by(Finding.severity)).all()
    open_by_sev = {s: 0 for s in SEV_RANK}
    open_by_sev.update(dict(open_rows))
    suppressed = db.scalar(select(func.count()).where(*base, Finding.status.in_(OPEN), active_suppression_clause())) or 0
    new_w = db.scalar(select(func.count()).where(*base, Finding.first_seen_at >= since)) or 0
    res_w = db.scalar(select(func.count()).where(*base, Finding.resolved_at >= since)) or 0
    recent = db.scalars(scans_q.order_by(Scan.created_at.desc()).limit(8)).all()
    fails = db.scalars(scans_q.where(Scan.decision == "FAIL").order_by(Scan.created_at.desc()).limit(5)).all()
    names = {r.id: r.full_name for r in db.scalars(select(Repository).where(Repository.id.in_(repo_ids)))}

    def s(sc: Scan) -> dict:
        return {"id": sc.id, "repository": names.get(sc.repository_id), "branch": sc.branch, "commit_sha": sc.commit_sha,
                "status": sc.status, "decision": sc.decision, "created_at": sc.created_at.isoformat()}

    top = db.execute(select(Finding, Repository.full_name).join(Repository, Repository.id == Finding.repository_id)
                     .where(*base, Finding.status.in_(OPEN), ~active_suppression_clause())
                     .order_by(Finding.risk_score.desc(), Finding.id).limit(8)).all()
    return {
        "window_days": window_days, "repositories": len(repo_ids), "scans": {"total": total_scans, "window": window_scans},
        "open_findings": open_by_sev, "suppressed_findings": suppressed, "decisions": decisions,
        "pass_rate": round((decisions["PASS"] + decisions["WARN"]) / decided * 100, 1) if decided else None,
        "new_in_window": new_w, "resolved_in_window": res_w,
        "recent_scans": [s(x) for x in recent], "recent_failures": [s(x) for x in fails],
        "top_remediation": [{"id": f.id, "title": f.title, "severity": f.severity, "risk_score": f.risk_score, "repository": n,
                             "package": f.package_name, "fixed_version": f.fixed_version, "file_path": f.file_path,
                             "remediation": f.remediation[:200]} for f, n in top],
    }


@router.get("/dashboard/trends")
def trends(days: int = Query(30, ge=1, le=365), db: Session = Depends(get_db), user: User = Depends(current_user)):
    repo_ids = _repo_ids(db, user)
    since = datetime.now(UTC) - timedelta(days=days)
    out: dict[str, dict] = defaultdict(lambda: {"scans": 0, "PASS": 0, "WARN": 0, "FAIL": 0, "new": 0, "resolved": 0, "risk": 0.0})
    if repo_ids:
        for decision, day, n in db.execute(select(Scan.decision, _day(Scan.created_at), func.count()).where(
                Scan.repository_id.in_(repo_ids), Scan.created_at >= since).group_by(Scan.decision, _day(Scan.created_at))):
            d = out[day.date().isoformat()]
            d["scans"] += n
            if decision in ("PASS", "WARN", "FAIL"):
                d[decision] += n
        base = (Finding.repository_id.in_(repo_ids), Finding.branch == Repository.default_branch, Finding.repository_id == Repository.id)
        for day, n in db.execute(select(_day(Finding.first_seen_at), func.count()).where(*base, Finding.first_seen_at >= since)
                                 .group_by(_day(Finding.first_seen_at))):
            out[day.date().isoformat()]["new"] += n
        for day, n in db.execute(select(_day(Finding.resolved_at), func.count()).where(*base, Finding.resolved_at >= since)
                                 .group_by(_day(Finding.resolved_at))):
            out[day.date().isoformat()]["resolved"] += n
        # Risk exposure per day: total risk of findings in the LAST default-branch scan of each repo on that day.
        rows = db.execute(select(Scan.id, Scan.repository_id, Scan.created_at).join(Repository, Repository.id == Scan.repository_id)
                          .where(Scan.repository_id.in_(repo_ids), Scan.branch == Repository.default_branch, Scan.created_at >= since,
                                 Scan.status.in_(["completed", "failed"])).order_by(Scan.created_at)).all()
        last: dict[tuple[str, str], str] = {}
        for sid, rid, created in rows:
            last[(rid, created.date().isoformat())] = sid
        if last:
            sums = dict(db.execute(select(ScanFinding.scan_id, func.coalesce(func.sum(ScanFinding.risk_score), 0.0))
                                   .where(ScanFinding.scan_id.in_(set(last.values()))).group_by(ScanFinding.scan_id)).all())
            for (_, day), sid in last.items():
                out[day]["risk"] = round(out[day]["risk"] + float(sums.get(sid, 0.0)), 1)
    return {"days": days, "points": [{"date": k, **v} for k, v in sorted(out.items())]}
