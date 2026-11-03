from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import (
    accessible_project_ids, client_ip, current_user, ensure_project_access, ensure_repo_access, require_roles,
)
from app.models import Finding, FindingStatus, Project, ProjectMember, Repository, Role, Scan, User
from app.schemas import (
    MemberAdd, Page, ProjectCreate, ProjectOut, RepositoryCreate, RepositoryCreated, RepositoryOut, RepositoryUpdate,
)
from app.security import generate_ingest_token
from app.services import audit

router = APIRouter(tags=["projects"])
WRITERS = (Role.ADMIN, Role.SECURITY_ENGINEER)


@router.get("/projects", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db), user: User = Depends(current_user)):
    ids = accessible_project_ids(db, user)
    q = select(Project).order_by(Project.name)
    if ids is not None:
        q = q.where(Project.id.in_(ids))
    return db.scalars(q).all()


@router.post("/projects", response_model=ProjectOut, status_code=201)
def create_project(body: ProjectCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles(Role.ADMIN))):
    p = Project(name=body.name, description=body.description)
    db.add(p)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A project with this name already exists") from None
    audit.record(db, actor=user.email, action="project.created", target_type="project", target_id=p.id, project_id=p.id,
                 details={"name": p.name}, ip=client_ip(request))
    db.commit()
    return p


@router.post("/projects/{project_id}/members", status_code=204)
def add_member(project_id: str, body: MemberAdd, request: Request, db: Session = Depends(get_db),
               user: User = Depends(require_roles(Role.ADMIN))):
    ensure_project_access(db, user, project_id)
    if db.get(User, body.user_id) is None:
        raise HTTPException(404, "User not found")
    if db.get(ProjectMember, (project_id, body.user_id)) is None:
        db.add(ProjectMember(project_id=project_id, user_id=body.user_id))
        audit.record(db, actor=user.email, action="project.member_added", target_type="project", target_id=project_id,
                     project_id=project_id, details={"user_id": body.user_id}, ip=client_ip(request))
        db.commit()


@router.delete("/projects/{project_id}/members/{user_id}", status_code=204)
def remove_member(project_id: str, user_id: str, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require_roles(Role.ADMIN))):
    m = db.get(ProjectMember, (project_id, user_id))
    if m:
        db.delete(m)
        audit.record(db, actor=user.email, action="project.member_removed", target_type="project", target_id=project_id,
                     project_id=project_id, details={"user_id": user_id}, ip=client_ip(request))
        db.commit()


@router.post("/repositories", response_model=RepositoryCreated, status_code=201)
def register_repository(body: RepositoryCreate, request: Request, db: Session = Depends(get_db),
                        user: User = Depends(require_roles(*WRITERS))):
    ensure_project_access(db, user, body.project_id)
    plain, digest, prefix = generate_ingest_token()
    repo = Repository(**body.model_dump(), ingest_token_hash=digest, ingest_token_prefix=prefix)
    db.add(repo)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Repository already registered in this project") from None
    audit.record(db, actor=user.email, action="repository.registered", target_type="repository", target_id=repo.id,
                 project_id=repo.project_id, details={"full_name": repo.full_name}, ip=client_ip(request))
    db.commit()
    return RepositoryCreated(**RepositoryOut.model_validate(repo).model_dump(), ingest_token=plain)


@router.post("/repositories/{repo_id}/rotate-token", response_model=RepositoryCreated)
def rotate_token(repo_id: str, request: Request, db: Session = Depends(get_db), user: User = Depends(require_roles(*WRITERS))):
    repo = ensure_repo_access(db, user, repo_id)
    plain, digest, prefix = generate_ingest_token()
    repo.ingest_token_hash, repo.ingest_token_prefix = digest, prefix
    audit.record(db, actor=user.email, action="repository.token_rotated", target_type="repository", target_id=repo.id,
                 project_id=repo.project_id, ip=client_ip(request))
    db.commit()
    return RepositoryCreated(**RepositoryOut.model_validate(repo).model_dump(), ingest_token=plain)


@router.get("/repositories", response_model=Page[dict])
def list_repositories(project_id: str | None = None, limit: int = 50, offset: int = 0, db: Session = Depends(get_db),
                      user: User = Depends(current_user)):
    limit = max(1, min(limit, 200))
    ids = accessible_project_ids(db, user)
    q = select(Repository)
    if ids is not None:
        q = q.where(Repository.project_id.in_(ids))
    if project_id:
        q = q.where(Repository.project_id == project_id)
    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    repos = db.scalars(q.order_by(Repository.full_name).limit(limit).offset(offset)).all()
    items = []
    for r in repos:
        last = db.scalar(select(Scan).where(Scan.repository_id == r.id).order_by(Scan.created_at.desc()).limit(1))
        open_by_sev = dict(db.execute(
            select(Finding.severity, func.count()).where(
                Finding.repository_id == r.id, Finding.branch == r.default_branch,
                Finding.status.in_([FindingStatus.OPEN.value, FindingStatus.ACKNOWLEDGED.value])).group_by(Finding.severity)).all())
        items.append({**RepositoryOut.model_validate(r).model_dump(mode="json"),
                      "latest_scan": {"id": last.id, "status": last.status, "decision": last.decision, "branch": last.branch,
                                      "commit_sha": last.commit_sha, "created_at": last.created_at.isoformat()} if last else None,
                      "open_findings": open_by_sev})
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/repositories/{repo_id}", response_model=RepositoryOut)
def get_repository(repo_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    return ensure_repo_access(db, user, repo_id)


@router.patch("/repositories/{repo_id}", response_model=RepositoryOut)
def update_repository(repo_id: str, body: RepositoryUpdate, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(require_roles(*WRITERS))):
    repo = ensure_repo_access(db, user, repo_id)
    changes = body.model_dump(exclude_none=True)
    for k, v in changes.items():
        setattr(repo, k, v)
    if changes:
        audit.record(db, actor=user.email, action="repository.updated", target_type="repository", target_id=repo.id,
                     project_id=repo.project_id, details=changes, ip=client_ip(request))
    db.commit()
    return repo
