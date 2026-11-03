from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import audit, auth, dashboard, findings, health, integrations, policies, projects, scans
from app.bootstrap import bootstrap
from app.config import get_settings
from app.db import session_factory
from app.logging_setup import configure_logging
from app.middleware import BodySizeLimitMiddleware, RequestContextMiddleware

log = logging.getLogger("pipelineguard")


def _rid(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


@asynccontextmanager
async def lifespan(_: FastAPI):
    with session_factory()() as db:
        bootstrap(db)
    yield


def create_app() -> FastAPI:
    configure_logging()
    s = get_settings()
    app = FastAPI(title="PipelineGuard API", version="1.0.0", lifespan=lifespan, docs_url="/api/v1/docs",
                  redoc_url=None, openapi_url="/api/v1/openapi.json",
                  description="DevSecOps CI/CD security gate: ingest scanner results, evaluate policy, track findings.")

    @app.exception_handler(HTTPException)
    async def http_exc(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse({"error": "http_error", "detail": exc.detail, "request_id": _rid(request)}, status_code=exc.status_code,
                            headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_exc(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Only location + message: never echo submitted values (they may contain secrets).
        detail = [{"loc": [str(x) for x in e["loc"]], "msg": e["msg"], "type": e["type"]} for e in exc.errors()]
        return JSONResponse({"error": "validation_error", "detail": detail, "request_id": _rid(request)}, status_code=422)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error", extra={"request_id": _rid(request)})
        return JSONResponse({"error": "internal_error", "detail": "Internal server error", "request_id": _rid(request)}, status_code=500)

    if s.cors_origin_list:
        app.add_middleware(CORSMiddleware, allow_origins=s.cors_origin_list, allow_methods=["GET", "POST", "PATCH", "DELETE"],
                           allow_headers=["Authorization", "Content-Type"], allow_credentials=False, max_age=600)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=s.max_body_bytes)
    app.add_middleware(RequestContextMiddleware)

    for r in (health.router, auth.router, projects.router, scans.router, findings.router, policies.router, dashboard.router,
              integrations.router, audit.router):
        app.include_router(r, prefix="/api/v1")
    return app


app = create_app()
