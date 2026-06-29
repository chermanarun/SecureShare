import httpx
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db.session import get_db
from app.schemas.health import ComponentStatus, HealthStatus, ReadinessStatus

router = APIRouter(tags=["health"])


@router.get(
    "/healthz",
    response_model=HealthStatus,
    summary="Liveness health check",
    description="Returns a lightweight liveness response. This endpoint does not check downstream dependencies.",
)
def healthz() -> HealthStatus:
    settings = get_settings()
    return HealthStatus(status="ok", service=settings.app_name, version="0.1.0")


@router.get(
    "/readyz",
    response_model=ReadinessStatus,
    summary="Readiness health check",
    description="Checks whether the API can reach PostgreSQL and OpenFGA. Use this for smoke tests and deployment readiness.",
    responses={503: {"description": "One or more required dependencies are unavailable."}},
)
def readyz(db: Session = Depends(get_db)) -> JSONResponse | ReadinessStatus:
    settings = get_settings()
    components: dict[str, ComponentStatus] = {}

    try:
        db.execute(text("select 1"))
        components["postgres"] = ComponentStatus(status="ok", detail="select 1 succeeded")
    except Exception:
        components["postgres"] = ComponentStatus(status="error", detail="database unavailable")

    try:
        response = httpx.get(f"{settings.openfga_api_url.rstrip('/')}/healthz", timeout=2.0)
        response.raise_for_status()
        components["openfga"] = ComponentStatus(status="ok", detail="health endpoint succeeded")
    except Exception:
        components["openfga"] = ComponentStatus(status="error", detail="authorization backend unavailable")

    overall = "ok" if all(component.status == "ok" for component in components.values()) else "error"
    payload = ReadinessStatus(status=overall, service=settings.app_name, version="0.1.0", components=components)
    if overall != "ok":
        return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=payload.model_dump())
    return payload
