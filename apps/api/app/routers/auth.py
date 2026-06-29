from datetime import UTC, datetime, timedelta
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.jwt import create_access_token
from app.auth.passwords import verify_password_or_dummy
from app.audit.service import AuditService
from app.config import get_settings
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas.auth import LoginRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])


def _hash_identifier(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def _principal_resource(email: str) -> str:
    return f"auth:login:principal:{_hash_identifier(email.strip().lower())}"


def _ip_resource(ip_address: str) -> str:
    return f"auth:login:ip:{_hash_identifier(ip_address)}"


def _client_ip(request: Request) -> str:
    return request.client.host if request.client and request.client.host else "unknown"


def _count_recent_denies(db: Session, *, resource: str, window_seconds: int) -> int:
    count = db.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(
            AuditLog.resource == resource,
            AuditLog.action == "login",
            AuditLog.decision == "deny",
            AuditLog.timestamp >= datetime.now(UTC) - timedelta(seconds=window_seconds),
        )
    )
    return int(count or 0)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Issue a development JWT",
    description=(
        "Authenticates a local demo user and returns a JWT containing identity claims only. "
        "The token does not contain document permissions, roles, groups, or authorization state."
    ),
    responses={
        200: {"description": "JWT issued."},
        401: {"description": "Invalid credentials."},
        429: {"description": "Too many failed login attempts."},
    },
)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    settings = get_settings()
    audit = AuditService(db)
    principal_resource = _principal_resource(str(payload.email))
    ip_resource = _ip_resource(_client_ip(request))
    principal_failed_attempts = _count_recent_denies(
        db,
        resource=principal_resource,
        window_seconds=settings.login_rate_limit_window_seconds,
    )
    ip_failed_attempts = _count_recent_denies(
        db,
        resource=ip_resource,
        window_seconds=settings.login_rate_limit_window_seconds,
    )

    if (
        principal_failed_attempts >= settings.login_rate_limit_attempts
        or ip_failed_attempts >= settings.login_rate_limit_attempts * 3
    ):
        audit.record(
            request_id=request.state.request_id,
            user_id=None,
            tenant_id=None,
            resource=principal_resource if principal_failed_attempts >= settings.login_rate_limit_attempts else ip_resource,
            action="login",
            allow=False,
            reason="rate limit exceeded",
            source="auth",
        )
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many failed login attempts")

    user = db.scalar(select(User).where(User.email == payload.email))
    password_valid = verify_password_or_dummy(payload.password, user.password_hash if user else None)
    if user is None or not password_valid:
        audit.record(
            request_id=request.state.request_id,
            user_id=user.id if user else None,
            tenant_id=user.tenant_id if user else None,
            resource=principal_resource,
            action="login",
            allow=False,
            reason="invalid credentials",
            source="auth",
        )
        audit.record(
            request_id=request.state.request_id,
            user_id=user.id if user else None,
            tenant_id=user.tenant_id if user else None,
            resource=ip_resource,
            action="login",
            allow=False,
            reason="invalid credentials",
            source="auth",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(user_id=user.id, tenant_id=user.tenant_id, email=user.email, settings=settings)
    return TokenResponse(access_token=token, expires_in=settings.jwt_ttl_seconds)
