from datetime import UTC, datetime, timedelta
import hashlib
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.current_user import Principal, get_current_principal
from app.auth.jwt import create_access_token
from app.auth.passwords import verify_password_or_dummy
from app.audit.service import AuditService
from app.config import get_settings
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas.auth import LoginRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)


def _hash_identifier(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def _principal_resource(email: str) -> str:
    return f"auth:login:principal:{_hash_identifier(email.strip().lower())}"


def _ip_resource(ip_address: str) -> str:
    return f"auth:login:ip:{_hash_identifier(ip_address)}"


def _principal_ip_resource(email: str, ip_address: str) -> str:
    normalized = f"{email.strip().lower()}|{ip_address}"
    return f"auth:login:principal_ip:{_hash_identifier(normalized)}"


def _client_ip(request: Request) -> str:
    return request.client.host if request.client and request.client.host else "unknown"


def _count_recent_denies(db: Session, *, resource: str, window_seconds: int) -> int:
    last_allow_at = db.scalar(
        select(func.max(AuditLog.timestamp)).where(
            AuditLog.resource == resource,
            AuditLog.action == "login",
            AuditLog.decision == "allow",
        )
    )
    window_start = datetime.now(UTC) - timedelta(seconds=window_seconds)
    if last_allow_at is not None and last_allow_at.tzinfo is None:
        last_allow_at = last_allow_at.replace(tzinfo=UTC)
    effective_start = max(window_start, last_allow_at) if last_allow_at else window_start
    count = db.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(
            AuditLog.resource == resource,
            AuditLog.action == "login",
            AuditLog.decision == "deny",
            AuditLog.timestamp >= effective_start,
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
    client_ip = _client_ip(request)
    principal_resource = _principal_resource(str(payload.email))
    principal_ip_resource = _principal_ip_resource(str(payload.email), client_ip)
    ip_resource = _ip_resource(client_ip)
    principal_ip_failed_attempts = _count_recent_denies(
        db,
        resource=principal_ip_resource,
        window_seconds=settings.login_rate_limit_window_seconds,
    )
    ip_failed_attempts = _count_recent_denies(
        db,
        resource=ip_resource,
        window_seconds=settings.login_rate_limit_window_seconds,
    )

    if (
        principal_ip_failed_attempts >= settings.login_rate_limit_attempts
        or ip_failed_attempts >= settings.login_rate_limit_attempts * 3
    ):
        throttled_resource = principal_ip_resource if principal_ip_failed_attempts >= settings.login_rate_limit_attempts else ip_resource
        audit.record(
            request_id=request.state.request_id,
            user_id=None,
            tenant_id=None,
            resource=throttled_resource,
            action="login",
            allow=False,
            reason="rate limit exceeded",
            source="auth",
        )
        logger.warning("login rate limit exceeded", extra={"resource": throttled_resource})
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
            resource=principal_ip_resource,
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
        logger.warning("login failed", extra={"email_hash": _hash_identifier(str(payload.email).strip().lower()), "ip_hash": _hash_identifier(client_ip)})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    audit.record(
        request_id=request.state.request_id,
        user_id=user.id,
        tenant_id=user.tenant_id,
        resource=principal_ip_resource,
        action="login",
        allow=True,
        reason="authenticated",
        source="auth",
    )
    token = create_access_token(
        user_id=user.id,
        tenant_id=user.tenant_id,
        email=user.email,
        token_version=user.token_version,
        settings=settings,
    )
    logger.info("login succeeded", extra={"user_id": user.id, "tenant_id": user.tenant_id})
    return TokenResponse(access_token=token, expires_in=settings.jwt_ttl_seconds)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke current bearer token family",
    description=(
        "Invalidates the caller's currently issued JWT family by incrementing the stored token version. "
        "Subsequent use of previously issued bearer tokens is rejected."
    ),
    responses={
        204: {"description": "Current token family revoked."},
        401: {"description": "Missing or invalid JWT."},
    },
)
def logout(
    request: Request,
    principal: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> None:
    user = db.get(User, principal.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")
    user.token_version += 1
    db.add(user)
    db.commit()
    AuditService(db).record(
        request_id=request.state.request_id,
        user_id=user.id,
        tenant_id=user.tenant_id,
        resource=f"user:{user.id}",
        action="logout",
        allow=True,
        reason="token version incremented",
        source="auth",
    )
    logger.info("logout revoked token family", extra={"user_id": user.id, "tenant_id": user.tenant_id})
