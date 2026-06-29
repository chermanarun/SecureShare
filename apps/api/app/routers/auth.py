from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth.jwt import create_access_token
from app.auth.passwords import verify_password
from app.audit.service import AuditService
from app.config import get_settings
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas.auth import LoginRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])


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
    login_resource = f"auth:login:{payload.email.lower()}"
    failed_attempts = db.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(
            AuditLog.resource == login_resource,
            AuditLog.action == "login",
            AuditLog.decision == "deny",
            AuditLog.timestamp >= datetime.now(UTC) - timedelta(seconds=settings.login_rate_limit_window_seconds),
        )
    )

    if failed_attempts is not None and failed_attempts >= settings.login_rate_limit_attempts:
        audit.record(
            request_id=request.state.request_id,
            user_id=None,
            tenant_id=None,
            resource=login_resource,
            action="login",
            allow=False,
            reason="rate limit exceeded",
            source="auth",
        )
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many failed login attempts")

    user = db.scalar(select(User).where(User.email == payload.email))
    if user is None or not verify_password(payload.password, user.password_hash):
        audit.record(
            request_id=request.state.request_id,
            user_id=user.id if user else None,
            tenant_id=user.tenant_id if user else None,
            resource=login_resource,
            action="login",
            allow=False,
            reason="invalid credentials",
            source="auth",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(user_id=user.id, tenant_id=user.tenant_id, email=user.email, settings=settings)
    return TokenResponse(access_token=token, expires_in=settings.jwt_ttl_seconds)
