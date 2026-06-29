from functools import lru_cache

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.jwt import create_access_token
from app.auth.passwords import verify_password
from app.auth.rate_limit import LoginRateLimiter
from app.audit.service import AuditService
from app.config import get_settings
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@lru_cache
def get_login_rate_limiter() -> LoginRateLimiter:
    settings = get_settings()
    return LoginRateLimiter(
        attempts=settings.login_rate_limit_attempts,
        window_seconds=settings.login_rate_limit_window_seconds,
    )


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
    limiter = get_login_rate_limiter()
    audit = AuditService(db)
    client_ip = request.client.host if request.client else "unknown"
    throttle_key = f"{payload.email.lower()}:{client_ip}"

    if not limiter.allow(throttle_key):
        audit.record(
            request_id=request.state.request_id,
            user_id=None,
            tenant_id=None,
            resource="auth:login",
            action="login",
            allow=False,
            reason="rate limit exceeded",
            source="auth",
        )
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many failed login attempts")

    user = db.scalar(select(User).where(User.email == payload.email))
    if user is None or not verify_password(payload.password, user.password_hash):
        limiter.record_failure(throttle_key)
        audit.record(
            request_id=request.state.request_id,
            user_id=user.id if user else None,
            tenant_id=user.tenant_id if user else None,
            resource="auth:login",
            action="login",
            allow=False,
            reason="invalid credentials",
            source="auth",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    limiter.clear(throttle_key)
    token = create_access_token(user_id=user.id, tenant_id=user.tenant_id, email=user.email, settings=settings)
    return TokenResponse(access_token=token, expires_in=settings.jwt_ttl_seconds)
