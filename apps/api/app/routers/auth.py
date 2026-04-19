from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.jwt import create_access_token
from app.auth.passwords import verify_password
from app.config import get_settings
from app.db.session import get_db
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
    },
)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.scalar(select(User).where(User.email == payload.email))
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    settings = get_settings()
    token = create_access_token(user_id=user.id, tenant_id=user.tenant_id, email=user.email, settings=settings)
    return TokenResponse(access_token=token, expires_in=settings.jwt_ttl_seconds)
