from datetime import UTC, datetime, timedelta
import logging
from typing import Any

import jwt
from fastapi import HTTPException, status
from pydantic import ValidationError

from app.config import Settings, get_settings
from app.schemas.auth import IdentityClaims

ALGORITHM = "HS256"
logger = logging.getLogger(__name__)


def create_access_token(
    *,
    user_id: str,
    tenant_id: str,
    email: str,
    token_version: int,
    settings: Settings | None = None,
) -> str:
    settings = settings or get_settings()
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "email": email,
        "token_version": token_version,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.jwt_ttl_seconds)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def decode_access_token(token: str, settings: Settings | None = None) -> IdentityClaims:
    settings = settings or get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[ALGORITHM],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={
                "require": ["sub", "tenant_id", "email", "token_version", "iss", "aud", "exp", "iat", "nbf"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
        return IdentityClaims.model_validate(payload)
    except (jwt.PyJWTError, ValidationError) as exc:
        logger.warning("access token rejected", extra={"reason": exc.__class__.__name__})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token") from exc
