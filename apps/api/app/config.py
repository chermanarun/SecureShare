from functools import lru_cache
import secrets
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_JWT_SECRET = "dev-only-change-me-minimum-32-characters"
DEFAULT_MACAROON_ROOT_KEY = "dev-macaroon-root-key-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SECURESHARE_", env_file=".env", extra="ignore")

    app_name: str = "SecureShare"
    environment: Literal["dev", "test", "prod"] = "dev"
    database_url: str = "postgresql+psycopg://secureshare:secureshare@postgres:5432/secureshare"
    jwt_issuer: str = "secureshare-dev"
    jwt_audience: str = "secureshare-api"
    jwt_secret: str | None = None
    jwt_ttl_seconds: int = 3600
    macaroon_root_key: str | None = None
    macaroon_location: str = "secureshare.local"
    openfga_api_url: str = "http://openfga:8080"
    openfga_store_id: str = "dev-store"
    openfga_authorization_model_id: str | None = None
    openfga_api_token: str | None = None
    login_rate_limit_attempts: int = 5
    login_rate_limit_window_seconds: int = 60

    @model_validator(mode="after")
    def validate_security_defaults(self) -> "Settings":
        if self.jwt_secret == DEFAULT_JWT_SECRET or self.macaroon_root_key == DEFAULT_MACAROON_ROOT_KEY:
            raise ValueError("Refusing to start with legacy public signing keys.")
        if self.environment == "dev":
            if not self.jwt_secret:
                self.jwt_secret = secrets.token_urlsafe(48)
            if not self.macaroon_root_key:
                self.macaroon_root_key = secrets.token_urlsafe(48)
        elif not self.jwt_secret or not self.macaroon_root_key:
            raise ValueError("Refusing to start non-dev environment without explicit signing keys.")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
