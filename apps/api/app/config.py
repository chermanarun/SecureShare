from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_JWT_SECRET = "dev-only-change-me-minimum-32-characters"
DEFAULT_MACAROON_ROOT_KEY = "dev-macaroon-root-key-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SECURESHARE_", env_file=".env", extra="ignore")

    app_name: str = "SecureShare"
    environment: Literal["dev", "test", "prod"] = "dev"
    allow_insecure_dev_defaults: bool = False
    database_url: str = "postgresql+psycopg://secureshare:secureshare@postgres:5432/secureshare"
    jwt_issuer: str = "secureshare-dev"
    jwt_audience: str = "secureshare-api"
    jwt_secret: str = Field(default=DEFAULT_JWT_SECRET)
    jwt_ttl_seconds: int = 3600
    macaroon_root_key: str = Field(default=DEFAULT_MACAROON_ROOT_KEY)
    macaroon_location: str = "secureshare.local"
    openfga_api_url: str = "http://openfga:8080"
    openfga_store_id: str = "dev-store"
    openfga_authorization_model_id: str | None = None
    login_rate_limit_attempts: int = 5
    login_rate_limit_window_seconds: int = 60

    @model_validator(mode="after")
    def validate_security_defaults(self) -> "Settings":
        using_default_jwt = self.jwt_secret == DEFAULT_JWT_SECRET
        using_default_macaroon = self.macaroon_root_key == DEFAULT_MACAROON_ROOT_KEY
        if (using_default_jwt or using_default_macaroon) and not self.allow_insecure_dev_defaults:
            raise ValueError(
                "Refusing to start with insecure default signing keys. "
                "Set explicit secrets or opt in with SECURESHARE_ALLOW_INSECURE_DEV_DEFAULTS=true for local development."
            )
        if self.environment != "dev" and (using_default_jwt or using_default_macaroon):
            raise ValueError("Refusing to start non-dev environment with insecure default signing keys.")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
