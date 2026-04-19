from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SECURESHARE_", env_file=".env", extra="ignore")

    app_name: str = "SecureShare"
    environment: str = "dev"
    database_url: str = "postgresql+psycopg://secureshare:secureshare@postgres:5432/secureshare"
    jwt_issuer: str = "secureshare-dev"
    jwt_audience: str = "secureshare-api"
    jwt_secret: str = Field(default="dev-only-change-me-minimum-32-characters")
    jwt_ttl_seconds: int = 3600
    macaroon_root_key: str = Field(default="dev-macaroon-root-key-change-me")
    macaroon_location: str = "secureshare.local"
    openfga_api_url: str = "http://openfga:8080"
    openfga_store_id: str = "dev-store"
    openfga_authorization_model_id: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()

