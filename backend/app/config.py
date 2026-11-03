"""Environment-based configuration. No secrets have defaults that are usable in production."""
from functools import lru_cache
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_INSECURE_SECRETS = {"", "change-me", "changeme", "dev-secret", "secret"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PG_", env_file=".env", extra="ignore")

    environment: Literal["development", "test", "production"] = "production"
    database_url: str = "postgresql+psycopg://pipelineguard:pipelineguard@localhost:5432/pipelineguard"
    jwt_secret: str = ""
    jwt_ttl_minutes: int = Field(default=60, ge=5, le=1440)
    cors_origins: str = ""  # comma-separated explicit origins; empty = no cross-origin access
    max_body_bytes: int = Field(default=25 * 1024 * 1024, ge=1024)
    ingest_rate_per_minute: int = Field(default=60, ge=1)
    login_max_attempts: int = Field(default=5, ge=1)
    login_lockout_seconds: int = Field(default=300, ge=1)
    suppression_max_days: int = Field(default=180, ge=1)
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""
    seed_demo_data: bool = False  # explicit opt-in; refused in production
    allow_private_webhook_targets: bool = False  # development only; refused in production
    kev_feed_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    default_policy_path: str = "policies/default.yaml"
    public_base_url: str = "http://localhost:8000"
    store_raw_reports: bool = True

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip() and o.strip() != "*"]

    @model_validator(mode="after")
    def _guard(self) -> "Settings":
        if self.environment == "production":
            if self.jwt_secret in _INSECURE_SECRETS or len(self.jwt_secret) < 32:
                raise ValueError("PG_JWT_SECRET must be set to a random value of at least 32 characters")
            if self.seed_demo_data:
                raise ValueError("PG_SEED_DEMO_DATA must not be enabled in production")
            if self.allow_private_webhook_targets:
                raise ValueError("PG_ALLOW_PRIVATE_WEBHOOK_TARGETS must not be enabled in production")
        elif len(self.jwt_secret) < 16:
            raise ValueError("PG_JWT_SECRET must be set (at least 16 characters) even in development")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
