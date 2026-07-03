"""Central configuration, loaded from environment / .env."""
from __future__ import annotations

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SOC_", env_file=".env", extra="ignore")

    # Data stores (conventional env names; SOC_-prefixed also accepted).
    database_url: str | None = Field(default=None, validation_alias=AliasChoices("DATABASE_URL", "SOC_DATABASE_URL"))
    redis_url: str | None = Field(default=None, validation_alias=AliasChoices("REDIS_URL", "SOC_REDIS_URL"))

    # Auth
    jwt_secret: str = "change-me-in-production-please-32chars-min"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 720

    # CORS — allowed browser origins (comma-separated) + optional regex.
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    cors_origin_regex: str | None = None  # e.g. https://.*\.vercel\.app for preview + prod

    # AI — fast, cheap summarization model (Haiku 4.5). Override with SOC_AI_MODEL.
    ai_model: str = "claude-haiku-4-5"
    anthropic_api_key: str | None = None  # falls back to ANTHROPIC_API_KEY env

    # Live NVD (NIST) CVE feed
    nvd_enabled: bool = True
    nvd_api_key: str | None = None  # optional — raises rate limits (falls back to NVD_API_KEY env)
    nvd_refresh_hours: float = 6.0

    # Telemetry
    scan_enabled: bool = False          # attempt real Nmap scans of scan_target
    scan_target: str = "192.168.1.0/24"
    sniff_enabled: bool = False         # attempt real Scapy packet capture
    broadcast_interval: float = 1.0     # seconds between packet broadcasts

    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
