"""
Sentinel XDR Pro — Core Settings
==================================
All configuration via environment variables / .env
"""
from __future__ import annotations
import json
from functools import lru_cache
from typing import List
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8",
        case_sensitive=False, extra="ignore",
    )

    # Application
    APP_NAME: str = "SentinelXDR"
    APP_VERSION: str = "3.0.0"
    APP_ENV: str = "production"
    DEBUG: bool = False

    # Database & Cache
    DATABASE_URL: str = "postgresql+asyncpg://xdr:xdr_secure_pass@localhost:5432/xdrdb"
    REDIS_URL: str = "redis://localhost:6379/0"

    # Auth / JWT
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION_openssl_rand_hex_32"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_origins(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",")]
        return v

    # Multi-Tenant
    DEFAULT_TENANT_ID: str = "tenant_default"
    DEFAULT_TENANT_NAME: str = "Default Organization"

    # UDP
    UDP_HOST: str = "0.0.0.0"
    UDP_PORT: int = 5005

    # Detection
    SCORE_LOW_THRESHOLD: int = 30
    SCORE_MEDIUM_THRESHOLD: int = 50
    SCORE_HIGH_THRESHOLD: int = 70
    SCORE_CRITICAL_THRESHOLD: int = 90
    CORRELATION_WINDOW_SECONDS: int = 3600
    BRUTE_FORCE_THRESHOLD: int = 5
    AUTO_BLOCK_ENABLED: bool = True
    AUTO_ISOLATE_ENABLED: bool = False

    # SLA (minutes)
    SLA_CRITICAL_MINUTES: int = 15
    SLA_HIGH_MINUTES: int = 60
    SLA_MEDIUM_MINUTES: int = 240

    # Threat Intel
    ABUSEIPDB_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    OTX_API_KEY: str = ""
    MISP_URL: str = ""
    MISP_API_KEY: str = ""

    # Integrations
    SLACK_WEBHOOK_URL: str = ""
    THEHIVE_URL: str = "http://localhost:9000"
    THEHIVE_API_KEY: str = ""

    # GeoIP
    GEOIP_DB_PATH: str = "./config/GeoLite2-City.mmdb"
    GEOIP_ASN_DB_PATH: str = "./config/GeoLite2-ASN.mmdb"

    # Wazuh (active response)
    WAZUH_URL: str = ""
    WAZUH_USER: str = "wazuh"
    WAZUH_PASSWORD: str = "wazuh"
    WAZUH_VERIFY_SSL: bool = False

    # Slack channel
    SLACK_CHANNEL: str = "#soc-alerts"

    # Queue settings
    REDIS_QUEUE_LOGS: str = "xdr:queue:logs"
    REDIS_QUEUE_ALERTS: str = "xdr:queue:alerts"
    QUEUE_BATCH_SIZE: int = 100
    QUEUE_POLL_INTERVAL: float = 0.1

    # Host inventory
    HOST_INVENTORY: str = '{"dc01":"CRITICAL","web01":"HIGH","db01":"CRITICAL","prod-db-04":"CRITICAL"}'

    def get_host_criticality(self, hostname: str) -> str:
        try:
            inv = json.loads(self.HOST_INVENTORY)
            return inv.get((hostname or "").lower(), "MEDIUM")
        except Exception:
            return "MEDIUM"

    def score_to_severity(self, score: float) -> str:
        if score >= self.SCORE_CRITICAL_THRESHOLD: return "CRITICAL"
        if score >= self.SCORE_HIGH_THRESHOLD: return "HIGH"
        if score >= self.SCORE_MEDIUM_THRESHOLD: return "MEDIUM"
        return "LOW"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

settings: Settings = get_settings()
