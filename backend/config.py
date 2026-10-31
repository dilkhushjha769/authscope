"""AuthScope Central Configuration Module.

Manages application settings, scope allowlists, role credentials, and Anthropic
API configuration using Pydantic Settings and environment variables.
"""

from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration class for AuthScope runtime."""

    # Environment & Logging
    authscope_env: str = Field(default="development", alias="AUTHSCOPE_ENV")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # Scope Allowlist Rules
    target_base_url: str = Field(default="http://localhost:3000", alias="TARGET_BASE_URL")
    allowed_hosts: List[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    allowed_ports: List[int] = Field(default_factory=lambda: [3000])
    allowed_schemes: List[str] = Field(default_factory=lambda: ["http", "https"])

    # Test Roles Credentials (OWASP Juice Shop defaults)
    user_a_email: str = Field(default="user1@juice-sh.op", alias="USER_A_EMAIL")
    user_a_password: str = Field(default="user1_password_placeholder", alias="USER_A_PASSWORD")
    user_b_email: str = Field(default="user2@juice-sh.op", alias="USER_B_EMAIL")
    user_b_password: str = Field(default="user2_password_placeholder", alias="USER_B_PASSWORD")
    admin_email: str = Field(default="admin@juice-sh.op", alias="ADMIN_EMAIL")
    admin_password: str = Field(default="admin_password_placeholder", alias="ADMIN_PASSWORD")

    # AI Configuration (Claude)
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(default="claude-3-5-sonnet-20241022", alias="ANTHROPIC_MODEL")
    anthropic_max_tokens: int = Field(default=2048, alias="ANTHROPIC_MAX_TOKENS")
    anthropic_timeout: float = Field(default=30.0, alias="ANTHROPIC_TIMEOUT")

    # Database
    database_path: str = Field(default="data/authscope.db", alias="DATABASE_PATH")

    # Security Guardrails
    request_timeout_seconds: float = Field(default=10.0, alias="REQUEST_TIMEOUT_SECONDS")
    max_requests_per_minute: int = Field(default=120, alias="MAX_REQUESTS_PER_MINUTE")
    follow_redirects: bool = Field(default=False, alias="FOLLOW_REDIRECTS")
    safe_mode: bool = Field(default=True, alias="SAFE_MODE")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


# Global settings singleton
settings = Settings()
