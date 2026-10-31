"""AuthScope Central Configuration Module.

Manages application settings, scope allowlists, role credentials, and Anthropic
API configuration using Pydantic Settings and environment variables.
"""

from typing import List, Union, Any
import json
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration class for AuthScope runtime."""

    # Environment & Logging
    authscope_env: str = Field(default="development", alias="AUTHSCOPE_ENV")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # Scope Allowlist Rules
    target_base_url: str = Field(default="http://localhost:3000", alias="TARGET_BASE_URL")
    allowed_hosts: Union[List[str], str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"], alias="ALLOWED_HOSTS")
    allowed_ports: Union[List[int], int, str] = Field(default_factory=lambda: [3000], alias="ALLOWED_PORTS")
    allowed_schemes: Union[List[str], str] = Field(default_factory=lambda: ["http", "https"], alias="ALLOWED_SCHEMES")

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

    # Database
    database_path: str = Field(default="data/authscope.db", alias="DATABASE_PATH")

    # Security Guardrails
    request_timeout_seconds: float = Field(default=10.0, alias="REQUEST_TIMEOUT_SECONDS")
    max_requests_per_minute: int = Field(default=120, alias="MAX_REQUESTS_PER_MINUTE")
    follow_redirects: bool = Field(default=False, alias="FOLLOW_REDIRECTS")
    safe_mode: bool = Field(default=True, alias="SAFE_MODE")

    @field_validator("allowed_hosts", "allowed_schemes", mode="after")
    @classmethod
    def parse_string_list(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @field_validator("allowed_ports", mode="after")
    @classmethod
    def parse_int_list(cls, v: Any) -> List[int]:
        if isinstance(v, int):
            return [v]
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                try:
                    return [int(x) for x in json.loads(v)]
                except Exception:
                    pass
            return [int(item.strip()) for item in v.split(",") if item.strip()]
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


# Global settings singleton
settings = Settings()
