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
    allowed_schemes: Union[List[str], str] = Field(default_factory=lambda: ["http"], alias="ALLOWED_SCHEMES")
    allowed_methods: Union[List[str], str] = Field(default_factory=lambda: ["GET"], alias="ALLOWED_METHODS")

    # Test Roles Credentials (OWASP Juice Shop defaults)
    user_a_email: str = Field(default="user1@juice-sh.op", alias="USER_A_EMAIL")
    user_a_password: str = Field(default="user1_password_placeholder", alias="USER_A_PASSWORD")
    user_a_token: str = Field(default="", alias="USER_A_TOKEN")

    user_b_email: str = Field(default="user2@juice-sh.op", alias="USER_B_EMAIL")
    user_b_password: str = Field(default="user2_password_placeholder", alias="USER_B_PASSWORD")
    user_b_token: str = Field(default="", alias="USER_B_TOKEN")

    admin_email: str = Field(default="admin@juice-sh.op", alias="ADMIN_EMAIL")
    admin_password: str = Field(default="admin_password_placeholder", alias="ADMIN_PASSWORD")
    admin_token: str = Field(default="", alias="ADMIN_TOKEN")

    # AI Configuration (Gemini & Claude)
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(default="claude-3-5-sonnet-20241022", alias="ANTHROPIC_MODEL")
    anthropic_max_tokens: int = Field(default=2048, alias="ANTHROPIC_MAX_TOKENS")
    anthropic_timeout: float = Field(default=30.0, alias="ANTHROPIC_TIMEOUT")

    # AI Configuration (Google Gemini Brain & Dual API Configuration)
    gemini_api_key: str = Field(default="", alias="GEMINI_API_KEY")
    gemini_model: str = Field(default="gemini-2.5-flash", alias="GEMINI_MODEL")
    # Gemini API #1: Text generation and interactive bug Q&A
    gemini_qa_api_key: str = Field(default="", alias="GEMINI_QA_API_KEY")
    gemini_qa_model: str = Field(default="", alias="GEMINI_QA_MODEL")
    # Gemini API #2: Bug impact, remediation, and secure code generation
    gemini_code_api_key: str = Field(default="", alias="GEMINI_CODE_API_KEY")
    gemini_code_model: str = Field(default="", alias="GEMINI_CODE_MODEL")

    gemini_max_tokens: int = Field(default=2048, alias="GEMINI_MAX_TOKENS")
    gemini_timeout: float = Field(default=30.0, alias="GEMINI_TIMEOUT")
    agent_max_iterations: int = Field(default=8, alias="AGENT_MAX_ITERATIONS")
    agent_max_tool_calls: int = Field(default=15, alias="AGENT_MAX_TOOL_CALLS")
    agent_temperature: float = Field(default=0.2, alias="AGENT_TEMPERATURE")

    # Storage Configuration
    database_path: str = Field(default="data/authscope.db", alias="DATABASE_PATH")

    # GitHub App user authorization. Secrets are backend-only and never serialized.
    github_client_id: str = Field(default="", alias="GITHUB_CLIENT_ID")
    github_client_secret: str = Field(default="", alias="GITHUB_CLIENT_SECRET")
    github_callback_url: str = Field(
        default="http://localhost:8000/api/github/callback",
        alias="GITHUB_CALLBACK_URL",
    )
    github_frontend_url: str = Field(default="http://localhost:3001", alias="FRONTEND_URL")
    github_app_slug: str = Field(default="", alias="GITHUB_APP_SLUG")
    github_token_encryption_key: str = Field(default="", alias="GITHUB_TOKEN_ENCRYPTION_KEY")
    github_session_cookie_secure: bool = Field(default=False, alias="GITHUB_SESSION_COOKIE_SECURE")

    # Execution Guardrails & Request Constraints
    request_timeout_seconds: float = Field(default=10.0, alias="REQUEST_TIMEOUT_SECONDS")
    assessment_timeout_seconds: float = Field(default=300.0, alias="ASSESSMENT_TIMEOUT_SECONDS")
    max_requests_per_minute: int = Field(default=120, alias="MAX_REQUESTS_PER_MINUTE")
    max_response_size_bytes: int = Field(default=1_048_576, alias="MAX_RESPONSE_SIZE_BYTES")  # 1 MB max response
    max_body_display_chars: int = Field(default=25_000, alias="MAX_BODY_DISPLAY_CHARS")
    follow_redirects: bool = Field(default=False, alias="FOLLOW_REDIRECTS")
    safe_mode: bool = Field(default=True, alias="SAFE_MODE")

    # CORS Configuration - Explicit development origins only; never wildcard with credentials
    cors_origins: Union[List[str], str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:3001",
            "http://127.0.0.1:3001",
        ],
        alias="CORS_ORIGINS",
    )

    @field_validator("allowed_hosts", "allowed_schemes", "allowed_methods", "cors_origins", mode="after")
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

    @field_validator("github_callback_url", mode="before")
    @classmethod
    def default_github_callback_when_blank(cls, value: Any) -> str:
        return str(value).strip() if value and str(value).strip() else "http://localhost:8000/api/github/callback"

    @field_validator("github_frontend_url", mode="before")
    @classmethod
    def default_github_frontend_when_blank(cls, value: Any) -> str:
        return str(value).strip().rstrip("/") if value and str(value).strip() else "http://localhost:3001"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


# Global settings singleton
settings = Settings()
