"""Application configuration via pydantic-settings.

All configuration is loaded from environment variables with the ``ACF_`` prefix.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseSettings):
    """Central configuration for the AI Context Firewall proxy.

    Every field can be overridden via an environment variable prefixed with
    ``ACF_`` (e.g. ``ACF_PROXY_PORT=9090``).
    """

    model_config = SettingsConfigDict(
        env_prefix="ACF_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        validate_default=True,
    )

    # ── Proxy ────────────────────────────────────────────────────────────
    proxy_host: str = Field(
        default="127.0.0.1",
        description="Address the mitmproxy listens on.",
    )
    proxy_port: int = Field(
        default=8080,
        ge=1,
        le=65535,
        description="Port the mitmproxy listens on.",
    )

    # ── Logging ──────────────────────────────────────────────────────────
    log_dir: str = Field(
        default="~/.acf/logs",
        description=(
            "Directory for log files.  ``~`` is expanded to the user's home"
            " directory at resolution time."
        ),
    )
    log_level: str = Field(
        default="INFO",
        description="Logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
    )

    @field_validator("log_level")
    @classmethod
    def _log_level_must_be_valid(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            msg = f"Invalid log level: {v!r}.  Choose from {allowed}"
            raise ValueError(msg)
        return upper

    # ── Feature flags ────────────────────────────────────────────────────
    file_filter_enabled: bool = Field(
        default=True,
        description="Enable the file-path/content filter middleware.",
    )
    entropy_enabled: bool = Field(
        default=True,
        description="Enable the entropy-based secret scanner.",
    )

    # ── Entropy thresholds ───────────────────────────────────────────────
    entropy_base64_threshold: float = Field(
        default=4.5,
        ge=0.0,
        le=8.0,
        description="Base64 entropy threshold (0.0 — 8.0).",
    )
    entropy_hex_threshold: float = Field(
        default=3.0,
        ge=0.0,
        le=8.0,
        description="Hex entropy threshold (0.0 — 8.0).",
    )
    entropy_min_length: int = Field(
        default=20,
        ge=1,
        description="Minimum string length before entropy analysis.",
    )

    # ── Request / response limits ────────────────────────────────────────
    max_body_size_mb: int = Field(
        default=10,
        ge=1,
        description="Maximum request/response body size in MB.",
    )

    # ── Derived helpers ──────────────────────────────────────────────────

    @property
    def resolved_log_dir(self) -> Path:
        """Return ``log_dir`` with ``~`` expanded to the user's home."""
        return Path(self.log_dir).expanduser().resolve()

    @property
    def max_body_size_bytes(self) -> int:
        """Return ``max_body_size_mb`` expressed in bytes."""
        return self.max_body_size_mb * 1024 * 1024
