"""Tests for ``acf.config.settings``."""

from __future__ import annotations

from pathlib import Path

import pydantic
import pytest

from acf.config.settings import AppConfig


class TestDefaults:
    """Default values match the specification."""

    def test_default_port_is_8080(self) -> None:
        cfg = AppConfig()
        assert cfg.proxy_port == 8080

    def test_default_entropy_thresholds(self) -> None:
        cfg = AppConfig()
        assert cfg.entropy_base64_threshold == 4.5
        assert cfg.entropy_hex_threshold == 3.0

    def test_default_max_body_size_mb(self) -> None:
        cfg = AppConfig()
        assert cfg.max_body_size_mb == 10

    def test_default_log_dir_is_tilde_path(self) -> None:
        cfg = AppConfig()
        assert cfg.log_dir == "~/.acf/logs"


class TestEnvVarOverride:
    """Environment variables with the ``ACF_`` prefix override defaults."""

    def test_port_overridden_by_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACF_PROXY_PORT", "9999")
        cfg = AppConfig()
        assert cfg.proxy_port == 9999

    def test_threshold_overridden_by_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACF_ENTROPY_BASE64_THRESHOLD", "6.0")
        cfg = AppConfig()
        assert cfg.entropy_base64_threshold == 6.0

    def test_bool_parsing_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACF_FILE_FILTER_ENABLED", "false")
        cfg = AppConfig()
        assert cfg.file_filter_enabled is False

    def test_bool_parsing_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ACF_ENTROPY_ENABLED", "true")
        cfg = AppConfig()
        assert cfg.entropy_enabled is True

    def test_env_prefix_isolation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Non-ACF_ prefixed variables are ignored."""
        monkeypatch.setenv("PROXY_PORT", "1234")
        cfg = AppConfig()
        assert cfg.proxy_port == 8080


class TestValidation:
    """Field-level validators enforce constraints."""

    @pytest.mark.parametrize("port", [0, 65536, -1, 99999])
    def test_port_out_of_range_raises(self, port: int) -> None:
        with pytest.raises(pydantic.ValidationError):
            AppConfig(proxy_port=port)

    @pytest.mark.parametrize("threshold", [-0.1, 8.1, 100.0])
    def test_entropy_base64_out_of_range(self, threshold: float) -> None:
        with pytest.raises(pydantic.ValidationError):
            AppConfig(entropy_base64_threshold=threshold)

    @pytest.mark.parametrize("threshold", [-1.0, 8.01, 999.0])
    def test_entropy_hex_out_of_range(self, threshold: float) -> None:
        with pytest.raises(pydantic.ValidationError):
            AppConfig(entropy_hex_threshold=threshold)

    @pytest.mark.parametrize("bad_level", ["debug", "warn", "error ", "", "TRACE"])
    def test_invalid_log_level_raises(self, bad_level: str) -> None:
        with pytest.raises(pydantic.ValidationError):
            AppConfig(log_level=bad_level)

    def test_entropy_min_length_must_be_positive(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            AppConfig(entropy_min_length=0)
        with pytest.raises(pydantic.ValidationError):
            AppConfig(entropy_min_length=-5)

    @pytest.mark.parametrize("mb", [0, -1])
    def test_max_body_size_must_be_positive(self, mb: int) -> None:
        with pytest.raises(pydantic.ValidationError):
            AppConfig(max_body_size_mb=mb)


class TestDerivedProperties:
    """Computed properties produce correct values."""

    def test_resolved_log_dir_expands_home(self) -> None:
        cfg = AppConfig(log_dir="~/test_acf_logs")
        resolved = cfg.resolved_log_dir
        assert resolved == Path.home() / "test_acf_logs"
        assert resolved.is_absolute()

    def test_max_body_size_bytes(self) -> None:
        cfg = AppConfig(max_body_size_mb=10)
        assert cfg.max_body_size_bytes == 10 * 1024 * 1024

    def test_resolved_log_dir_absolute_when_already_absolute(self) -> None:
        cfg = AppConfig(log_dir="/var/log/acf")
        assert cfg.resolved_log_dir == Path("/var/log/acf")


class TestEnvFile:
    """``.env`` file support (integration-light)."""

    def test_load_from_env_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text("ACF_PROXY_PORT=4321\nACF_LOG_LEVEL=DEBUG\n")
        # pydantic-settings resolves env_file relative to cwd / module dir,
        # so we pass the path explicitly for deterministic results.
        cfg2 = AppConfig(_env_file=str(env_file))
        assert cfg2.proxy_port == 4321
        assert cfg2.log_level == "DEBUG"
