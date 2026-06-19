"""Tests for ``acf scan``, ``acf config show``, and ``acf setup`` CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from acf.cli import main


# ── scan command ───────────────────────────────────────────────────────


class TestScanCommand:
    """``acf scan <target>`` runs DetectionEngine and outputs JSON."""

    def test_scan_command_exists(self) -> None:
        assert "scan" in main.commands

    def test_scan_help(self) -> None:
        result = CliRunner().invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "TARGET" in result.output

    def test_scan_clean_file(self, tmp_path: Path) -> None:
        """A file with no secrets produces an empty JSON array."""
        clean = tmp_path / "clean.py"
        clean.write_text("x = 1\nprint('hello world')\n", encoding="utf-8")

        result = CliRunner().invoke(main, ["scan", str(clean)])
        assert result.exit_code == 0
        findings = json.loads(result.output)
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_scan_file_with_aws_key(self, tmp_path: Path) -> None:
        """A file containing an AWS access key produces findings."""
        secret_file = tmp_path / "secrets.env"
        secret_file.write_text(
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
            encoding="utf-8",
        )

        result = CliRunner().invoke(main, ["scan", str(secret_file)])
        assert result.exit_code == 0
        findings = json.loads(result.output)
        assert len(findings) >= 1
        assert any(f["secret_type"] == "aws-access-key" for f in findings)

    def test_scan_file_field_present(self, tmp_path: Path) -> None:
        """Each finding includes the originating file path."""
        secret_file = tmp_path / "creds.txt"
        secret_file.write_text(
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
            encoding="utf-8",
        )

        result = CliRunner().invoke(main, ["scan", str(secret_file)])
        findings = json.loads(result.output)
        assert len(findings) >= 1
        assert all("file" in f for f in findings)

    def test_scan_directory(self, tmp_path: Path) -> None:
        """Scanning a directory recursively processes all text files."""
        (tmp_path / "a.txt").write_text("safe content\n", encoding="utf-8")
        (tmp_path / "b.txt").write_text(
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8"
        )
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "c.txt").write_text("also safe\n", encoding="utf-8")

        result = CliRunner().invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        findings = json.loads(result.output)
        assert len(findings) >= 1

    def test_scan_skips_binary_extensions(self, tmp_path: Path) -> None:
        """Binary file extensions are skipped silently."""
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        (tmp_path / "clean.txt").write_text("nothing here\n", encoding="utf-8")

        result = CliRunner().invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        findings = json.loads(result.output)
        assert isinstance(findings, list)

    def test_scan_pretty_print(self, tmp_path: Path) -> None:
        """--pretty flag produces indented JSON."""
        clean = tmp_path / "clean.py"
        clean.write_text("x = 1\n", encoding="utf-8")

        result = CliRunner().invoke(main, ["scan", "--pretty", str(clean)])
        assert result.exit_code == 0
        # Pretty-printed JSON contains newlines and indentation
        assert "\n" in result.output

    def test_scan_nonexistent_path(self) -> None:
        """Scanning a non-existent path exits with an error."""
        result = CliRunner().invoke(main, ["scan", "/nonexistent/path/xyz"])
        assert result.exit_code != 0

    def test_scan_empty_directory(self, tmp_path: Path) -> None:
        """An empty directory produces an empty JSON array."""
        result = CliRunner().invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 0
        findings = json.loads(result.output)
        assert findings == []


# ── config show command ────────────────────────────────────────────────


class TestConfigShowCommand:
    """``acf config show`` displays the current configuration."""

    def test_config_group_exists(self) -> None:
        assert "config" in main.commands

    def test_config_show_exists(self) -> None:
        config_cmd = main.commands["config"]
        assert hasattr(config_cmd, "commands")
        assert "show" in config_cmd.commands  # type: ignore[attr-defined]

    def test_config_show_output(self) -> None:
        result = CliRunner().invoke(main, ["config", "show"])
        assert result.exit_code == 0
        assert "proxy_host" in result.output
        assert "proxy_port" in result.output
        assert "log_level" in result.output
        assert "entropy_enabled" in result.output

    def test_config_show_displays_defaults(self) -> None:
        result = CliRunner().invoke(main, ["config", "show"])
        assert result.exit_code == 0
        assert "127.0.0.1" in result.output
        assert "8080" in result.output


# ── setup command ──────────────────────────────────────────────────────


class TestSetupCommand:
    """``acf setup`` generates CA cert and proxy configuration instructions."""

    def test_setup_command_exists(self) -> None:
        assert "setup" in main.commands

    def test_setup_help(self) -> None:
        result = CliRunner().invoke(main, ["setup", "--help"])
        assert result.exit_code == 0
        assert "--ci" in result.output

    def test_setup_output_contains_cert_info(self) -> None:
        result = CliRunner().invoke(main, ["setup"])
        assert result.exit_code == 0
        assert "CA Certificate" in result.output
        assert "acf-ca-cert.pem" in result.output

    def test_setup_output_contains_proxy_config(self) -> None:
        result = CliRunner().invoke(main, ["setup"])
        assert result.exit_code == 0
        assert "Proxy Configuration" in result.output
        assert "HTTPS_PROXY" in result.output

    def test_setup_ci_flag(self) -> None:
        result = CliRunner().invoke(main, ["setup", "--ci"])
        assert result.exit_code == 0
        assert "CI" in result.output
        assert "HTTPS_PROXY" in result.output

    def test_setup_contains_proxy_address(self) -> None:
        result = CliRunner().invoke(main, ["setup"])
        assert result.exit_code == 0
        assert "127.0.0.1:8080" in result.output


# ── Help integration ───────────────────────────────────────────────────


class TestNewCommandsInHelp:
    """All new commands appear in ``acf --help``."""

    def test_help_shows_scan(self) -> None:
        result = CliRunner().invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output

    def test_help_shows_config(self) -> None:
        result = CliRunner().invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "config" in result.output

    def test_help_shows_setup(self) -> None:
        result = CliRunner().invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "setup" in result.output
