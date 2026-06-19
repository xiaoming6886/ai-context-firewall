"""Tests for ``acf.cli``."""

from __future__ import annotations

from click.testing import CliRunner

from acf.cli import main


class TestHelpOutput:
    """``acf --help`` lists every registered sub-command."""

    def test_help_shows_start(self) -> None:
        result = CliRunner().invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "start" in result.output

    def test_help_shows_stop(self) -> None:
        result = CliRunner().invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "stop" in result.output

    def test_help_shows_status(self) -> None:
        result = CliRunner().invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "status" in result.output


class TestCommandRegistration:
    """Each expected command is registered on the CLI group."""

    def test_start_command_exists(self) -> None:
        assert "start" in main.commands

    def test_stop_command_exists(self) -> None:
        assert "stop" in main.commands

    def test_status_command_exists(self) -> None:
        assert "status" in main.commands


class TestVersion:
    """``acf --version`` prints the version string."""

    def test_version_flag(self) -> None:
        result = CliRunner().invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "acf" in result.output
        assert "0.1.0" in result.output


class TestStatusCommand:
    """``acf status`` runs without error when proxy is stopped."""

    def test_status_when_stopped(self, tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        # Redirect PID file to a non-existent temp location so status = stopped.
        monkeypatch.setattr("acf.cli._PID_FILE", tmp_path / "acf.pid")
        result = CliRunner().invoke(main, ["status"])
        assert result.exit_code == 0
        assert "stopped" in result.output.lower()


class TestStartCommand:
    """``acf start`` writes a PID file and reports success."""

    def test_start_writes_pid(self, tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        pid_file = tmp_path / "acf.pid"
        monkeypatch.setattr("acf.cli._PID_FILE", pid_file)
        monkeypatch.setattr("acf.cli._PID_DIR", tmp_path)
        result = CliRunner().invoke(main, ["start"])
        assert result.exit_code == 0
        assert "started" in result.output.lower()
        assert pid_file.exists()
        # Cleanup: remove pid so stop tests aren't affected.
        pid_file.unlink(missing_ok=True)

    def test_start_with_port_option(self, tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        pid_file = tmp_path / "acf.pid"
        monkeypatch.setattr("acf.cli._PID_FILE", pid_file)
        monkeypatch.setattr("acf.cli._PID_DIR", tmp_path)
        result = CliRunner().invoke(main, ["start", "--port", "9999"])
        assert result.exit_code == 0
        assert "9999" in result.output
        pid_file.unlink(missing_ok=True)


class TestStopCommand:
    """``acf stop`` reports error when proxy is not running."""

    def test_stop_when_not_running(self, tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr("acf.cli._PID_FILE", tmp_path / "acf.pid")
        result = CliRunner().invoke(main, ["stop"])
        assert result.exit_code != 0
        assert "not running" in result.output.lower()
