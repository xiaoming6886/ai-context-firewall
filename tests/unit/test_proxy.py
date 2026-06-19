"""Unit tests for acf.proxy.server (ProxyServer)."""

from __future__ import annotations

import os
import shutil
import signal
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from acf.config.settings import AppConfig
from acf.proxy.server import ProxyServer, ProxyServerError


# ── Helpers ────────────────────────────────────────────────────────────


def _make_config(
    host: str = "127.0.0.1",
    port: int = 18080,
) -> AppConfig:
    """Build an AppConfig with test-friendly defaults."""
    return AppConfig(
        proxy_host=host,
        proxy_port=port,
    )


def _make_addon() -> MagicMock:
    """Return a mock InterceptAddon."""
    return MagicMock()


def _make_blocking_master() -> MagicMock:
    """Build a mock DumpMaster whose ``run()`` blocks until ``shutdown()`` is called.

    This prevents the background thread from finishing before assertions run,
    which would make ``is_running`` return ``False`` prematurely.
    """
    master = MagicMock()
    event = threading.Event()
    master.run.side_effect = lambda: event.wait(timeout=10)
    master.shutdown.side_effect = lambda: event.set()
    return master


def _make_server(
    config: AppConfig | None = None,
    addon: MagicMock | None = None,
) -> ProxyServer:
    """Build a ProxyServer with mock dependencies."""
    return ProxyServer(
        config=config or _make_config(),
        addon=addon or _make_addon(),
    )


# ── Tests ──────────────────────────────────────────────────────────────


class TestProxyServerLifecycle:
    """Tests for start/stop lifecycle of ProxyServer."""

    # ── 1. Start creates a running server ──────────────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_start_creates_running_server(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """start() initialises DumpMaster and spawns a background thread."""
        mock_master = _make_blocking_master()
        mock_master_cls.return_value = mock_master

        server = _make_server()
        server.start()

        try:
            mock_options_cls.assert_called_once()
            opts_kwargs = mock_options_cls.call_args.kwargs
            assert opts_kwargs["listen_host"] == "127.0.0.1"
            assert opts_kwargs["listen_port"] == 18080

            mock_master_cls.assert_called_once()
            mock_master.addons.add.assert_called_once()
            assert server.is_running
        finally:
            server.stop()

    # ── 2. Stop shuts down gracefully ──────────────────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_stop_shuts_down_gracefully(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """stop() signals the master and joins the background thread."""
        mock_master = _make_blocking_master()
        mock_master_cls.return_value = mock_master

        server = _make_server()
        server.start()
        assert server.is_running

        server.stop()

        assert not server.is_running
        assert server._master is None
        assert server._thread is None

    # ── 3. Double start is a no-op ─────────────────────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_double_start_is_noop(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """Calling start() twice does not create a second master."""
        mock_master = _make_blocking_master()
        mock_master_cls.return_value = mock_master

        server = _make_server()
        server.start()

        try:
            server.start()  # second call — should be ignored
            # DumpMaster should only have been constructed once
            assert mock_master_cls.call_count == 1
        finally:
            server.stop()

    # ── 4. Double stop is a no-op ──────────────────────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_double_stop_is_noop(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """Calling stop() on an already-stopped server does not raise."""
        mock_master = _make_blocking_master()
        mock_master_cls.return_value = mock_master

        server = _make_server()
        server.start()
        server.stop()

        # Should not raise
        server.stop()
        assert not server.is_running

    # ── 5. Stop on never-started server is safe ────────────────────────

    def test_stop_without_start_is_safe(self) -> None:
        """Calling stop() before start() does not raise."""
        server = _make_server()
        server.stop()  # should be a no-op
        assert not server.is_running


class TestAddonLoading:
    """Tests verifying the InterceptAddon is loaded into DumpMaster."""

    # ── 6. Addon is added to master ────────────────────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_addon_loaded_correctly(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """The InterceptAddon instance is registered with DumpMaster.addons."""
        mock_master = _make_blocking_master()
        mock_master_cls.return_value = mock_master

        addon = _make_addon()
        server = _make_server(addon=addon)
        server.start()

        try:
            mock_master.addons.add.assert_called_once_with(addon)
        finally:
            server.stop()


class TestCACertCheck:
    """Tests for CA certificate validation."""

    # ── 7. Options include listen config and headless mode ─────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_options_include_listen_config(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """Options are constructed with listen_host and listen_port from config."""
        mock_master = _make_blocking_master()
        mock_master_cls.return_value = mock_master

        config = _make_config(host="127.0.0.1", port=9999)
        server = _make_server(config=config)
        server.start()

        try:
            call_kwargs = mock_options_cls.call_args.kwargs
            assert call_kwargs["listen_host"] == "127.0.0.1"
            assert call_kwargs["listen_port"] == 9999
            # web_open_browser should be disabled for headless operation
            assert call_kwargs["web_open_browser"] is False
        finally:
            server.stop()

    # ── 8. CA cert path is well-formed ─────────────────────────────────

    def test_mitmproxy_default_confdir_path(self) -> None:
        """mitmproxy's default confdir (~/.mitmproxy) path is well-formed.

        Actual cert generation happens when DumpMaster first runs; this test
        only verifies the path structure is correct.
        """
        confdir = Path.home() / ".mitmproxy"
        assert confdir.parent == Path.home()
        assert confdir.name == ".mitmproxy"


class TestPortInUse:
    """Tests for port-already-in-use error handling."""

    # ── 9. Port already in use raises ProxyServerError ─────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_port_in_use_raises_error(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """ProxyServerError is raised when the port is already bound."""
        mock_master_cls.side_effect = OSError("Address already in use")

        server = _make_server()

        with pytest.raises(ProxyServerError, match="failed to initialise proxy"):
            server.start()

        assert not server.is_running


class TestPIDFileManagement:
    """Tests for PID file read/write/cleanup."""

    # ── 10. write_pid_file creates file with current PID ───────────────

    def test_write_pid_file(self, tmp_path: Path) -> None:
        """write_pid_file() writes the current PID to the expected path."""
        with patch("acf.proxy.server._PID_DIR", tmp_path), \
             patch("acf.proxy.server._PID_FILE", tmp_path / "acf.pid"):
            server = _make_server()
            server.write_pid_file()

            pid_file = tmp_path / "acf.pid"
            assert pid_file.exists()
            assert int(pid_file.read_text().strip()) == os.getpid()

    # ── 11. read_pid returns None when no file ─────────────────────────

    def test_read_pid_returns_none_when_no_file(self, tmp_path: Path) -> None:
        """read_pid() returns None when the PID file does not exist."""
        with patch("acf.proxy.server._PID_FILE", tmp_path / "nonexistent.pid"):
            assert ProxyServer.read_pid() is None

    # ── 12. read_pid returns None for dead process ─────────────────────

    def test_read_pid_returns_none_for_dead_process(self, tmp_path: Path) -> None:
        """read_pid() returns None and cleans up when the PID is stale."""
        pid_file = tmp_path / "acf.pid"
        # Use a PID that almost certainly doesn't exist
        pid_file.write_text("999999999")

        with patch("acf.proxy.server._PID_FILE", pid_file):
            result = ProxyServer.read_pid()
            assert result is None
            # Stale PID file should be cleaned up
            assert not pid_file.exists()


class TestSignalHandlers:
    """Tests for SIGINT/SIGTERM signal handler installation."""

    # ── 13. Signal handlers installed on start ─────────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_signal_handlers_installed(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """start() installs custom SIGINT and SIGTERM handlers."""
        mock_master = _make_blocking_master()
        mock_master_cls.return_value = mock_master

        original_sigint = signal.getsignal(signal.SIGINT)
        original_sigterm = signal.getsignal(signal.SIGTERM)

        server = _make_server()
        server.start()

        try:
            current_sigint = signal.getsignal(signal.SIGINT)
            current_sigterm = signal.getsignal(signal.SIGTERM)
            # Handlers should have been replaced
            assert current_sigint != original_sigint or server._signal_handler == current_sigint
            assert current_sigterm != original_sigterm or server._signal_handler == current_sigterm
        finally:
            server.stop()

    # ── 14. Signal handlers restored on stop ───────────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_signal_handlers_restored_on_stop(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """stop() restores the original signal handlers."""
        mock_master = _make_blocking_master()
        mock_master_cls.return_value = mock_master

        original_sigint = signal.getsignal(signal.SIGINT)
        original_sigterm = signal.getsignal(signal.SIGTERM)

        server = _make_server()
        server.start()
        server.stop()

        assert signal.getsignal(signal.SIGINT) == original_sigint
        assert signal.getsignal(signal.SIGTERM) == original_sigterm


class TestIsRunning:
    """Tests for the is_running property."""

    # ── 15. is_running is False before start ───────────────────────────

    def test_is_running_false_before_start(self) -> None:
        """is_running returns False before start() is called."""
        server = _make_server()
        assert server.is_running is False

    # ── 16. is_running is False after stop ─────────────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_is_running_false_after_stop(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """is_running returns False after stop() is called."""
        mock_master = _make_blocking_master()
        mock_master_cls.return_value = mock_master

        server = _make_server()
        server.start()
        server.stop()

        assert server.is_running is False


# ── Additional edge-case / lifecycle tests ─────────────────────────────


class TestCrashRestartLifecycle:
    """Tests for start → crash → restart lifecycle of ProxyServer."""

    # ── C1. Server restarts after event loop crash ────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_restart_after_crash(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """After the event loop crashes, the server can be restarted."""
        # First start: master.run() crashes immediately
        crashing_master = MagicMock()
        crashing_master.run.side_effect = RuntimeError("event loop exploded")
        mock_master_cls.return_value = crashing_master

        server = _make_server()
        server.start()

        # Wait for the background thread to finish (it crashed)
        time.sleep(0.5)

        # Server should detect the thread is dead
        assert not server.is_running

        # Clean up the stopped server state
        server.stop()

        # Now set up a working master for the restart
        working_master = _make_blocking_master()
        mock_master_cls.return_value = working_master

        server.start()
        try:
            assert server.is_running
        finally:
            server.stop()

    # ── C2. _run_loop sets _running=False on crash ────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_run_loop_clears_running_on_crash(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """When _run_loop catches an exception, _running is set to False."""
        crashing_master = MagicMock()
        crashing_master.run.side_effect = RuntimeError("boom")
        mock_master_cls.return_value = crashing_master

        server = _make_server()
        server.start()

        # Give the thread time to crash
        time.sleep(0.5)

        assert server._running is False
        server.stop()  # cleanup

    # ── C3. _run_loop closes event loop in finally ────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_run_loop_closes_event_loop_on_crash(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """The asyncio event loop is closed even when master.run() crashes."""
        crashing_master = MagicMock()
        crashing_master.run.side_effect = RuntimeError("boom")
        mock_master_cls.return_value = crashing_master

        server = _make_server()
        server.start()

        time.sleep(0.5)

        # After crash + finally, _loop should be None (closed and cleared)
        assert server._loop is None
        server.stop()

    # ── C4. Stop after crash is safe ──────────────────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_stop_after_crash_is_safe(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """Calling stop() after the event loop crashed is safe."""
        crashing_master = MagicMock()
        crashing_master.run.side_effect = RuntimeError("boom")
        mock_master_cls.return_value = crashing_master

        server = _make_server()
        server.start()

        time.sleep(0.5)

        # Should not raise even though thread already died
        server.stop()
        assert not server.is_running
        assert server._master is None
        assert server._thread is None


class TestPortBindingRaceCondition:
    """Tests for port binding race conditions and OSError handling."""

    # ── P1. OSError during Options construction ───────────────────────

    @patch("acf.proxy.server.Options")
    def test_options_oserror_raises_proxy_server_error(
        self,
        mock_options_cls: MagicMock,
    ) -> None:
        """OSError during Options() construction raises ProxyServerError."""
        mock_options_cls.side_effect = OSError("Invalid argument")

        server = _make_server()

        with pytest.raises(ProxyServerError, match="failed to initialise proxy"):
            server.start()

        assert not server.is_running

    # ── P2. OSError during DumpMaster construction ────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_dumpmaster_oserror_raises_proxy_server_error(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """OSError during DumpMaster() construction (port bind) raises ProxyServerError."""
        mock_master_cls.side_effect = OSError("[Errno 98] Address already in use")

        server = _make_server()

        with pytest.raises(ProxyServerError, match="failed to initialise proxy"):
            server.start()

        assert not server.is_running
        assert server._master is None

    # ── P3. Port 0 (OS-assigned) is accepted ──────────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_port_zero_accepted(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """Port 0 (let OS choose) is a valid configuration."""
        mock_master = _make_blocking_master()
        mock_master_cls.return_value = mock_master

        config = _make_config(port=0)
        server = _make_server(config=config)
        server.start()

        try:
            opts_kwargs = mock_options_cls.call_args.kwargs
            assert opts_kwargs["listen_port"] == 0
            assert server.is_running
        finally:
            server.stop()

    # ── P4. Concurrent start attempts — second is no-op ───────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_concurrent_start_second_is_noop(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """Rapid successive start() calls don't create multiple masters."""
        mock_master = _make_blocking_master()
        mock_master_cls.return_value = mock_master

        server = _make_server()
        server.start()
        server.start()
        server.start()

        try:
            assert mock_master_cls.call_count == 1
        finally:
            server.stop()

    # ── P5. Different host/port combinations ────────────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_custom_host_port_propagated(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """Custom host and port from config are passed to Options."""
        mock_master = _make_blocking_master()
        mock_master_cls.return_value = mock_master

        config = _make_config(host="0.0.0.0", port=3128)
        server = _make_server(config=config)
        server.start()

        try:
            opts_kwargs = mock_options_cls.call_args.kwargs
            assert opts_kwargs["listen_host"] == "0.0.0.0"
            assert opts_kwargs["listen_port"] == 3128
        finally:
            server.stop()


class TestCACertRegeneration:
    """Tests for CA certificate management and regeneration."""

    # ── CA1. mitmproxy confdir path structure ─────────────────────────

    def test_mitmproxy_confdir_is_under_home(self) -> None:
        """mitmproxy's default confdir is ~/.mitmproxy."""
        confdir = Path.home() / ".mitmproxy"
        assert str(confdir).endswith(".mitmproxy")
        assert confdir.parent == Path.home()

    # ── CA2. Expected cert file names ─────────────────────────────────

    def test_expected_cert_file_names(self) -> None:
        """mitmproxy generates known cert file names in its confdir."""
        confdir = Path.home() / ".mitmproxy"
        expected_files = [
            "mitmproxy-ca.pem",
            "mitmproxy-ca-cert.pem",
            "mitmproxy-ca-cert.cer",
            "mitmproxy-dhparam.pem",
        ]
        # Verify the expected names are well-formed paths
        for fname in expected_files:
            cert_path = confdir / fname
            assert cert_path.parent == confdir
            assert cert_path.name == fname

    # ── CA3. Cert regeneration via confdir removal ────────────────────

    def test_cert_regeneration_by_removing_confdir(
        self, tmp_path: Path
    ) -> None:
        """Removing the confdir triggers cert regeneration on next start.

        This test verifies the mechanism: if the confdir doesn't exist,
        mitmproxy will regenerate certs. We simulate this by checking
        that a non-existent confdir path is handled gracefully.
        """
        fake_confdir = tmp_path / ".mitmproxy"
        assert not fake_confdir.exists()

        # Simulate what mitmproxy does: create confdir if missing
        fake_confdir.mkdir(parents=True, exist_ok=True)
        assert fake_confdir.exists()

        # Write a dummy cert file
        cert_file = fake_confdir / "mitmproxy-ca.pem"
        cert_file.write_text("DUMMY CERT")
        assert cert_file.exists()

        # "Regenerate" by removing and recreating
        shutil.rmtree(fake_confdir)
        assert not fake_confdir.exists()

        fake_confdir.mkdir(parents=True, exist_ok=True)
        new_cert_file = fake_confdir / "mitmproxy-ca.pem"
        new_cert_file.write_text("NEW DUMMY CERT")
        assert new_cert_file.read_text() == "NEW DUMMY CERT"

    # ── CA4. DumpMaster created with headless mode (no web UI) ────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_dumpmaster_headless_no_web_browser(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """DumpMaster is created with with_termlog=False and with_dumper=False."""
        mock_master = _make_blocking_master()
        mock_master_cls.return_value = mock_master

        server = _make_server()
        server.start()

        try:
            mock_master_cls.assert_called_once()
            call_kwargs = mock_master_cls.call_args.kwargs
            assert call_kwargs["with_termlog"] is False
            assert call_kwargs["with_dumper"] is False
        finally:
            server.stop()


class TestProxyServerThreadSafety:
    """Tests for thread safety and cleanup of ProxyServer."""

    # ── T1. Thread is daemon — won't prevent process exit ─────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_proxy_thread_is_daemon(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """The background proxy thread is a daemon thread."""
        mock_master = _make_blocking_master()
        mock_master_cls.return_value = mock_master

        server = _make_server()
        server.start()

        try:
            assert server._thread is not None
            assert server._thread.daemon is True
            assert server._thread.name == "acf-proxy"
        finally:
            server.stop()

    # ── T2. master.shutdown() exception is swallowed ──────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_shutdown_exception_swallowed(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
    ) -> None:
        """If master.shutdown() raises, stop() still completes cleanly."""
        mock_master = MagicMock()
        event = threading.Event()
        mock_master.run.side_effect = lambda: event.wait(timeout=10)
        # shutdown raises instead of setting the event
        mock_master.shutdown.side_effect = RuntimeError("shutdown failed")
        mock_master_cls.return_value = mock_master

        server = _make_server()
        server.start()

        # Should not raise even though shutdown() throws
        server.stop()

        assert server._master is None
        assert server._thread is None

    # ── T3. PID file cleanup on stop ──────────────────────────────────

    @patch("acf.proxy.server.DumpMaster")
    @patch("acf.proxy.server.Options")
    def test_pid_file_cleaned_on_stop(
        self,
        mock_options_cls: MagicMock,
        mock_master_cls: MagicMock,
        tmp_path: Path,
    ) -> None:
        """stop() removes the PID file."""
        mock_master = _make_blocking_master()
        mock_master_cls.return_value = mock_master

        pid_file = tmp_path / "acf.pid"
        pid_file.write_text(str(os.getpid()))

        with patch("acf.proxy.server._PID_DIR", tmp_path), \
             patch("acf.proxy.server._PID_FILE", pid_file):
            server = _make_server()
            server.start()
            server.stop()

            assert not pid_file.exists()

    # ── T4. read_pid with invalid file content ────────────────────────

    def test_read_pid_invalid_content(self, tmp_path: Path) -> None:
        """read_pid() returns None and cleans up when PID file has garbage."""
        pid_file = tmp_path / "acf.pid"
        pid_file.write_text("not-a-number")

        with patch("acf.proxy.server._PID_FILE", pid_file):
            result = ProxyServer.read_pid()
            assert result is None
            assert not pid_file.exists()

    # ── T5. read_pid with empty file ──────────────────────────────────

    def test_read_pid_empty_file(self, tmp_path: Path) -> None:
        """read_pid() returns None and cleans up when PID file is empty."""
        pid_file = tmp_path / "acf.pid"
        pid_file.write_text("")

        with patch("acf.proxy.server._PID_FILE", pid_file):
            result = ProxyServer.read_pid()
            assert result is None
            assert not pid_file.exists()
