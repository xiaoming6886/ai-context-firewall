"""ProxyServer wrapping mitmproxy for AI Context Firewall.

Provides a programmatic interface to start/stop the mitmproxy-based
intercepting proxy, with signal handling, PID file management for
daemon mode, and the InterceptAddon pre-loaded.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from acf.proxy.intercept import InterceptAddon

if TYPE_CHECKING:
    from acf.config.settings import AppConfig

logger = logging.getLogger(__name__)

_PID_DIR = Path.home() / ".acf"
_PID_FILE = _PID_DIR / "acf.pid"


class ProxyServerError(Exception):
    """Raised when the proxy server fails to start or encounters a fatal error."""


class ProxyServer:
    """Manages the mitmproxy lifecycle for the AI Context Firewall.

    Responsibilities:
      - Construct a ``DumpMaster`` with the ``InterceptAddon`` loaded.
      - Bind to ``config.proxy_host:config.proxy_port``.
      - Run the event loop in a background thread.
      - Graceful shutdown via ``stop()`` or OS signals.
      - PID file management for daemon mode.

    Usage::

        server = ProxyServer(config, addon)
        server.start()       # blocks until the proxy is listening
        # ... proxy is running in a background thread ...
        server.stop()        # graceful shutdown
    """

    def __init__(
        self,
        config: AppConfig,
        addon: InterceptAddon,
        daemon: bool = False,
    ) -> None:
        self._config = config
        self._addon = addon
        self._daemon = daemon
        self._master: DumpMaster | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._original_sigint = signal.getsignal(signal.SIGINT)
        self._original_sigterm = signal.getsignal(signal.SIGTERM)

    # ── Public API ──────────────────────────────────────────────────────

    def start(self) -> None:
        """Launch mitmproxy with InterceptAddon loaded, bound to configured host:port.

        Spawns a background thread running the asyncio event loop that drives
        the ``DumpMaster``.  Installs signal handlers for SIGINT/SIGTERM so
        the proxy shuts down cleanly on Ctrl-C or ``kill``.

        Raises:
            ProxyServerError: If the proxy fails to bind or start.
        """
        if self._running:
            logger.warning("proxy server is already running")
            return

        host = self._config.proxy_host
        port = self._config.proxy_port

        logger.info("starting proxy server on %s:%d", host, port)

        try:
            opts = Options(
                listen_host=host,
                listen_port=port,
                # Disable the interactive web UI — we run headless.
                web_open_browser=False,
            )
            self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            self._master.addons.add(self._addon)
        except OSError as exc:
            msg = f"failed to initialise proxy on {host}:{port}: {exc}"
            logger.error(msg)
            raise ProxyServerError(msg) from exc

        self._running = True
        self._install_signal_handlers()

        self._thread = threading.Thread(
            target=self._run_loop,
            name="acf-proxy",
            daemon=True,
        )
        self._thread.start()

        logger.info("proxy server started on %s:%d (PID %d)", host, port, os.getpid())

    def stop(self) -> None:
        """Gracefully shut down the proxy server.

        Signals the ``DumpMaster`` to stop, waits for the background thread
        to finish, removes the PID file, and restores original signal handlers.
        """
        if not self._running:
            logger.debug("proxy server is not running; stop() is a no-op")
            return

        logger.info("stopping proxy server")
        self._running = False

        # DumpMaster.shutdown() is thread-safe and signals the master to stop.
        if self._master is not None:
            try:
                self._master.shutdown()
            except Exception:
                logger.debug("master.shutdown() raised; ignoring", exc_info=True)

        if self._thread is not None:
            self._thread.join(timeout=10)
            if self._thread.is_alive():
                logger.warning("proxy thread did not exit within 10 s")
            self._thread = None

        self._master = None
        self._loop = None
        self._restore_signal_handlers()
        self._remove_pid_file()

        logger.info("proxy server stopped")

    @property
    def is_running(self) -> bool:
        """Return ``True`` if the proxy server is currently listening."""
        return self._running and self._thread is not None and self._thread.is_alive()

    # ── Daemon I/O redirection ─────────────────────────────────────────

    def redirect_stdio(self, log_path: Path | None = None) -> None:
        """Redirect ``stdout`` and ``stderr`` to a log file.

        Called from the child process after ``--daemon`` spawns it.
        The file is opened in append mode so multiple runs accumulate.
        """
        if not self._daemon:
            return

        if log_path is None:
            log_path = _PID_DIR / "acf-daemon.log"
        _PID_DIR.mkdir(parents=True, exist_ok=True)

        # Flush any buffered output before redirecting.
        sys.stdout.flush()
        sys.stderr.flush()

        log_fh = open(log_path, "a", encoding="utf-8")  # noqa: SIM115 — intentionally kept open
        os.dup2(log_fh.fileno(), sys.stdout.fileno())
        os.dup2(log_fh.fileno(), sys.stderr.fileno())
        # Keep stderr pointing at the same fd so both go to the same file.
        log_fh.close()

        logger.info("daemon stdio redirected to %s", log_path)

    # ── PID file management ─────────────────────────────────────────────

    def write_pid_file(self) -> None:
        """Write the current process PID to ``~/.acf/acf.pid``.

        Creates the directory if it does not exist.  Intended for daemon mode.
        """
        _PID_DIR.mkdir(parents=True, exist_ok=True)
        _PID_FILE.write_text(str(os.getpid()))
        logger.debug("wrote PID %d to %s", os.getpid(), _PID_FILE)

    @staticmethod
    def _remove_pid_file() -> None:
        """Delete the PID file (idempotent)."""
        _PID_FILE.unlink(missing_ok=True)

    @staticmethod
    def read_pid() -> int | None:
        """Return the stored PID if the process is alive, else ``None``."""
        if not _PID_FILE.exists():
            return None
        try:
            pid = int(_PID_FILE.read_text().strip())
            os.kill(pid, 0)  # signal 0 = existence check
            return pid
        except (ValueError, ProcessLookupError, PermissionError, OSError):
            _PID_FILE.unlink(missing_ok=True)
            return None

    # ── Signal handlers ─────────────────────────────────────────────────

    def _install_signal_handlers(self) -> None:
        """Install SIGINT/SIGTERM handlers that trigger graceful shutdown."""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _restore_signal_handlers(self) -> None:
        """Restore the original signal handlers saved at construction time."""
        signal.signal(signal.SIGINT, self._original_sigint)
        signal.signal(signal.SIGTERM, self._original_sigterm)

    def _signal_handler(self, signum: int, _frame: object) -> None:
        """Handle SIGINT/SIGTERM by initiating graceful shutdown."""
        sig_name = signal.Signals(signum).name
        logger.info("received %s — initiating graceful shutdown", sig_name)
        self.stop()

    # ── Internal ────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        """Run the ``DumpMaster`` event loop in a background thread."""
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            assert self._master is not None
            self._master.run()
        except Exception:
            logger.exception("proxy event loop crashed")
            self._running = False
        finally:
            if self._loop is not None:
                self._loop.close()
                self._loop = None

    # ── WebSocket handling stub ──────────────────────────────────────────
    #
    # CAPABILITY GAP (S4): The current InterceptAddon processes only HTTP
    # request/response flows via the ``request`` and ``response`` hooks.
    # WebSocket messages (``websocket_message`` hook) are NOT intercepted,
    # meaning secrets transmitted over WebSocket connections to AI providers
    # (e.g. streaming chat completions via WS) will pass through uninspected.
    #
    # To close this gap, InterceptAddon needs:
    #   1. A ``websocket_message(flow)`` hook implementation.
    #   2. Extraction of text content from ``flow.websocket_message``.
    #   3. Running the same detection + redaction pipeline on WS payloads.
    #   4. Optionally blocking individual WS frames (vs. killing the conn).
    #
    # This is tracked as milestone S4 in the project roadmap.
    # ─────────────────────────────────────────────────────────────────────
