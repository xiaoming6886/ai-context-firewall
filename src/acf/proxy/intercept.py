"""mitmproxy addon for AI Context Firewall.

Intercepts HTTP flows targeting AI API endpoints, applying file-filter
blocking, secret detection, and redaction before forwarding requests
upstream.
"""

from __future__ import annotations

import logging

from mitmproxy import http

from acf.audit.logger import AuditLogger
from acf.detection.engine import DetectionEngine
from acf.models.types import FindingSummary
from acf.proxy.file_filter import FileFilter
from acf.proxy.targets import is_ai_endpoint
from acf.redaction.redactor import Redactor

logger = logging.getLogger(__name__)


class InterceptAddon:
    """mitmproxy addon implementing the AI Context Firewall request pipeline.

    Pipeline (``request`` hook):
      1. **Target filter** — skip non-AI endpoints (pass-through).
      2. **File filter** — block dangerous files with HTTP 403.
      3. **Detection engine** — scan body for secrets.
      4. **Redactor** — replace findings with ``[REDACTED:…]`` markers.
      5. **Forward** — send (possibly modified) request upstream.

    The ``response`` hook is a pass-through stub reserved for future use.

    All exceptions are caught and logged so the proxy never crashes due to
    addon failures.
    """

    def __init__(
        self,
        file_filter: FileFilter,
        detection_engine: DetectionEngine,
        redactor: Redactor,
        audit_logger: AuditLogger,
    ) -> None:
        self._file_filter = file_filter
        self._engine = detection_engine
        self._redactor = redactor
        self._audit = audit_logger

    # ── mitmproxy hooks ────────────────────────────────────────────────

    def request(self, flow: http.HTTPFlow) -> None:
        """Process an outgoing HTTP request through the firewall pipeline."""
        try:
            self._handle_request(flow)
        except Exception:
            logger.exception("intercept addon request handler failed")

    def response(self, flow: http.HTTPFlow) -> None:
        """Pass-through stub for response processing (reserved for future use)."""
        try:
            self._handle_response(flow)
        except Exception:
            logger.exception("intercept addon response handler failed")

    # ── Internal pipeline ──────────────────────────────────────────────

    def _handle_request(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url

        # 1. Target filter — skip non-AI endpoints
        if not is_ai_endpoint(url):
            return

        # Extract body text for analysis
        body_bytes = flow.request.get_content()
        body_text = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""

        # Derive client info for audit logging
        client_ip = _client_ip(flow)

        # 2. File filter — block dangerous files
        blocked, file_matches = self._file_filter.should_block(body_text)
        if blocked:
            flow.response = http.Response.make(
                403,
                b"Blocked by AI Context Firewall: sensitive file content detected",
                {
                    "Content-Type": "text/plain",
                    "X-Blocked-By": "ACF",
                },
            )
            self._audit.log_file_block(
                url=url,
                matches=file_matches,
                client_ip=client_ip,
            )
            logger.critical(
                "blocked request to %s — file filter matched %d rule(s)",
                url,
                len(file_matches),
            )
            return

        # 3. Detection engine — scan for secrets
        findings = self._engine.scan(body_text)
        if not findings:
            # Log a PASS event so operators can calculate detection rate.
            self._audit.log_pass(
                url=url,
                client_ip=client_ip,
            )
            return

        # 4. Redactor — replace findings with markers
        redacted_text = self._redactor.redact(body_text, findings)
        redacted_bytes = redacted_text.encode("utf-8")

        # Update request body and Content-Length
        flow.request.set_content(redacted_bytes)
        flow.request.headers["Content-Length"] = str(len(redacted_bytes))

        # Build finding summaries for audit
        summaries = [
            FindingSummary(
                type=f.secret_type,
                confidence=f.confidence,
                length=f.end - f.start,
            )
            for f in findings
        ]

        self._audit.log_redaction(
            url=url,
            findings=summaries,
            client_ip=client_ip,
        )
        logger.warning(
            "redacted %d finding(s) in request to %s",
            len(findings),
            url,
        )

    def _handle_response(self, flow: http.HTTPFlow) -> None:
        """Stub — no response processing yet."""
        pass


# ── Helpers ────────────────────────────────────────────────────────────


def _client_ip(flow: http.HTTPFlow) -> str:
    """Extract the client IP address from *flow*, or ``""`` on failure."""
    try:
        address = flow.client_conn.address
        if isinstance(address, tuple):
            return str(address[0])
        return str(address)
    except Exception:
        return ""
