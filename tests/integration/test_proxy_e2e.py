"""Full E2E proxy integration tests for AI Context Firewall.

Exercises the complete proxy pipeline by sending real HTTP requests through
the mitmproxy-based intercepting proxy on localhost:8099.  A ``MockUpstreamAddon``
captures forwarded (post-pipeline) requests and returns canned responses so
no real AI API is contacted.

Test scenarios:
  1. Single request with AWS key → forwarded body is redacted
  2. Request with PEM private-key content → 403 blocked
  3. Concurrent 10 requests all redacted properly
  4. Audit log has entries for both blocks and redactions

Total: 5 tests across 4 test classes
"""

from __future__ import annotations

import asyncio
import json
import socket
import time

import httpx
import pytest
from mitmproxy import http as mhttp

from acf.audit.logger import AuditLogger
from acf.config.settings import AppConfig
from acf.detection.engine import DetectionEngine
from acf.proxy.file_filter import FileFilter
from acf.proxy.intercept import InterceptAddon
from acf.proxy.server import ProxyServer
from acf.redaction.redactor import Redactor

# ── Constants ──────────────────────────────────────────────────────────

TEST_PORT = 8099
PROXY_URL = f"http://127.0.0.1:{TEST_PORT}"
AI_ENDPOINT = "http://api.openai.com/v1/chat/completions"

# Realistic PEM private-key content with >101 base64 chars between markers
# (FileFilter requires ≥101 base64 chars for the inline PEM check).
PEM_BODY = (
    "some config text\n"
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA1K7Q0v3b8z5F0a7b8c9d0e1f2g3h4i5j6k7l8m9n0o1p2q3r"
    "4s5t6u7v8w9x0yz1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z"
    "7a8b9c0d1e2f3g4h5i6j7k8l9m0n1o2p3q4r5s6t7u8v9w0x1y2z3a4b5c6d7e8f9g0h"
    "1i2j3k4l5m6n7o8p9q0r1s2t3u4v5w6x7y8z9a0b1c2d3e4f5g6h7i8j9k0l1m2n3o4p\n"
    "-----END RSA PRIVATE KEY-----\n"
    "more config text\n"
)

AWS_KEY_BODY = "config: AKIAIOSFODNN7EXAMPLE is the access key"


# ── Mock upstream addon ───────────────────────────────────────────────


class MockUpstreamAddon:
    """mitmproxy addon registered *after* ``InterceptAddon``.

    Captures the (possibly redacted) request body that the firewall pipeline
    forwards upstream, then returns a canned 200 response so no real AI API
    is contacted.
    """

    def __init__(self) -> None:
        self.captured: list[dict] = []

    def request(self, flow: mhttp.HTTPFlow) -> None:
        body = flow.request.get_content()
        self.captured.append(
            {
                "url": flow.request.pretty_url,
                "body": body.decode("utf-8", errors="replace") if body else "",
            }
        )
        flow.response = mhttp.Response.make(
            200,
            json.dumps({"choices": [{"message": {"content": "mock"}}]}).encode(),
            {"Content-Type": "application/json"},
        )

    def reset(self) -> None:
        """Clear captured requests between tests."""
        self.captured.clear()


# ── Helpers ────────────────────────────────────────────────────────────


def _wait_for_proxy(port: int, timeout: float = 10.0) -> None:
    """Block until the proxy port accepts TCP connections or *timeout* expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            sock.close()
            return
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)
    raise RuntimeError(f"proxy on port {port} did not start within {timeout}s")


# ── Module-scoped fixture ─────────────────────────────────────────────


@pytest.fixture(scope="module")
def proxy_env(tmp_path_factory: pytest.TempPathFactory):
    """Start the proxy server once for the entire test module.

    Yields a dict with:
      - ``server``: running ``ProxyServer`` instance
      - ``mock``:   ``MockUpstreamAddon`` for inspecting forwarded requests
      - ``audit``:  ``AuditLogger`` for reading audit events
    """
    tmp = tmp_path_factory.mktemp("proxy_e2e")
    config = AppConfig(
        proxy_host="127.0.0.1",
        proxy_port=TEST_PORT,
        entropy_enabled=True,
        max_body_size_mb=999,
    )

    file_filter = FileFilter()
    engine = DetectionEngine(config)
    redactor = Redactor()
    audit_logger = AuditLogger(tmp / "audit.jsonl")

    intercept = InterceptAddon(file_filter, engine, redactor, audit_logger)
    mock_upstream = MockUpstreamAddon()

    server = ProxyServer(config, intercept)
    server.start()

    # Register mock addon AFTER InterceptAddon so it sees post-pipeline bodies.
    server._master.addons.add(mock_upstream)  # type: ignore[union-attr]

    _wait_for_proxy(TEST_PORT)

    yield {
        "server": server,
        "mock": mock_upstream,
        "audit": audit_logger,
    }

    server.stop()


# ══════════════════════════════════════════════════════════════════════
# Test 1: Single request with AWS key → forwarded body is redacted
# ══════════════════════════════════════════════════════════════════════


class TestAwsKeyRedactedViaProxy:
    """Send one request containing an AWS Access Key ID through the proxy
    and verify the upstream receives a redacted body."""

    @pytest.mark.asyncio
    async def test_aws_key_redacted_in_forwarded_request(
        self, proxy_env: dict
    ) -> None:
        proxy_env["mock"].reset()

        async with httpx.AsyncClient(proxy=PROXY_URL) as client:
            resp = await client.post(AI_ENDPOINT, content=AWS_KEY_BODY)

        # Mock upstream returns 200
        assert resp.status_code == 200

        # Exactly one request forwarded
        assert len(proxy_env["mock"].captured) == 1
        captured_body = proxy_env["mock"].captured[0]["body"]

        # AWS key must be redacted
        assert "AKIAIOSFODNN7EXAMPLE" not in captured_body
        assert "[REDACTED:" in captured_body

        # Surrounding text preserved
        assert "config:" in captured_body
        assert "is the access key" in captured_body


# ══════════════════════════════════════════════════════════════════════
# Test 2: Request with PEM private-key content → 403 blocked
# ══════════════════════════════════════════════════════════════════════


class TestPemContentBlockedViaProxy:
    """Send a request containing inline PEM private-key content and verify
    the proxy returns 403 without forwarding upstream."""

    @pytest.mark.asyncio
    async def test_pem_content_returns_403(self, proxy_env: dict) -> None:
        proxy_env["mock"].reset()

        async with httpx.AsyncClient(proxy=PROXY_URL) as client:
            resp = await client.post(AI_ENDPOINT, content=PEM_BODY)

        # Firewall blocks with 403
        assert resp.status_code == 403
        assert "locked" in resp.text.lower()  # "Blocked" or "blocked"

        # Upstream must NOT have received the request
        assert len(proxy_env["mock"].captured) == 0


# ══════════════════════════════════════════════════════════════════════
# Test 3: Concurrent 10 requests all redacted properly
# ══════════════════════════════════════════════════════════════════════


class TestConcurrentRedaction:
    """Fire 10 concurrent requests, each containing an AWS key, and verify
    every one is properly redacted before reaching upstream."""

    @pytest.mark.asyncio
    async def test_concurrent_10_requests_all_redacted(
        self, proxy_env: dict
    ) -> None:
        proxy_env["mock"].reset()

        async def _send(index: int) -> httpx.Response:
            body = f"request-{index}: AKIAIOSFODNN7EXAMPLE key"
            async with httpx.AsyncClient(proxy=PROXY_URL) as client:
                return await client.post(AI_ENDPOINT, content=body)

        responses = await asyncio.gather(*[_send(i) for i in range(10)])

        # All should succeed (mock returns 200)
        assert all(r.status_code == 200 for r in responses)

        # All 10 forwarded and redacted
        assert len(proxy_env["mock"].captured) == 10
        for idx, cap in enumerate(proxy_env["mock"].captured):
            assert "AKIAIOSFODNN7EXAMPLE" not in cap["body"], (
                f"request {idx} was NOT redacted"
            )
            assert "[REDACTED:" in cap["body"], (
                f"request {idx} missing redaction marker"
            )


# ══════════════════════════════════════════════════════════════════════
# Test 4: Audit log has entries for both blocks and redactions
# ══════════════════════════════════════════════════════════════════════


class TestAuditLogEntries:
    """Verify that the JSONL audit log records both file-block (CRITICAL)
    and redaction (WARNING) events when requests pass through the proxy."""

    @pytest.mark.asyncio
    async def test_audit_log_records_blocks_and_redactions(
        self, proxy_env: dict
    ) -> None:
        audit: AuditLogger = proxy_env["audit"]

        # Snapshot existing event count (from earlier tests in this module)
        existing_count = len(audit.read_events())

        # ── Trigger a file-block (PEM content → 403) ────────────────
        async with httpx.AsyncClient(proxy=PROXY_URL) as client:
            block_resp = await client.post(AI_ENDPOINT, content=PEM_BODY)
        assert block_resp.status_code == 403

        # ── Trigger a redaction (AWS key → forwarded) ───────────────
        proxy_env["mock"].reset()
        async with httpx.AsyncClient(proxy=PROXY_URL) as client:
            redact_resp = await client.post(AI_ENDPOINT, content=AWS_KEY_BODY)
        assert redact_resp.status_code == 200

        # ── Verify new audit events ─────────────────────────────────
        all_events = audit.read_events()
        new_events = all_events[existing_count:]

        assert len(new_events) == 2, (
            f"expected 2 new audit events, got {len(new_events)}"
        )

        # First event: file block (CRITICAL)
        block_ev = new_events[0]
        assert block_ev.event_type.value == "file_block"
        assert block_ev.severity.value == "CRITICAL"
        assert len(block_ev.file_blocks) >= 1

        # Second event: redaction (WARNING)
        redact_ev = new_events[1]
        assert redact_ev.event_type.value == "redaction"
        assert redact_ev.severity.value == "WARNING"
        assert redact_ev.findings_count >= 1
        assert len(redact_ev.findings) >= 1
        # At least one finding should be the AWS key
        aws_summaries = [f for f in redact_ev.findings if f.type == "aws-access-key"]
        assert len(aws_summaries) >= 1


# ══════════════════════════════════════════════════════════════════════
# Test 5 (bonus): Safe content passes through unmodified
# ══════════════════════════════════════════════════════════════════════


class TestSafeContentPassesThrough:
    """A request with no secrets passes through the proxy unmodified,
    and no audit event is written."""

    @pytest.mark.asyncio
    async def test_safe_content_unchanged(self, proxy_env: dict) -> None:
        proxy_env["mock"].reset()
        audit: AuditLogger = proxy_env["audit"]
        existing_count = len(audit.read_events())

        safe_body = "def add(a: int, b: int) -> int:\n    return a + b\n"

        async with httpx.AsyncClient(proxy=PROXY_URL) as client:
            resp = await client.post(AI_ENDPOINT, content=safe_body)

        assert resp.status_code == 200

        # Upstream received the body unchanged
        assert len(proxy_env["mock"].captured) == 1
        assert proxy_env["mock"].captured[0]["body"] == safe_body

        # No new audit events (safe content → no block, no redaction)
        all_events = audit.read_events()
        assert len(all_events) == existing_count
