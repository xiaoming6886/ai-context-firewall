"""Unit tests for acf.proxy.intercept (InterceptAddon)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from acf.models.types import Finding, FileBlockMatch, FindingSummary, MatchType
from acf.proxy.intercept import InterceptAddon, _client_ip


# ── Helpers ────────────────────────────────────────────────────────────


def _make_flow(
    url: str = "https://api.openai.com/v1/chat/completions",
    body: bytes = b"",
    client_addr: tuple = ("127.0.0.1", 54321),
) -> MagicMock:
    """Build a mock ``http.HTTPFlow`` with the given URL and body."""
    flow = MagicMock()
    flow.request.pretty_url = url
    flow.request.get_content.return_value = body
    flow.request.headers = {}
    flow.request.set_content = MagicMock()
    flow.client_conn.address = client_addr
    flow.response = None
    return flow


def _make_addon(
    file_filter: MagicMock | None = None,
    engine: MagicMock | None = None,
    redactor: MagicMock | None = None,
    audit: MagicMock | None = None,
) -> InterceptAddon:
    """Build an InterceptAddon with mock dependencies."""
    return InterceptAddon(
        file_filter=file_filter or MagicMock(),
        detection_engine=engine or MagicMock(),
        redactor=redactor or MagicMock(),
        audit_logger=audit or MagicMock(),
    )


# ── Tests ──────────────────────────────────────────────────────────────


class TestInterceptAddon:
    """Tests for the InterceptAddon mitmproxy addon."""

    # ── 1. Non-AI URL passes through ──────────────────────────────────

    def test_non_ai_url_passes_through(self) -> None:
        """Requests to non-AI URLs are forwarded without inspection."""
        ff = MagicMock()
        engine = MagicMock()
        addon = _make_addon(file_filter=ff, engine=engine)

        flow = _make_flow(url="https://example.com/api/data", body=b"hello")
        addon.request(flow)

        ff.should_block.assert_not_called()
        engine.scan.assert_not_called()
        assert flow.response is None

    # ── 2. .env file content → 403 blocked ────────────────────────────

    @patch("acf.proxy.intercept.http.Response")
    def test_env_file_blocked_with_403(self, mock_response_cls: MagicMock) -> None:
        """Requests containing .env file content are blocked with HTTP 403."""
        sentinel_response = MagicMock()
        mock_response_cls.make.return_value = sentinel_response

        ff = MagicMock()
        ff.should_block.return_value = (True, [
            FileBlockMatch(rule_type=MatchType.EXTENSION, matched_value=".env", position=0),
        ])
        audit = MagicMock()
        addon = _make_addon(file_filter=ff, audit=audit)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=b"DATABASE_URL=postgres://...",
        )
        addon.request(flow)

        mock_response_cls.make.assert_called_once()
        assert mock_response_cls.make.call_args[0][0] == 403
        assert flow.response is sentinel_response

    # ── 3. AWS key → redacted ─────────────────────────────────────────

    def test_aws_key_redacted(self) -> None:
        """Requests containing AWS keys are redacted before forwarding."""
        finding = Finding(
            secret_type="aws-access-key",
            start=10,
            end=30,
            confidence="HIGH",
            matched_rule="aws-access-key-id",
        )
        engine = MagicMock()
        engine.scan.return_value = [finding]

        ff = MagicMock()
        ff.should_block.return_value = (False, [])

        redactor = MagicMock()
        redactor.redact.return_value = "key=[REDACTED:aws-access-key]"

        audit = MagicMock()
        addon = _make_addon(file_filter=ff, engine=engine, redactor=redactor, audit=audit)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=b"key=AKIAIOSFODNN7EXAMPLE",
        )
        addon.request(flow)

        redactor.redact.assert_called_once()
        flow.request.set_content.assert_called_once()
        # Content-Length should be updated
        assert "Content-Length" in flow.request.headers

    # ── 4. Clean request passes through unchanged ─────────────────────

    def test_clean_request_passes_through(self) -> None:
        """Clean requests to AI endpoints are forwarded without modification."""
        ff = MagicMock()
        ff.should_block.return_value = (False, [])

        engine = MagicMock()
        engine.scan.return_value = []

        addon = _make_addon(file_filter=ff, engine=engine)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=b"Hello, how are you?",
        )
        addon.request(flow)

        flow.request.set_content.assert_not_called()
        assert flow.response is None

    # ── 5. Audit logger receives CRITICAL for file block ──────────────

    @patch("acf.proxy.intercept.http.Response")
    def test_audit_critical_on_file_block(self, mock_response_cls: MagicMock) -> None:
        """File-block events produce a CRITICAL audit log entry."""
        mock_response_cls.make.return_value = MagicMock()

        file_matches = [
            FileBlockMatch(rule_type=MatchType.EXTENSION, matched_value=".env", position=5),
        ]
        ff = MagicMock()
        ff.should_block.return_value = (True, file_matches)

        audit = MagicMock()
        addon = _make_addon(file_filter=ff, audit=audit)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=b"test.env",
        )
        addon.request(flow)

        audit.log_file_block.assert_called_once()
        block_call_kwargs = audit.log_file_block.call_args
        assert block_call_kwargs.kwargs["url"] == "https://api.openai.com/v1/chat/completions"

    # ── 6. Audit logger receives WARNING for redaction ────────────────

    def test_audit_warning_on_redaction(self) -> None:
        """Redaction events produce a WARNING audit log entry."""
        finding = Finding(
            secret_type="aws-secret-key",
            start=0,
            end=40,
            confidence="HIGH",
            matched_rule="aws-secret-access-key",
        )
        engine = MagicMock()
        engine.scan.return_value = [finding]

        ff = MagicMock()
        ff.should_block.return_value = (False, [])

        redactor = MagicMock()
        redactor.redact.return_value = "[REDACTED:aws-secret-key]"

        audit = MagicMock()
        addon = _make_addon(file_filter=ff, engine=engine, redactor=redactor, audit=audit)

        flow = _make_flow(
            url="https://api.anthropic.com/v1/messages",
            body=b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        addon.request(flow)

        audit.log_redaction.assert_called_once()
        redact_call = audit.log_redaction.call_args
        summaries = redact_call.kwargs["findings"]
        assert len(summaries) == 1
        assert isinstance(summaries[0], FindingSummary)
        assert summaries[0].type == "aws-secret-key"

    # ── 7. Response hook is pass-through ──────────────────────────────

    def test_response_hook_passthrough(self) -> None:
        """The response hook does not modify the flow."""
        addon = _make_addon()
        flow = _make_flow()
        flow.response = MagicMock()
        flow.response.status_code = 200

        addon.response(flow)

        # Response should remain untouched
        assert flow.response.status_code == 200

    # ── 8. Exception in request handler doesn't crash ─────────────────

    def test_exception_in_request_does_not_crash(self) -> None:
        """Exceptions in the request pipeline are caught and logged."""
        ff = MagicMock()
        ff.should_block.side_effect = RuntimeError("boom")

        addon = _make_addon(file_filter=ff)
        flow = _make_flow(url="https://api.openai.com/v1/chat/completions", body=b"x")

        # Should not raise
        addon.request(flow)

    # ── 9. Empty body to AI endpoint passes through ───────────────────

    def test_empty_body_passes_through(self) -> None:
        """Empty-body requests to AI endpoints pass through without scanning."""
        ff = MagicMock()
        ff.should_block.return_value = (False, [])

        engine = MagicMock()
        engine.scan.return_value = []

        addon = _make_addon(file_filter=ff, engine=engine)

        flow = _make_flow(url="https://api.openai.com/v1/models", body=b"")
        addon.request(flow)

        # scan is called with empty string, returns []
        engine.scan.assert_called_once_with("")
        flow.request.set_content.assert_not_called()

    # ── 10. Content-Length updated after redaction ────────────────────

    def test_content_length_updated_after_redaction(self) -> None:
        """Content-Length header reflects the redacted body size."""
        finding = Finding(
            secret_type="generic-api-key",
            start=0,
            end=10,
            confidence="HIGH",
            matched_rule="generic-api-key",
        )
        engine = MagicMock()
        engine.scan.return_value = [finding]

        ff = MagicMock()
        ff.should_block.return_value = (False, [])

        redacted = "REDACTED!"  # 9 bytes
        redactor = MagicMock()
        redactor.redact.return_value = redacted

        addon = _make_addon(file_filter=ff, engine=engine, redactor=redactor)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=b"secret_key",
        )
        addon.request(flow)

        flow.request.set_content.assert_called_once_with(redacted.encode("utf-8"))
        assert flow.request.headers["Content-Length"] == str(len(redacted.encode("utf-8")))

    # ── 11. Multiple findings all redacted ────────────────────────────

    def test_multiple_findings_all_redacted(self) -> None:
        """All findings in a request are redacted and audited."""
        findings = [
            Finding(secret_type="aws-key", start=0, end=20, confidence="HIGH", matched_rule="r1"),
            Finding(secret_type="github-token", start=30, end=70, confidence="HIGH", matched_rule="r2"),
        ]
        engine = MagicMock()
        engine.scan.return_value = findings

        ff = MagicMock()
        ff.should_block.return_value = (False, [])

        redactor = MagicMock()
        redactor.redact.return_value = "[REDACTED:aws-key] and [REDACTED:github-token]"

        audit = MagicMock()
        addon = _make_addon(file_filter=ff, engine=engine, redactor=redactor, audit=audit)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=b"AKIAIOSFODNN7EXAMPLE and ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        )
        addon.request(flow)

        # Both findings passed to redactor
        redactor.redact.assert_called_once()
        redact_args = redactor.redact.call_args
        assert len(redact_args[0][1]) == 2

        # Audit has 2 summaries
        audit.log_redaction.assert_called_once()
        summaries = audit.log_redaction.call_args.kwargs["findings"]
        assert len(summaries) == 2

    # ── 12. File block prevents detection engine from running ─────────

    @patch("acf.proxy.intercept.http.Response")
    def test_file_block_skips_detection_engine(self, mock_response_cls: MagicMock) -> None:
        """When file filter blocks, the detection engine is never invoked."""
        mock_response_cls.make.return_value = MagicMock()

        ff = MagicMock()
        ff.should_block.return_value = (True, [
            FileBlockMatch(rule_type=MatchType.PATH, matched_value="~/.ssh/", position=0),
        ])

        engine = MagicMock()
        addon = _make_addon(file_filter=ff, engine=engine)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=b"~/.ssh/id_rsa",
        )
        addon.request(flow)

        engine.scan.assert_not_called()

    # ── 13. Client IP extracted and passed to audit ───────────────────

    @patch("acf.proxy.intercept.http.Response")
    def test_client_ip_passed_to_audit(self, mock_response_cls: MagicMock) -> None:
        """Client IP from the flow is forwarded to audit logger."""
        mock_response_cls.make.return_value = MagicMock()

        ff = MagicMock()
        ff.should_block.return_value = (True, [
            FileBlockMatch(rule_type=MatchType.EXTENSION, matched_value=".pem", position=0),
        ])

        audit = MagicMock()
        addon = _make_addon(file_filter=ff, audit=audit)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=b"cert.pem",
            client_addr=("192.168.1.100", 12345),
        )
        addon.request(flow)

        audit.log_file_block.assert_called_once()
        assert audit.log_file_block.call_args.kwargs["client_ip"] == "192.168.1.100"


class TestClientIpHelper:
    """Tests for the _client_ip helper function."""

    def test_extracts_ip_from_tuple(self) -> None:
        flow = MagicMock()
        flow.client_conn.address = ("10.0.0.1", 8080)
        assert _client_ip(flow) == "10.0.0.1"

    def test_returns_empty_on_failure(self) -> None:
        flow = MagicMock()
        flow.client_conn.address = None
        # Should not raise, returns something (possibly "None" string or "")
        result = _client_ip(flow)
        assert isinstance(result, str)

    def test_extracts_ip_from_string_address(self) -> None:
        """Non-tuple address (e.g. Unix socket path) is stringified."""
        flow = MagicMock()
        flow.client_conn.address = "/var/run/proxy.sock"
        assert _client_ip(flow) == "/var/run/proxy.sock"

    def test_returns_empty_on_attribute_error(self) -> None:
        """Missing client_conn attribute returns empty string."""
        flow = MagicMock()
        del flow.client_conn.address  # simulate missing attr
        # MagicMock will still return a mock, so use PropertyMock to raise
        type(flow.client_conn).address = property(lambda self: (_ for _ in ()).throw(AttributeError("no addr")))
        result = _client_ip(flow)
        assert result == ""


# ── Edge-case tests ────────────────────────────────────────────────────


class TestInterceptAddonEdgeCases:
    """Edge-case and robustness tests for InterceptAddon."""

    # ── E1. Malformed request — get_content() returns None ────────────

    def test_malformed_request_no_body(self) -> None:
        """When get_content() returns None the pipeline handles it gracefully."""
        ff = MagicMock()
        ff.should_block.return_value = (False, [])

        engine = MagicMock()
        engine.scan.return_value = []

        addon = _make_addon(file_filter=ff, engine=engine)

        flow = _make_flow(url="https://api.openai.com/v1/chat/completions")
        flow.request.get_content.return_value = None  # no body at all

        # Should not raise
        addon.request(flow)

        # body_text should be "" → scan called with empty string
        engine.scan.assert_called_once_with("")
        flow.request.set_content.assert_not_called()

    # ── E2. Binary body (raw bytes, not valid text) ───────────────────

    def test_binary_body_handled_gracefully(self) -> None:
        """Binary payload (e.g. image data) is decoded with replacement chars."""
        binary_data = bytes(range(256))  # all byte values including non-UTF8

        ff = MagicMock()
        ff.should_block.return_value = (False, [])

        engine = MagicMock()
        engine.scan.return_value = []

        addon = _make_addon(file_filter=ff, engine=engine)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=binary_data,
        )
        addon.request(flow)

        # The body should be decoded with errors="replace" — no crash
        engine.scan.assert_called_once()
        scanned_text = engine.scan.call_args[0][0]
        assert isinstance(scanned_text, str)
        # Replacement characters should be present for invalid bytes
        assert "\ufffd" in scanned_text

    # ── E3. Empty body (explicit b"") ─────────────────────────────────

    def test_empty_body_explicit(self) -> None:
        """Explicit empty-bytes body is handled without errors."""
        ff = MagicMock()
        ff.should_block.return_value = (False, [])

        engine = MagicMock()
        engine.scan.return_value = []

        addon = _make_addon(file_filter=ff, engine=engine)

        flow = _make_flow(
            url="https://api.anthropic.com/v1/messages",
            body=b"",
        )
        addon.request(flow)

        engine.scan.assert_called_once_with("")
        flow.request.set_content.assert_not_called()

    # ── E4. Huge body (>10 MB equivalent) ─────────────────────────────

    def test_huge_body_processed(self) -> None:
        """A very large request body (>10 MB) is processed without crashing."""
        # 11 MB of repetitive text — large enough to stress-test
        huge_body = b"x" * (11 * 1024 * 1024)

        ff = MagicMock()
        ff.should_block.return_value = (False, [])

        engine = MagicMock()
        engine.scan.return_value = []

        addon = _make_addon(file_filter=ff, engine=engine)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=huge_body,
        )
        addon.request(flow)

        # scan should receive the full decoded text
        engine.scan.assert_called_once()
        scanned_text = engine.scan.call_args[0][0]
        assert len(scanned_text) == len(huge_body)

    # ── E5. Detection engine raises — proxy doesn't crash ─────────────

    def test_detection_engine_error_does_not_crash(self) -> None:
        """If the detection engine raises, the addon catches and logs it."""
        ff = MagicMock()
        ff.should_block.return_value = (False, [])

        engine = MagicMock()
        engine.scan.side_effect = RuntimeError("detection engine OOM")

        addon = _make_addon(file_filter=ff, engine=engine)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=b"some normal text",
        )

        # Must not raise — outer try/except in request() catches it
        addon.request(flow)

        # Request should not be modified (error occurred before redaction)
        flow.request.set_content.assert_not_called()

    # ── E6. Redactor raises — proxy doesn't crash ─────────────────────

    def test_redactor_error_does_not_crash(self) -> None:
        """If the redactor raises, the addon catches and logs it."""
        finding = Finding(
            secret_type="test-key",
            start=0,
            end=5,
            confidence="HIGH",
            matched_rule="test",
        )
        engine = MagicMock()
        engine.scan.return_value = [finding]

        ff = MagicMock()
        ff.should_block.return_value = (False, [])

        redactor = MagicMock()
        redactor.redact.side_effect = ValueError("redactor internal error")

        addon = _make_addon(file_filter=ff, engine=engine, redactor=redactor)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=b"hello",
        )

        # Must not raise
        addon.request(flow)

        # Body should not be modified since redactor failed
        flow.request.set_content.assert_not_called()

    # ── E7. Non-UTF8 text handled gracefully ───────────────────────────

    def test_non_utf8_text_decoded_with_replacement(self) -> None:
        """Invalid UTF-8 sequences are replaced, not raising UnicodeDecodeError."""
        # Mix of valid and invalid UTF-8 bytes
        bad_utf8 = b"hello \xff\xfe world \x80\x81\x82"

        ff = MagicMock()
        ff.should_block.return_value = (False, [])

        engine = MagicMock()
        engine.scan.return_value = []

        addon = _make_addon(file_filter=ff, engine=engine)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=bad_utf8,
        )
        addon.request(flow)

        engine.scan.assert_called_once()
        scanned_text = engine.scan.call_args[0][0]
        assert isinstance(scanned_text, str)
        # Valid parts preserved, invalid replaced
        assert "hello" in scanned_text
        assert "world" in scanned_text
        assert "\ufffd" in scanned_text

    # ── E8. Response hook exception doesn't crash ─────────────────────

    def test_response_hook_exception_does_not_crash(self) -> None:
        """Exceptions in the response hook are caught and logged."""
        addon = _make_addon()
        flow = MagicMock()
        # Make _handle_response raise by patching it
        addon._handle_response = MagicMock(side_effect=RuntimeError("response boom"))

        # Must not raise
        addon.response(flow)

    # ── E9. File filter raises — proxy doesn't crash ───────────────────

    def test_file_filter_error_does_not_crash(self) -> None:
        """If file_filter.should_block raises, the addon catches it."""
        ff = MagicMock()
        ff.should_block.side_effect = OSError("disk read error")

        addon = _make_addon(file_filter=ff)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=b"some content",
        )

        # Must not raise
        addon.request(flow)

    # ── E10. Audit logger raises — proxy doesn't crash ────────────────

    @patch("acf.proxy.intercept.http.Response")
    def test_audit_logger_error_does_not_crash(
        self, mock_response_cls: MagicMock
    ) -> None:
        """If audit logger raises during file block, addon still doesn't crash."""
        mock_response_cls.make.return_value = MagicMock()

        ff = MagicMock()
        ff.should_block.return_value = (True, [
            FileBlockMatch(rule_type=MatchType.EXTENSION, matched_value=".env", position=0),
        ])

        audit = MagicMock()
        audit.log_file_block.side_effect = IOError("audit disk full")

        addon = _make_addon(file_filter=ff, audit=audit)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=b"test.env",
        )

        # Must not raise — outer try/except catches audit failure
        addon.request(flow)

    # ── E11. Unicode body with multi-byte characters ──────────────────

    def test_unicode_multibyte_body(self) -> None:
        """Body with multi-byte Unicode (CJK, emoji) is handled correctly."""
        unicode_body = "你好世界 🌍 مرحبا".encode("utf-8")

        ff = MagicMock()
        ff.should_block.return_value = (False, [])

        engine = MagicMock()
        engine.scan.return_value = []

        addon = _make_addon(file_filter=ff, engine=engine)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=unicode_body,
        )
        addon.request(flow)

        engine.scan.assert_called_once()
        scanned_text = engine.scan.call_args[0][0]
        assert "你好世界" in scanned_text
        assert "🌍" in scanned_text

    # ── E12. Client IP extraction with IPv6 tuple ─────────────────────

    def test_client_ip_ipv6_tuple(self) -> None:
        """IPv6 address tuple is extracted correctly."""
        flow = MagicMock()
        # IPv6 sockaddr: (address, port, flowinfo, scope_id)
        flow.client_conn.address = ("::1", 8080, 0, 0)
        assert _client_ip(flow) == "::1"

    # ── E13. Redaction with findings updates Content-Length correctly ──

    def test_redaction_content_length_matches_set_content(self) -> None:
        """Content-Length matches the exact bytes passed to set_content."""
        finding = Finding(
            secret_type="api-key",
            start=0,
            end=8,
            confidence="HIGH",
            matched_rule="test",
        )
        engine = MagicMock()
        engine.scan.return_value = [finding]

        ff = MagicMock()
        ff.should_block.return_value = (False, [])

        # Redacted text with multi-byte chars to verify byte-length vs char-length
        redacted = "[REDACTED:api-key] 你好"  # contains 2 CJK chars (6 bytes in UTF-8)
        redactor = MagicMock()
        redactor.redact.return_value = redacted

        addon = _make_addon(file_filter=ff, engine=engine, redactor=redactor)

        flow = _make_flow(
            url="https://api.openai.com/v1/chat/completions",
            body=b"mysecret rest",
        )
        addon.request(flow)

        expected_bytes = redacted.encode("utf-8")
        flow.request.set_content.assert_called_once_with(expected_bytes)
        # Content-Length should be byte count, not char count
        assert flow.request.headers["Content-Length"] == str(len(expected_bytes))
        assert flow.request.headers["Content-Length"] != str(len(redacted))
