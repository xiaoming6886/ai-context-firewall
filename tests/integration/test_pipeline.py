"""Integration tests for the AI Context Firewall pipeline.

Wires FileFilter → DetectionEngine → Redactor → AuditLogger in sequence,
testing the full request-processing pipeline without an actual HTTP proxy.

Each test exercises the complete chain from input to audit output, verifying
that components interact correctly end-to-end.

Total: 13 tests across 9 test classes
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from acf.audit.logger import AuditLogger
from acf.config.settings import AppConfig
from acf.detection.engine import DetectionEngine
from acf.models.types import (
    EventType,
    FileBlockMatch,
    Finding,
    FindingSummary,
    MatchType,
    Severity,
)
from acf.proxy.file_filter import FileFilter
from acf.redaction.redactor import Redactor


# ── Pipeline orchestrator (mirrors proxy middleware logic) ─────────────


@dataclass
class PipelineResult:
    """Outcome of a single request passing through the pipeline."""

    blocked: bool = False
    block_matches: list[FileBlockMatch] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    redacted_text: str = ""
    original_text: str = ""


def run_pipeline(
    *,
    file_path: str,
    body: str,
    file_filter: FileFilter,
    engine: DetectionEngine,
    redactor: Redactor,
    audit_logger: AuditLogger,
    url: str = "/v1/chat/completions",
    client_ip: str = "127.0.0.1",
    request_id: str = "req-test-001",
) -> PipelineResult:
    """Execute the full FileFilter → DetectionEngine → Redactor → AuditLogger pipeline.

    This mirrors the logic that the mitmproxy intercept addon would execute
    for each request, but without any HTTP layer.

    Parameters
    ----------
    file_path:
        The file path or URL path associated with the request body.
    body:
        The raw text content of the request.
    file_filter:
        Pre-filter that blocks sensitive files by extension/path/PEM content.
    engine:
        Detection engine that scans for secrets.
    redactor:
        Redaction engine that replaces findings with markers.
    audit_logger:
        JSONL audit logger for recording decisions.
    url:
        The request URL (for audit logging).
    client_ip:
        Client IP address (for audit logging).
    request_id:
        Unique request identifier (for audit logging).

    Returns
    -------
    PipelineResult
        Structured outcome including block status, findings, and redacted text.
    """
    result = PipelineResult(original_text=body)

    # ── Stage 1: File filter ────────────────────────────────────────
    blocked, matches = file_filter.should_block(file_path)
    if blocked:
        result.blocked = True
        result.block_matches = matches
        audit_logger.log_file_block(
            url=url,
            matches=matches,
            client_ip=client_ip,
            request_id=request_id,
        )
        return result

    # ── Stage 2: Detection engine ───────────────────────────────────
    findings = engine.scan(body)
    result.findings = findings

    # ── Stage 3: Redaction ──────────────────────────────────────────
    if findings:
        result.redacted_text = redactor.redact(body, findings)
        # Build finding summaries for audit
        summaries = [
            FindingSummary(
                type=f.secret_type,
                confidence=f.confidence,
                length=f.end - f.start,
            )
            for f in findings
        ]
        audit_logger.log_redaction(
            url=url,
            findings=summaries,
            client_ip=client_ip,
            request_id=request_id,
        )
    else:
        result.redacted_text = body

    return result


# ── Fixtures ───────────────────────────────────────────────────────────


@pytest.fixture
def config() -> AppConfig:
    """AppConfig with entropy enabled and generous body size."""
    return AppConfig(
        entropy_enabled=True,
        max_body_size_mb=999,
    )


@pytest.fixture
def pipeline_components(config: AppConfig, tmp_path: Path):
    """Build all pipeline components wired together."""
    file_filter = FileFilter()
    engine = DetectionEngine(config)
    redactor = Redactor()
    log_path = tmp_path / "audit.jsonl"
    audit_logger = AuditLogger(log_path)
    return {
        "file_filter": file_filter,
        "engine": engine,
        "redactor": redactor,
        "audit_logger": audit_logger,
        "log_path": log_path,
    }


# ══════════════════════════════════════════════════════════════════════
# Test 1: .env file in request → FileFilter blocks (403)
# ══════════════════════════════════════════════════════════════════════


class TestEnvFileBlocked:
    """A .env file path triggers FileFilter blocking before detection runs."""

    def test_env_file_blocked(
        self, pipeline_components: dict
    ) -> None:
        """Requesting a .env file → blocked at FileFilter stage, no detection."""
        result = run_pipeline(
            file_path="/project/config/.env",
            body="DATABASE_URL=postgres://admin:secret@db:5432/prod\nSECRET_KEY=abc123",
            **pipeline_components,
        )

        assert result.blocked is True
        assert len(result.block_matches) >= 1
        assert result.block_matches[0].matched_value == ".env"
        # Detection engine should NOT have run — no findings
        assert result.findings == []
        # No redaction performed
        assert result.redacted_text == ""

    def test_env_file_audit_log_written(
        self, pipeline_components: dict
    ) -> None:
        """Blocking a .env file produces a CRITICAL audit event."""
        run_pipeline(
            file_path="/app/.env",
            body="API_KEY=sk-1234567890abcdef",
            **pipeline_components,
        )

        events = pipeline_components["audit_logger"].read_events()
        assert len(events) == 1
        ev = events[0]
        assert ev.severity == Severity.CRITICAL
        assert ev.event_type == EventType.FILE_BLOCK
        assert len(ev.file_blocks) >= 1
        assert ev.file_blocks[0].matched_value == ".env"


# ══════════════════════════════════════════════════════════════════════
# Test 2: AWS key in request → detected + redacted
# ══════════════════════════════════════════════════════════════════════


class TestAwsKeyDetectedAndRedacted:
    """An AWS Access Key ID in the body is detected and redacted."""

    def test_aws_key_detected_and_redacted(
        self, pipeline_components: dict
    ) -> None:
        """AWS key passes file filter, gets detected, and is redacted."""
        body = "config: AKIAIOSFODNN7EXAMPLE is the access key"
        result = run_pipeline(
            file_path="/app/config.yaml",
            body=body,
            **pipeline_components,
        )

        # Not blocked by file filter
        assert result.blocked is False

        # Detection found the AWS key
        assert len(result.findings) >= 1
        aws_findings = [f for f in result.findings if f.matched_rule == "aws-access-key"]
        assert len(aws_findings) == 1
        assert aws_findings[0].secret_type == "aws-access-key"

        # Redaction replaced the key
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text
        assert "[REDACTED:aws-access-key]" in result.redacted_text
        # Surrounding text preserved
        assert "config:" in result.redacted_text
        assert "is the access key" in result.redacted_text


# ══════════════════════════════════════════════════════════════════════
# Test 3: JWT in request → detected
# ══════════════════════════════════════════════════════════════════════


class TestJwtDetected:
    """A JWT token in the body is detected by the detection engine."""

    def test_jwt_detected(
        self, pipeline_components: dict
    ) -> None:
        """A well-formed JWT is detected and redacted."""
        jwt_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        body = f"Authorization: Bearer {jwt_token}"
        result = run_pipeline(
            file_path="/api/auth",
            body=body,
            **pipeline_components,
        )

        assert result.blocked is False

        # JWT should be detected
        jwt_findings = [f for f in result.findings if f.matched_rule == "jwt"]
        assert len(jwt_findings) >= 1

        # Redacted text should not contain the raw JWT
        assert jwt_token not in result.redacted_text
        assert "[REDACTED:" in result.redacted_text


# ══════════════════════════════════════════════════════════════════════
# Test 4: Mixed file with secrets + safe code → secrets redacted,
#          safe code preserved
# ══════════════════════════════════════════════════════════════════════


class TestMixedSecretsAndSafeCode:
    """A file containing both secrets and safe code: secrets are redacted
    while safe code is preserved intact."""

    def test_mixed_content_selective_redaction(
        self, pipeline_components: dict
    ) -> None:
        """Secrets are redacted; surrounding safe code is untouched."""
        body = (
            'def hello(name: str = "World") -> str:\n'
            '    return f"Hello, {name}!"\n'
            "\n"
            "# Configuration\n"
            'aws_key = "AKIAIOSFODNN7EXAMPLE"\n'
            'openai_key = "sk-abc123def456ghi789jkl012mno345p"\n'
            "\n"
            "def add(a: int, b: int) -> int:\n"
            "    return a + b\n"
        )
        result = run_pipeline(
            file_path="/app/main.py",
            body=body,
            **pipeline_components,
        )

        assert result.blocked is False
        assert len(result.findings) >= 2

        # Secrets are redacted
        assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text
        assert "sk-abc123def456ghi789jkl012mno345p" not in result.redacted_text

        # Safe code is preserved
        assert 'def hello(name: str = "World") -> str:' in result.redacted_text
        assert 'return f"Hello, {name}!"' in result.redacted_text
        assert "def add(a: int, b: int) -> int:" in result.redacted_text
        assert "return a + b" in result.redacted_text
        assert "# Configuration" in result.redacted_text


# ══════════════════════════════════════════════════════════════════════
# Test 5: Audit log written for file block (CRITICAL)
# ══════════════════════════════════════════════════════════════════════


class TestAuditLogFileBlock:
    """Verify that file-block events are written to the audit log with
    correct severity and structure."""

    def test_file_block_audit_event_structure(
        self, pipeline_components: dict
    ) -> None:
        """A blocked .pem file produces a well-structured CRITICAL audit event."""
        run_pipeline(
            file_path="/certs/server.pem",
            body="-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
            request_id="req-audit-001",
            client_ip="10.0.0.5",
            **pipeline_components,
        )

        events = pipeline_components["audit_logger"].read_events()
        assert len(events) == 1
        ev = events[0]

        # Severity and type
        assert ev.severity == Severity.CRITICAL
        assert ev.event_type == EventType.FILE_BLOCK

        # Metadata preserved
        assert ev.request_id == "req-audit-001"
        assert ev.client_ip == "10.0.0.5"
        assert ev.url == "/v1/chat/completions"

        # File block details
        assert len(ev.file_blocks) >= 1
        assert ev.file_blocks[0].matched_value == ".pem"

        # No findings (detection didn't run)
        assert ev.findings == []
        assert ev.findings_count == 0

    def test_multiple_file_blocks_logged(
        self, pipeline_components: dict
    ) -> None:
        """A path matching both extension and path pattern logs all matches."""
        run_pipeline(
            file_path="~/.ssh/id_rsa.key",
            body="ssh-rsa AAAA...",
            request_id="req-audit-002",
            **pipeline_components,
        )

        events = pipeline_components["audit_logger"].read_events()
        assert len(events) == 1
        ev = events[0]
        assert ev.severity == Severity.CRITICAL
        # Should have both extension (.key) and path (~/.ssh/) matches
        assert len(ev.file_blocks) >= 2
        rule_types = {m.rule_type for m in ev.file_blocks}
        assert MatchType.EXTENSION in rule_types
        assert MatchType.PATH in rule_types


# ══════════════════════════════════════════════════════════════════════
# Test 6: Audit log written for redaction (WARNING)
# ══════════════════════════════════════════════════════════════════════


class TestAuditLogRedaction:
    """Verify that redaction events are written to the audit log with
    correct severity and finding summaries."""

    def test_redaction_audit_event_structure(
        self, pipeline_components: dict
    ) -> None:
        """A body with an AWS key produces a WARNING redaction audit event."""
        body = "key=AKIAIOSFODNN7EXAMPLE"
        run_pipeline(
            file_path="/app/deploy.sh",
            body=body,
            request_id="req-redact-001",
            client_ip="192.168.1.50",
            **pipeline_components,
        )

        events = pipeline_components["audit_logger"].read_events()
        assert len(events) == 1
        ev = events[0]

        # Severity and type
        assert ev.severity == Severity.WARNING
        assert ev.event_type == EventType.REDACTION

        # Metadata
        assert ev.request_id == "req-redact-001"
        assert ev.client_ip == "192.168.1.50"

        # Findings
        assert ev.findings_count >= 1
        assert len(ev.findings) >= 1
        # At least one finding should be the AWS key
        aws_summaries = [f for f in ev.findings if f.type == "aws-access-key"]
        assert len(aws_summaries) >= 1
        assert aws_summaries[0].confidence == "HIGH"
        assert aws_summaries[0].length == 20  # AKIAIOSFODNN7EXAMPLE is 20 chars

        # No file blocks (file filter didn't trigger)
        assert ev.file_blocks == []

    def test_redaction_audit_multiple_findings(
        self, pipeline_components: dict
    ) -> None:
        """Multiple secrets in one body produce multiple finding summaries."""
        body = (
            "aws=AKIAIOSFODNN7EXAMPLE\n"
            "openai=sk-abc123def456ghi789jkl012mno345p\n"
        )
        run_pipeline(
            file_path="/app/config.txt",
            body=body,
            request_id="req-redact-002",
            **pipeline_components,
        )

        events = pipeline_components["audit_logger"].read_events()
        assert len(events) == 1
        ev = events[0]
        assert ev.severity == Severity.WARNING
        assert ev.event_type == EventType.REDACTION
        assert ev.findings_count >= 2
        types = {f.type for f in ev.findings}
        assert "aws-access-key" in types
        assert "openai-api-key" in types


# ══════════════════════════════════════════════════════════════════════
# Test 7: Safe code → no findings, no redaction
# ══════════════════════════════════════════════════════════════════════


class TestSafeCodePassesThrough:
    """Safe code with no secrets passes through the entire pipeline
    without any findings, redaction, or audit events."""

    def test_safe_code_no_findings(
        self, pipeline_components: dict
    ) -> None:
        """Pure safe code produces no findings and text is unchanged."""
        safe_code = (
            'def hello(name: str = "World") -> str:\n'
            '    """Return a friendly greeting."""\n'
            '    return f"Hello, {name}!"\n'
            "\n"
            "\n"
            "class Foo:\n"
            '    """A simple example class."""\n'
            "\n"
            "    def __init__(self, value: int = 0) -> None:\n"
            "        self._value = value\n"
            "\n"
            "    def get_value(self) -> int:\n"
            "        return self._value\n"
        )
        result = run_pipeline(
            file_path="/app/utils.py",
            body=safe_code,
            **pipeline_components,
        )

        assert result.blocked is False
        assert result.findings == []
        assert result.redacted_text == safe_code

        # No audit events written (no block, no redaction)
        events = pipeline_components["audit_logger"].read_events()
        assert len(events) == 0

    def test_safe_json_no_findings(
        self, pipeline_components: dict
    ) -> None:
        """A benign JSON payload produces no findings."""
        safe_json = (
            '{"name": "test-app", "version": "1.0.0", '
            '"description": "A sample application", '
            '"dependencies": {"flask": "^2.0", "requests": "^2.28"}}'
        )
        result = run_pipeline(
            file_path="/app/package.json",
            body=safe_json,
            **pipeline_components,
        )

        assert result.blocked is False
        assert result.findings == []
        assert result.redacted_text == safe_json

        events = pipeline_components["audit_logger"].read_events()
        assert len(events) == 0


# ══════════════════════════════════════════════════════════════════════
# Test 8: Full pipeline sequence — block then scan in series
# ══════════════════════════════════════════════════════════════════════


class TestPipelineSequence:
    """Verify that multiple requests through the same pipeline produce
    correct cumulative audit log entries."""

    def test_sequential_requests_audit_log(
        self, pipeline_components: dict
    ) -> None:
        """Three sequential requests (block, redact, pass) produce correct audit trail."""
        # Request 1: blocked .env file
        r1 = run_pipeline(
            file_path="/project/.env",
            body="SECRET_KEY=supersecretvalue123",
            request_id="seq-001",
            **pipeline_components,
        )
        assert r1.blocked is True

        # Request 2: body with AWS key → redacted
        r2 = run_pipeline(
            file_path="/app/deploy.py",
            body="key = AKIAIOSFODNN7EXAMPLE",
            request_id="seq-002",
            **pipeline_components,
        )
        assert r2.blocked is False
        assert len(r2.findings) >= 1

        # Request 3: safe code → passes through
        r3 = run_pipeline(
            file_path="/app/utils.py",
            body="def add(a, b): return a + b",
            request_id="seq-003",
            **pipeline_components,
        )
        assert r3.blocked is False
        assert r3.findings == []

        # Verify cumulative audit log
        events = pipeline_components["audit_logger"].read_events()
        assert len(events) == 2  # block + redaction (pass doesn't log)

        # First event: file block
        assert events[0].event_type == EventType.FILE_BLOCK
        assert events[0].severity == Severity.CRITICAL
        assert events[0].request_id == "seq-001"

        # Second event: redaction
        assert events[1].event_type == EventType.REDACTION
        assert events[1].severity == Severity.WARNING
        assert events[1].request_id == "seq-002"


# ══════════════════════════════════════════════════════════════════════
# Test 9: PEM private key content → blocked by FileFilter PEM check
# ══════════════════════════════════════════════════════════════════════


class TestPemContentBlocked:
    """Inline PEM private key content (not just file extension) is blocked
    by the FileFilter's PEM content check."""

    def test_pem_inline_content_blocked(
        self, pipeline_components: dict
    ) -> None:
        """PEM private key content in the request payload is blocked.

        FileFilter.check() inspects its argument as both a file path and
        raw content.  When the PEM block appears in the argument string,
        the PEM inline check triggers regardless of file extension.
        """
        pem_body = (
            "Some config text\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA1K7Q0v3b8z5F0a7b8c9d0e1f2g3h4i5j6k7l8m9n0o1p2q3r4s5t6u7v8w9x0y\n"
            "z1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f3g4h5i6j7k8l9m0n\n"
            "-----END RSA PRIVATE KEY-----\n"
            "More config text\n"
        )
        # FileFilter receives the full payload as its argument,
        # enabling PEM inline detection even without a sensitive extension.
        result = run_pipeline(
            file_path=pem_body,
            body=pem_body,
            **pipeline_components,
        )

        assert result.blocked is True
        pem_matches = [m for m in result.block_matches if m.rule_type == MatchType.PEM_BLOCK]
        assert len(pem_matches) >= 1

        # Audit log should record the block
        events = pipeline_components["audit_logger"].read_events()
        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL
        assert events[0].event_type == EventType.FILE_BLOCK
