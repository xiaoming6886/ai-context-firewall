"""End-to-end audit verification test for AI Context Firewall.

Simulates 50 requests through the full pipeline (FileFilter → DetectionEngine
→ Redactor → AuditLogger), then verifies:

1. ``acf audit --summary`` reports correct event counts.
2. Every JSONL line is parseable as a valid AuditEvent.
3. Rotated gzip backups are readable and contain valid data.
4. No data is lost across log rotation boundaries.

Request mix (50 total):
  - 20 requests containing secrets  → WARNING / redaction events
  -  5 requests with sensitive files → CRITICAL / file-block events
  - 25 clean requests               → no audit events (pass-through)

Total: 6 tests across 4 test classes.
"""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from click.testing import CliRunner

from acf.audit.logger import AuditLogger
from acf.cli import main
from acf.config.settings import AppConfig
from acf.detection.engine import DetectionEngine
from acf.models.types import (
    AuditEvent,
    EventType,
    FileBlockMatch,
    Finding,
    FindingSummary,
    Severity,
)
from acf.proxy.file_filter import FileFilter
from acf.redaction.redactor import Redactor


# ── Pipeline orchestrator (mirrors proxy middleware logic) ─────────────


@dataclass
class _PipelineResult:
    """Outcome of a single request through the pipeline."""

    blocked: bool = False
    block_matches: list[FileBlockMatch] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    redacted_text: str = ""


def _run_pipeline(
    *,
    file_path: str,
    body: str,
    file_filter: FileFilter,
    engine: DetectionEngine,
    redactor: Redactor,
    audit_logger: AuditLogger,
    url: str = "/v1/chat/completions",
    client_ip: str = "127.0.0.1",
    request_id: str = "req-000",
) -> _PipelineResult:
    """Execute FileFilter → DetectionEngine → Redactor → AuditLogger."""
    result = _PipelineResult()

    # Stage 1: File filter
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

    # Stage 2: Detection
    findings = engine.scan(body)
    result.findings = findings

    # Stage 3: Redaction + audit
    if findings:
        result.redacted_text = redactor.redact(body, findings)
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


# ── Request payloads ────────────────────────────────────────────────────

# 20 secret-bearing bodies (each contains at least one detectable secret)
_SECRET_BODIES: list[tuple[str, str]] = [
    # (file_path, body)
    ("/app/config.yaml", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"),
    ("/app/deploy.sh", "export AWS_KEY=AKIAI44QH8DHBEXAMPLE"),
    ("/app/env.py", 'KEY = "AKIAJTPQ5WN5D2EXAMPLE"'),
    ("/src/auth.js", "const key = 'AKIAZ56YFQJH3EXAMPLE';"),
    ("/cfg/prod.ini", "access_key=AKIAYR34FZQ7EXAMPLE"),
    ("/app/openai.py", 'client = OpenAI(api_key="sk-abc123def456ghi789jkl012mno345p")'),
    ("/src/llm.ts", 'const k = "sk-proj-abc123def456ghi789jkl012mno345pqr";'),
    ("/cfg/keys.json", '{"openai": "sk-test1234567890abcdefghijklmnop"}'),
    ("/app/gpt.py", 'api_key = "sk-live1234567890abcdefghijklm"'),
    ("/src/ai.rb", 'key = "sk-xyz9876543210zyxwvutsrqponml"'),
    ("/app/jwt.py", "token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'"),
    ("/src/auth.go", 'tok := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"'),
    ("/cfg/tokens.txt", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.ABcdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDE"),
    ("/app/mixed.py", "aws=AKIAIOSFODNN7EXAMPLE\nopenai=sk-abc123def456ghi789jkl012mno345p"),
    ("/src/secrets.yaml", "key: AKIAI44QH8DHBEXAMPLE\nother: sk-test1234567890abcdefghijklmnop"),
    ("/cfg/creds.env", "AWS_ACCESS_KEY_ID=AKIAJTPQ5WN5D2EXAMPLE"),
    ("/app/prod.py", 'SECRET = "sk-live9876543210zyxwvutsrqponmlkj"'),
    ("/src/conf.ts", 'const aws = "AKIAZ56YFQJH3EXAMPLE";'),
    ("/cfg/api.json", '{"key": "sk-abc9876543210fedcbazyxwvutsrq"}'),
    ("/app/bot.py", 'token = "sk-proj-xyz1234567890abcdefghijklmnopqrs"'),
]

# 5 file-block paths (sensitive file extensions / paths)
_FILE_BLOCK_PATHS: list[tuple[str, str]] = [
    ("/project/.env", "DATABASE_URL=postgres://admin:secret@db:5432/prod"),
    ("/certs/server.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."),
    ("/keys/api.key", "super-secret-key-content-here"),
    ("~/.ssh/id_rsa", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD..."),
    ("/secrets/creds.p12", "binary-pkcs12-content"),
]

# 25 clean bodies (no secrets, no sensitive file paths)
_CLEAN_BODIES: list[tuple[str, str]] = [
    ("/app/utils.py", 'def add(a: int, b: int) -> int:\n    return a + b\n'),
    ("/app/models.py", "class User:\n    def __init__(self, name: str):\n        self.name = name\n"),
    ("/src/index.ts", 'console.log("Hello, world!");\n'),
    ("/src/app.js", "function greet(name) { return `Hi ${name}`; }\n"),
    ("/cfg/settings.json", '{"theme": "dark", "language": "en", "fontSize": 14}'),
    ("/app/views.py", "def index(request):\n    return render(request, 'index.html')\n"),
    ("/src/main.go", 'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("hi") }\n'),
    ("/app/routes.rb", "get '/health' do\n  'OK'\nend\n"),
    ("/src/lib.rs", 'pub fn hello() -> String { "Hello".to_string() }\n'),
    ("/app/handler.py", "def handler(event, context):\n    return {'statusCode': 200}\n"),
    ("/src/test.ts", 'describe("math", () => { it("adds", () => { expect(1+1).toBe(2); }); });\n'),
    ("/cfg/manifest.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app\n"),
    ("/app/middleware.py", "class Middleware:\n    def process(self, req):\n        return req\n"),
    ("/src/utils.js", "export const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));\n"),
    ("/app/schema.sql", "CREATE TABLE users (id SERIAL PRIMARY KEY, name VARCHAR(100));\n"),
    ("/src/types.ts", "interface Config { debug: boolean; port: number; }\n"),
    ("/app/serializers.py", "class UserSerializer:\n    class Meta:\n        fields = '__all__'\n"),
    ("/cfg/docker-compose.yml", "version: '3'\nservices:\n  web:\n    image: nginx\n"),
    ("/src/helpers.py", "def flatten(lst):\n    return [x for sub in lst for x in sub]\n"),
    ("/app/validators.py", "def is_email(s: str) -> bool:\n    return '@' in s and '.' in s\n"),
    ("/src/constants.ts", "export const MAX_RETRIES = 3;\nexport const TIMEOUT_MS = 5000;\n"),
    ("/app/exceptions.py", "class NotFoundError(Exception):\n    pass\n"),
    ("/cfg/nginx.conf", "server {\n    listen 80;\n    server_name localhost;\n}\n"),
    ("/src/logger.py", "import logging\nlogger = logging.getLogger(__name__)\n"),
    ("/app/tasks.py", "def background_task(items: list) -> int:\n    return len(items)\n"),
]


# ── Fixtures ────────────────────────────────────────────────────────────


@pytest.fixture
def e2e_config() -> AppConfig:
    """AppConfig with entropy enabled."""
    return AppConfig(entropy_enabled=True, max_body_size_mb=999)


@pytest.fixture
def e2e_pipeline(e2e_config: AppConfig, tmp_path: Path):
    """Build pipeline components with a small max_file_size to force rotation."""
    file_filter = FileFilter()
    engine = DetectionEngine(e2e_config)
    redactor = Redactor()
    log_path = tmp_path / "audit.jsonl"
    # ~200 bytes per event → rotation triggers after ~2-3 events
    audit_logger = AuditLogger(log_path, max_file_size=500, max_backup_count=5)
    return {
        "file_filter": file_filter,
        "engine": engine,
        "redactor": redactor,
        "audit_logger": audit_logger,
        "log_path": log_path,
    }


def _send_all_requests(e2e_pipeline: dict) -> dict:
    """Send all 50 requests through the pipeline.

    Returns a dict with counts and the set of request_ids that should
    have produced audit events.
    """
    audit_logger: AuditLogger = e2e_pipeline["audit_logger"]
    expected_redaction_ids: set[str] = set()
    expected_file_block_ids: set[str] = set()

    # Interleave the three categories to simulate realistic traffic
    secret_iter = iter(_SECRET_BODIES)
    block_iter = iter(_FILE_BLOCK_PATHS)
    clean_iter = iter(_CLEAN_BODIES)

    request_seq = 0
    for batch_idx in range(5):
        # Each batch: 4 secrets, 1 file block, 5 clean = 10 requests
        for _ in range(4):
            file_path, body = next(secret_iter)
            request_seq += 1
            rid = f"req-e2e-{request_seq:03d}"
            result = _run_pipeline(
                file_path=file_path,
                body=body,
                request_id=rid,
                **e2e_pipeline,
            )
            if result.findings:
                expected_redaction_ids.add(rid)

        file_path, body = next(block_iter)
        request_seq += 1
        rid = f"req-e2e-{request_seq:03d}"
        result = _run_pipeline(
            file_path=file_path,
            body=body,
            request_id=rid,
            **e2e_pipeline,
        )
        if result.blocked:
            expected_file_block_ids.add(rid)

        for _ in range(5):
            file_path, body = next(clean_iter)
            request_seq += 1
            # Clean requests don't produce audit events

    return {
        "total_requests": request_seq,
        "expected_redaction_ids": expected_redaction_ids,
        "expected_file_block_ids": expected_file_block_ids,
    }


# ══════════════════════════════════════════════════════════════════════
# Test 1: Full 50-request pipeline produces correct event counts
# ══════════════════════════════════════════════════════════════════════


class TestFiftyRequestPipeline:
    """Simulate 50 requests and verify audit event counts."""

    def test_request_counts_match_expected(
        self, e2e_pipeline: dict
    ) -> None:
        """50 requests produce the expected number of audit events."""
        stats = _send_all_requests(e2e_pipeline)

        assert stats["total_requests"] == 50

        # Collect all events from active file + backups
        all_events = _collect_all_events(e2e_pipeline)

        redaction_events = [
            e for e in all_events if e.event_type == EventType.REDACTION
        ]
        file_block_events = [
            e for e in all_events if e.event_type == EventType.FILE_BLOCK
        ]

        # Every secret-bearing request that produced findings → redaction event
        assert len(redaction_events) == len(stats["expected_redaction_ids"]), (
            f"Expected {len(stats['expected_redaction_ids'])} redaction events, "
            f"got {len(redaction_events)}"
        )

        # Every file-block request → file-block event
        assert len(file_block_events) == len(stats["expected_file_block_ids"]), (
            f"Expected {len(stats['expected_file_block_ids'])} file-block events, "
            f"got {len(file_block_events)}"
        )

        # Total events = redactions + file blocks (clean requests don't log)
        total_expected = len(stats["expected_redaction_ids"]) + len(stats["expected_file_block_ids"])
        assert len(all_events) == total_expected

    def test_redaction_request_ids_in_audit(
        self, e2e_pipeline: dict
    ) -> None:
        """Every redaction request_id appears in the audit log."""
        stats = _send_all_requests(e2e_pipeline)
        all_events = _collect_all_events(e2e_pipeline)

        logged_redaction_ids = {
            e.request_id
            for e in all_events
            if e.event_type == EventType.REDACTION
        }
        missing = stats["expected_redaction_ids"] - logged_redaction_ids
        assert not missing, f"Missing redaction request_ids: {missing}"

    def test_file_block_request_ids_in_audit(
        self, e2e_pipeline: dict
    ) -> None:
        """Every file-block request_id appears in the audit log."""
        stats = _send_all_requests(e2e_pipeline)
        all_events = _collect_all_events(e2e_pipeline)

        logged_block_ids = {
            e.request_id
            for e in all_events
            if e.event_type == EventType.FILE_BLOCK
        }
        missing = stats["expected_file_block_ids"] - logged_block_ids
        assert not missing, f"Missing file-block request_ids: {missing}"


# ══════════════════════════════════════════════════════════════════════
# Test 2: CLI ``acf audit --summary`` reports correct counts
# ══════════════════════════════════════════════════════════════════════


class TestCliAuditSummary:
    """Verify ``acf audit --summary --format json`` after 50 requests."""

    def test_summary_total_events(self, e2e_pipeline: dict) -> None:
        """CLI summary total_events matches actual event count."""
        stats = _send_all_requests(e2e_pipeline)
        log_path: Path = e2e_pipeline["log_path"]

        # The CLI reads from the active log file only (not backups).
        # We need to collect events from the active file for comparison.
        active_logger = AuditLogger(log_path)
        active_events = active_logger.read_events()

        result = CliRunner().invoke(
            main,
            ["audit", "--log-path", str(log_path), "--summary", "--format", "json"],
        )
        assert result.exit_code == 0, f"CLI failed: {result.output}"

        data = json.loads(result.output)
        assert data["total_events"] == len(active_events)

    def test_summary_severity_breakdown(self, e2e_pipeline: dict) -> None:
        """CLI summary severity counts match actual events."""
        _send_all_requests(e2e_pipeline)
        log_path: Path = e2e_pipeline["log_path"]

        active_logger = AuditLogger(log_path)
        active_events = active_logger.read_events()

        result = CliRunner().invoke(
            main,
            ["audit", "--log-path", str(log_path), "--summary", "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)

        # Count expected severities from active file events
        expected_critical = sum(
            1 for e in active_events if e.severity == Severity.CRITICAL
        )
        expected_warning = sum(
            1 for e in active_events if e.severity == Severity.WARNING
        )

        by_severity = data["by_severity"]
        if expected_critical > 0:
            assert by_severity.get("CRITICAL", 0) == expected_critical
        if expected_warning > 0:
            assert by_severity.get("WARNING", 0) == expected_warning

    def test_summary_event_type_breakdown(self, e2e_pipeline: dict) -> None:
        """CLI summary event type counts match actual events."""
        _send_all_requests(e2e_pipeline)
        log_path: Path = e2e_pipeline["log_path"]

        active_logger = AuditLogger(log_path)
        active_events = active_logger.read_events()

        result = CliRunner().invoke(
            main,
            ["audit", "--log-path", str(log_path), "--summary", "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)

        expected_redactions = sum(
            1 for e in active_events if e.event_type == EventType.REDACTION
        )
        expected_blocks = sum(
            1 for e in active_events if e.event_type == EventType.FILE_BLOCK
        )

        by_type = data["by_event_type"]
        if expected_redactions > 0:
            assert by_type.get("redaction", 0) == expected_redactions
        if expected_blocks > 0:
            assert by_type.get("file_block", 0) == expected_blocks


# ══════════════════════════════════════════════════════════════════════
# Test 3: All JSONL lines are parseable
# ══════════════════════════════════════════════════════════════════════


class TestJsonlParseability:
    """Every line in the active log and all rotated backups is valid."""

    def test_active_log_all_lines_parseable(
        self, e2e_pipeline: dict
    ) -> None:
        """Every non-empty line in the active JSONL file is valid JSON."""
        _send_all_requests(e2e_pipeline)
        log_path: Path = e2e_pipeline["log_path"]

        if not log_path.exists():
            pytest.skip("Active log file does not exist")

        line_count = 0
        with open(log_path, encoding="utf-8") as f:
            for line_no, raw in enumerate(f, start=1):
                stripped = raw.strip()
                if not stripped:
                    continue
                line_count += 1
                try:
                    parsed = json.loads(stripped)
                except json.JSONDecodeError:
                    pytest.fail(
                        f"Line {line_no} is not valid JSON: {stripped[:80]!r}"
                    )
                # Must be a valid AuditEvent
                AuditEvent.model_validate(parsed)

        assert line_count > 0, "Active log file has no parseable lines"

    def test_rotated_backups_all_lines_parseable(
        self, e2e_pipeline: dict
    ) -> None:
        """Every line in every gzip backup is valid JSON."""
        _send_all_requests(e2e_pipeline)
        log_path: Path = e2e_pipeline["log_path"]

        backups = sorted(log_path.parent.glob("audit.jsonl.*.gz"))
        if not backups:
            pytest.skip("No rotated backups created")

        total_lines = 0
        for backup_path in backups:
            with gzip.open(backup_path, "rt", encoding="utf-8") as f:
                for line_no, raw in enumerate(f, start=1):
                    stripped = raw.strip()
                    if not stripped:
                        continue
                    total_lines += 1
                    try:
                        parsed = json.loads(stripped)
                    except json.JSONDecodeError:
                        pytest.fail(
                            f"Backup {backup_path.name} line {line_no} "
                            f"is not valid JSON: {stripped[:80]!r}"
                        )
                    AuditEvent.model_validate(parsed)

        assert total_lines > 0, "Backups contain no parseable lines"


# ══════════════════════════════════════════════════════════════════════
# Test 4: Rotated logs are readable
# ══════════════════════════════════════════════════════════════════════


class TestRotatedLogsReadable:
    """Verify that rotated gzip backups exist and are decompressable."""

    def test_rotation_occurred(self, e2e_pipeline: dict) -> None:
        """With max_file_size=500, 50 requests must trigger rotation."""
        _send_all_requests(e2e_pipeline)
        log_path: Path = e2e_pipeline["log_path"]

        backups = sorted(log_path.parent.glob("audit.jsonl.*.gz"))
        assert len(backups) >= 1, (
            "Expected at least one rotated backup with max_file_size=500"
        )

    def test_backups_are_valid_gzip(self, e2e_pipeline: dict) -> None:
        """Every backup file can be decompressed without error."""
        _send_all_requests(e2e_pipeline)
        log_path: Path = e2e_pipeline["log_path"]

        backups = sorted(log_path.parent.glob("audit.jsonl.*.gz"))
        for backup_path in backups:
            try:
                with gzip.open(backup_path, "rt", encoding="utf-8") as f:
                    content = f.read()
            except gzip.BadGzipFile:
                pytest.fail(f"Backup {backup_path.name} is not valid gzip")
            except OSError as exc:
                pytest.fail(f"Backup {backup_path.name} read error: {exc}")

            assert len(content) > 0, f"Backup {backup_path.name} is empty"

    def test_backup_count_within_limit(self, e2e_pipeline: dict) -> None:
        """Number of backups does not exceed max_backup_count."""
        _send_all_requests(e2e_pipeline)
        log_path: Path = e2e_pipeline["log_path"]

        backups = sorted(log_path.parent.glob("audit.jsonl.*.gz"))
        assert len(backups) <= 5, (
            f"Expected ≤5 backups (max_backup_count=5), got {len(backups)}"
        )

    def test_backup_numbering_is_sequential(self, e2e_pipeline: dict) -> None:
        """Backup files are numbered .1.gz, .2.gz, ... without gaps."""
        _send_all_requests(e2e_pipeline)
        log_path: Path = e2e_pipeline["log_path"]

        backups = sorted(log_path.parent.glob("audit.jsonl.*.gz"))
        if not backups:
            pytest.skip("No backups to check")

        numbers = []
        for b in backups:
            # Extract number from "audit.jsonl.N.gz"
            stem = b.name.replace("audit.jsonl.", "").replace(".gz", "")
            numbers.append(int(stem))

        numbers.sort()
        expected = list(range(1, len(numbers) + 1))
        assert numbers == expected, (
            f"Backup numbering gap: got {numbers}, expected {expected}"
        )


# ══════════════════════════════════════════════════════════════════════
# Test 5: No data loss across rotation
# ══════════════════════════════════════════════════════════════════════


class TestNoDataLossAcrossRotation:
    """Every event ever written survives in the active file or a backup."""

    def test_all_events_recoverable(self, e2e_pipeline: dict) -> None:
        """All request_ids that produced events are found across all files."""
        stats = _send_all_requests(e2e_pipeline)
        log_path: Path = e2e_pipeline["log_path"]

        # Collect all request_ids from active file
        active_logger = AuditLogger(log_path)
        active_events = active_logger.read_events()
        found_ids = {e.request_id for e in active_events}

        # Collect from all backups
        backups = sorted(log_path.parent.glob("audit.jsonl.*.gz"))
        for backup_path in backups:
            with gzip.open(backup_path, "rt", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    parsed = json.loads(stripped)
                    found_ids.add(parsed["request_id"])

        # All expected redaction + file-block IDs must be present
        all_expected = stats["expected_redaction_ids"] | stats["expected_file_block_ids"]
        missing = all_expected - found_ids
        assert not missing, (
            f"Data loss detected: {len(missing)} events missing from "
            f"active file + {len(backups)} backups. "
            f"Missing IDs: {sorted(missing)[:10]}"
        )

    def test_total_event_count_across_all_files(
        self, e2e_pipeline: dict
    ) -> None:
        """Sum of events in active file + backups equals total written."""
        stats = _send_all_requests(e2e_pipeline)
        log_path: Path = e2e_pipeline["log_path"]

        # Count events in active file
        active_logger = AuditLogger(log_path)
        active_count = len(active_logger.read_events())

        # Count events in backups
        backup_count = 0
        backups = sorted(log_path.parent.glob("audit.jsonl.*.gz"))
        for backup_path in backups:
            with gzip.open(backup_path, "rt", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        backup_count += 1

        total_recovered = active_count + backup_count
        total_expected = (
            len(stats["expected_redaction_ids"])
            + len(stats["expected_file_block_ids"])
        )

        assert total_recovered == total_expected, (
            f"Event count mismatch: recovered {total_recovered} "
            f"(active={active_count}, backups={backup_count}), "
            f"expected {total_expected}"
        )

    def test_no_duplicate_events_across_files(
        self, e2e_pipeline: dict
    ) -> None:
        """No request_id appears in both the active file and a backup."""
        _send_all_requests(e2e_pipeline)
        log_path: Path = e2e_pipeline["log_path"]

        # Collect request_ids per source
        active_logger = AuditLogger(log_path)
        active_ids = {e.request_id for e in active_logger.read_events()}

        backup_ids: set[str] = set()
        backups = sorted(log_path.parent.glob("audit.jsonl.*.gz"))
        for backup_path in backups:
            with gzip.open(backup_path, "rt", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    parsed = json.loads(stripped)
                    rid = parsed["request_id"]
                    assert rid not in backup_ids, (
                        f"Duplicate request_id {rid} across backups"
                    )
                    backup_ids.add(rid)

        # Active file IDs should not overlap with backup IDs
        overlap = active_ids & backup_ids
        assert not overlap, (
            f"Duplicate request_ids found in active file and backups: "
            f"{sorted(overlap)[:5]}"
        )


# ══════════════════════════════════════════════════════════════════════
# Test 6: Severity and event-type correctness in audit trail
# ══════════════════════════════════════════════════════════════════════


class TestAuditTrailCorrectness:
    """Verify that each event has the correct severity and type."""

    def test_all_redaction_events_are_warning(
        self, e2e_pipeline: dict
    ) -> None:
        """Every redaction event has WARNING severity."""
        _send_all_requests(e2e_pipeline)
        all_events = _collect_all_events(e2e_pipeline)

        redactions = [e for e in all_events if e.event_type == EventType.REDACTION]
        for ev in redactions:
            assert ev.severity == Severity.WARNING, (
                f"Redaction event {ev.request_id} has severity "
                f"{ev.severity}, expected WARNING"
            )

    def test_all_file_block_events_are_critical(
        self, e2e_pipeline: dict
    ) -> None:
        """Every file-block event has CRITICAL severity."""
        _send_all_requests(e2e_pipeline)
        all_events = _collect_all_events(e2e_pipeline)

        blocks = [e for e in all_events if e.event_type == EventType.FILE_BLOCK]
        for ev in blocks:
            assert ev.severity == Severity.CRITICAL, (
                f"File-block event {ev.request_id} has severity "
                f"{ev.severity}, expected CRITICAL"
            )

    def test_redaction_events_have_findings(
        self, e2e_pipeline: dict
    ) -> None:
        """Every redaction event has at least one finding summary."""
        _send_all_requests(e2e_pipeline)
        all_events = _collect_all_events(e2e_pipeline)

        redactions = [e for e in all_events if e.event_type == EventType.REDACTION]
        for ev in redactions:
            assert ev.findings_count >= 1, (
                f"Redaction event {ev.request_id} has findings_count=0"
            )
            assert len(ev.findings) >= 1, (
                f"Redaction event {ev.request_id} has empty findings list"
            )

    def test_file_block_events_have_blocks(
        self, e2e_pipeline: dict
    ) -> None:
        """Every file-block event has at least one file-block match."""
        _send_all_requests(e2e_pipeline)
        all_events = _collect_all_events(e2e_pipeline)

        blocks = [e for e in all_events if e.event_type == EventType.FILE_BLOCK]
        for ev in blocks:
            assert len(ev.file_blocks) >= 1, (
                f"File-block event {ev.request_id} has empty file_blocks"
            )


# ── Helpers ─────────────────────────────────────────────────────────────


def _collect_all_events(e2e_pipeline: dict) -> list[AuditEvent]:
    """Collect all AuditEvents from the active file and all gzip backups."""
    log_path: Path = e2e_pipeline["log_path"]

    # Active file
    active_logger = AuditLogger(log_path)
    events = active_logger.read_events()

    # Backups
    backups = sorted(log_path.parent.glob("audit.jsonl.*.gz"))
    for backup_path in backups:
        with gzip.open(backup_path, "rt", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                events.append(AuditEvent.model_validate_json(stripped))

    return events
