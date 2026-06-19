"""Unit tests for acf.audit.logger — AuditLogger."""

from __future__ import annotations

import gzip
import json
import threading
import time
from pathlib import Path

import pytest

from acf.audit.logger import AuditLogger
from acf.models.types import (
    AuditEvent,
    EventType,
    FileBlockMatch,
    FindingSummary,
    MatchType,
    Severity,
)


# ── helpers ────────────────────────────────────────────────────────────


@pytest.fixture
def log_path(tmp_path: Path) -> Path:
    """Return a temporary path for the JSONL log file."""
    return tmp_path / "audit.jsonl"


@pytest.fixture
def logger(log_path: Path) -> AuditLogger:
    """Return an AuditLogger instance pointed at the temp path."""
    return AuditLogger(log_path)


# ── 1. JSONL write creates file ───────────────────────────────────────


class TestJsonlFileCreation:
    """Verify that logging an event actually produces a file on disk."""

    def test_write_creates_file(self, logger: AuditLogger, log_path: Path) -> None:
        event = AuditEvent(
            timestamp="2026-06-19T12:00:00Z",
            url="/v1/chat/completions",
            severity=Severity.INFO,
            event_type=EventType.PASS,
        )
        assert not log_path.exists()
        logger.log_event(event)
        assert log_path.exists()
        assert log_path.stat().st_size > 0

    def test_append_to_existing_file(
        self, logger: AuditLogger, log_path: Path
    ) -> None:
        event = AuditEvent(
            timestamp="2026-06-19T12:00:00Z",
            url="/v1/chat",
            severity=Severity.INFO,
            event_type=EventType.PASS,
        )
        logger.log_event(event)
        size_before = log_path.stat().st_size

        logger.log_event(event)
        size_after = log_path.stat().st_size
        assert size_after > size_before

        lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2


# ── 2. CRITICAL file-block event ──────────────────────────────────────


class TestCriticalFileBlock:
    def test_log_file_block(self, logger: AuditLogger, log_path: Path) -> None:
        matches = [
            FileBlockMatch(
                rule_type=MatchType.EXTENSION, matched_value=".env", position=0
            ),
        ]
        logger.log_file_block(
            url="/v1/chat/completions",
            matches=matches,
            client_ip="10.0.0.1",
            request_id="req-001",
        )

        events = logger.read_events()
        assert len(events) == 1
        ev = events[0]
        assert ev.severity == Severity.CRITICAL
        assert ev.event_type == EventType.FILE_BLOCK
        assert ev.url == "/v1/chat/completions"
        assert ev.client_ip == "10.0.0.1"
        assert ev.request_id == "req-001"
        assert ev.findings_count == 0
        assert ev.findings == []
        assert len(ev.file_blocks) == 1
        assert ev.file_blocks[0].matched_value == ".env"

    def test_log_file_block_with_no_matches(
        self, logger: AuditLogger, log_path: Path
    ) -> None:
        logger.log_file_block(url="/api/upload", matches=[])
        events = logger.read_events()
        assert len(events) == 1
        assert events[0].file_blocks == []


# ── 3. WARNING redaction event ────────────────────────────────────────


class TestWarningRedaction:
    def test_log_redaction(self, logger: AuditLogger, log_path: Path) -> None:
        findings = [
            FindingSummary(type="api_key", confidence="HIGH", length=32),
            FindingSummary(type="jwt", confidence="MEDIUM", length=64),
        ]
        logger.log_redaction(
            url="/v1/chat/completions",
            findings=findings,
            client_ip="192.168.1.100",
            request_id="req-002",
        )

        events = logger.read_events()
        assert len(events) == 1
        ev = events[0]
        assert ev.severity == Severity.WARNING
        assert ev.event_type == EventType.REDACTION
        assert ev.url == "/v1/chat/completions"
        assert ev.client_ip == "192.168.1.100"
        assert ev.request_id == "req-002"
        assert ev.findings_count == 2
        assert len(ev.findings) == 2
        assert ev.findings[0].type == "api_key"
        assert ev.findings[1].type == "jwt"

    def test_log_redaction_with_no_findings(
        self, logger: AuditLogger, log_path: Path
    ) -> None:
        logger.log_redaction(url="/api/validate", findings=[])
        events = logger.read_events()
        assert len(events) == 1
        assert events[0].findings == []
        assert events[0].findings_count == 0


# ── 4. INFO pass event ────────────────────────────────────────────────


class TestInfoPass:
    def test_info_pass_direct(
        self, logger: AuditLogger, log_path: Path
    ) -> None:
        event = AuditEvent(
            timestamp="2026-06-19T14:00:00Z",
            url="/v1/chat/completions",
            severity=Severity.INFO,
            event_type=EventType.PASS,
        )
        logger.log_event(event)
        events = logger.read_events()
        assert len(events) == 1
        assert events[0].severity == Severity.INFO
        assert events[0].event_type == EventType.PASS


# ── 5. Read back and parse valid JSON ─────────────────────────────────


class TestReadBack:
    def test_read_back_multiple_events(self, logger: AuditLogger, log_path: Path) -> None:
        logger.log_file_block(
            url="/api/file",
            matches=[FileBlockMatch(
                rule_type=MatchType.EXTENSION, matched_value=".pem", position=0
            )],
        )
        logger.log_redaction(
            url="/api/chat",
            findings=[FindingSummary(type="secret", confidence="HIGH", length=16)],
        )

        events = logger.read_events()
        assert len(events) == 2
        assert events[0].event_type == EventType.FILE_BLOCK
        assert events[1].event_type == EventType.REDACTION

    def test_each_line_is_valid_json(self, logger: AuditLogger, log_path: Path) -> None:
        event = AuditEvent(
            timestamp="2026-06-19T15:00:00Z",
            url="/api/test",
            severity=Severity.INFO,
            event_type=EventType.PASS,
            source="unit-test",
        )
        logger.log_event(event)

        with open(log_path, encoding="utf-8") as f:
            for line in f:
                parsed = json.loads(line.strip())
                assert parsed["event_type"] == "pass"
                assert parsed["severity"] == "INFO"
                assert parsed["source"] == "unit-test"

    def test_log_event_preserves_all_fields(
        self, logger: AuditLogger, log_path: Path
    ) -> None:
        event = AuditEvent(
            timestamp="2026-06-19T16:00:00Z",
            url="/api/upload",
            severity=Severity.CRITICAL,
            event_type=EventType.FILE_BLOCK,
            source="mitmproxy",
            findings_count=1,
            findings=[FindingSummary(type="private_key", confidence="HIGH", length=64)],
            file_blocks=[
                FileBlockMatch(
                    rule_type=MatchType.PATH, matched_value="/etc/secret", position=42
                ),
            ],
            client_ip="10.0.0.50",
            request_id="req-003",
        )
        logger.log_event(event)

        events = logger.read_events()
        assert len(events) == 1
        ev = events[0]
        assert ev.timestamp == "2026-06-19T16:00:00Z"
        assert ev.url == "/api/upload"
        assert ev.severity == Severity.CRITICAL
        assert ev.event_type == EventType.FILE_BLOCK
        assert ev.source == "mitmproxy"
        assert ev.findings_count == 1
        assert len(ev.findings) == 1
        assert ev.findings[0].type == "private_key"
        assert ev.findings[0].confidence == "HIGH"
        assert ev.findings[0].length == 64
        assert len(ev.file_blocks) == 1
        assert ev.file_blocks[0].rule_type == MatchType.PATH
        assert ev.file_blocks[0].matched_value == "/etc/secret"
        assert ev.file_blocks[0].position == 42
        assert ev.client_ip == "10.0.0.50"
        assert ev.request_id == "req-003"


# ── 6. Atomic append (no partial writes) ──────────────────────────────


class TestAtomicAppend:
    def test_write_is_single_line(self, logger: AuditLogger, log_path: Path) -> None:
        """Each log_event produces exactly one line (one \\n)."""
        event = AuditEvent(
            timestamp="2026-06-19T17:00:00Z",
            url="/v1/chat/completions",
            severity=Severity.INFO,
            event_type=EventType.PASS,
        )
        logger.log_event(event)

        raw = log_path.read_bytes()
        # Exactly one newline at the end
        assert raw.count(b"\n") == 1
        assert raw.endswith(b"\n")

    def test_consecutive_writes_produce_separate_lines(
        self, logger: AuditLogger, log_path: Path
    ) -> None:
        for i in range(5):
            event = AuditEvent(
                timestamp=f"2026-06-19T17:0{i}:00Z",
                url=f"/api/endpoint/{i}",
                severity=Severity.INFO,
                event_type=EventType.PASS,
                request_id=f"req-{i:03d}",
            )
            logger.log_event(event)

        lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 5
        for i, line in enumerate(lines):
            parsed = json.loads(line)
            assert parsed["request_id"] == f"req-{i:03d}"


# ── 7. Malformed recovery (skip corrupt line) ─────────────────────────


class TestMalformedRecovery:
    def test_skip_corrupt_line(self, logger: AuditLogger, log_path: Path) -> None:
        """Corrupt JSON lines are skipped; valid lines are still returned."""
        # Manually inject a corrupt line then a valid one
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("not valid json\n")
        event = AuditEvent(
            timestamp="2026-06-19T18:00:00Z",
            url="/api/clean",
            severity=Severity.INFO,
            event_type=EventType.PASS,
        )
        logger.log_event(event)

        events = logger.read_events()
        assert len(events) == 1
        assert events[0].url == "/api/clean"

    def test_skip_empty_lines(self, logger: AuditLogger, log_path: Path) -> None:
        """Blank lines between entries are ignored."""
        raw = (
            '{"timestamp":"T1","url":"/a","severity":"INFO","event_type":"pass","source":"proxy","findings_count":0,"findings":[],"file_blocks":[],"client_ip":"","request_id":""}\n'
            "\n"
            "\n"
            '{"timestamp":"T2","url":"/b","severity":"INFO","event_type":"pass","source":"proxy","findings_count":0,"findings":[],"file_blocks":[],"client_ip":"","request_id":""}\n'
        )
        log_path.write_text(raw, encoding="utf-8")

        events = logger.read_events()
        assert len(events) == 2

    def test_skip_partial_line_at_end(
        self, logger: AuditLogger, log_path: Path
    ) -> None:
        """A line without trailing newline is still parsed."""
        log_path.write_text(
            '{"timestamp":"T1","url":"/a","severity":"INFO","event_type":"pass","source":"proxy","findings_count":0,"findings":[],"file_blocks":[],"client_ip":"","request_id":""}',
            encoding="utf-8",
        )
        events = logger.read_events()
        assert len(events) == 1


# ── 8. Concurrent write safety ────────────────────────────────────────


class TestConcurrentWriteSafety:
    def test_concurrent_writes_all_lines_valid(
        self, log_path: Path
    ) -> None:
        """Multiple threads writing concurrently produce only valid JSON."""
        logger = AuditLogger(log_path)
        n_threads = 8
        events_per_thread = 25
        barrier = threading.Barrier(n_threads)

        def _writer(thread_id: int) -> None:
            barrier.wait()  # synchronised start
            for i in range(events_per_thread):
                ev = AuditEvent(
                    timestamp=f"2026-06-19T{i:04d}Z",
                    url=f"/api/thread-{thread_id}/event-{i}",
                    severity=Severity.INFO,
                    event_type=EventType.PASS,
                    request_id=f"t{thread_id}-e{i}",
                )
                logger.log_event(ev)

        threads = [
            threading.Thread(target=_writer, args=(tid,))
            for tid in range(n_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Every line must parse as valid JSON and be a valid AuditEvent
        events = logger.read_events()
        total_expected = n_threads * events_per_thread
        assert len(events) == total_expected, (
            f"Expected {total_expected} events, got {len(events)}"
        )

        request_ids = {ev.request_id for ev in events}
        assert len(request_ids) == total_expected, "Duplicate request_ids found"

    def test_read_while_writing(self, log_path: Path) -> None:
        """Concurrent readers always see complete lines."""
        logger = AuditLogger(log_path)
        stop_event = threading.Event()

        def _writer() -> None:
            i = 0
            while not stop_event.is_set():
                ev = AuditEvent(
                    timestamp=f"2026-06-19T{i:05d}Z",
                    url=f"/api/write-test/{i}",
                    severity=Severity.INFO,
                    event_type=EventType.PASS,
                )
                logger.log_event(ev)
                i += 1

        writer = threading.Thread(target=_writer, daemon=True)
        writer.start()

        # Read a few times while writer is active
        for _ in range(10):
            events = logger.read_events()
            # All returned lines must be valid — no JSON decode errors
            assert all(isinstance(e, AuditEvent) for e in events)
            time.sleep(0.01)

        stop_event.set()
        writer.join(timeout=2)

    def test_concurrent_unique_events(
        self, log_path: Path
    ) -> None:
        """Two loggers writing to the same file interleave safely."""
        logger_a = AuditLogger(log_path)
        logger_b = AuditLogger(log_path)

        barrier = threading.Barrier(2)

        def _write_a() -> None:
            barrier.wait()
            for i in range(50):
                logger_a.log_file_block(
                    url="/api/a",
                    matches=[FileBlockMatch(
                        rule_type=MatchType.EXTENSION, matched_value=f".ext-{i}", position=i
                    )],
                )

        def _write_b() -> None:
            barrier.wait()
            for i in range(50):
                logger_b.log_redaction(
                    url="/api/b",
                    findings=[FindingSummary(type=f"secret-{i}", confidence="HIGH", length=i)],
                )

        ta = threading.Thread(target=_write_a)
        tb = threading.Thread(target=_write_b)
        ta.start()
        tb.start()
        ta.join()
        tb.join()

        events = logger_a.read_events()
        assert len(events) == 100
        file_blocks = [e for e in events if e.event_type == EventType.FILE_BLOCK]
        redactions = [e for e in events if e.event_type == EventType.REDACTION]
        assert len(file_blocks) == 50
        assert len(redactions) == 50


# ── 9. Edge cases ─────────────────────────────────────────────────────


class TestEdgeCases:
    def test_read_events_nonexistent_file(
        self, logger: AuditLogger, log_path: Path
    ) -> None:
        """read_events on a non-existent path returns empty list."""
        assert not log_path.exists()
        assert logger.read_events() == []

    def test_empty_log_file(self, logger: AuditLogger, log_path: Path) -> None:
        """An empty file returns an empty list."""
        log_path.touch()
        assert logger.read_events() == []

    def test_log_event_with_minimal_fields(
        self, logger: AuditLogger, log_path: Path
    ) -> None:
        """An event with only required fields can be written and read."""
        event = AuditEvent(
            timestamp="2026-06-19T19:00:00Z",
            url="/health",
            severity=Severity.INFO,
            event_type=EventType.PASS,
        )
        logger.log_event(event)
        events = logger.read_events()
        assert len(events) == 1
        assert events[0].source == "proxy"  # default
        assert events[0].findings == []
        assert events[0].file_blocks == []

    def test_multiple_event_types_interleaved(
        self, logger: AuditLogger, log_path: Path
    ) -> None:
        """Logging different event types in sequence preserves order."""
        logger.log_file_block(
            url="/api/1",
            matches=[FileBlockMatch(
                rule_type=MatchType.EXTENSION, matched_value=".env", position=0
            )],
        )
        logger.log_redaction(
            url="/api/2",
            findings=[FindingSummary(type="key", confidence="HIGH", length=8)],
        )
        pass_event = AuditEvent(
            timestamp="2026-06-19T20:00:00Z",
            url="/api/3",
            severity=Severity.INFO,
            event_type=EventType.PASS,
        )
        logger.log_event(pass_event)

        events = logger.read_events()
        assert len(events) == 3
        assert events[0].event_type == EventType.FILE_BLOCK
        assert events[1].event_type == EventType.REDACTION
        assert events[2].event_type == EventType.PASS


# ── 10. Log rotation ───────────────────────────────────────────────────


class TestLogRotation:
    """Automatic log rotation with gzip-compressed backups."""

    def test_rotation_creates_gz_backup(self, tmp_path: Path) -> None:
        """When file exceeds max_file_size, a .1.gz backup is created."""
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path, max_file_size=10)

        event = AuditEvent(
            timestamp="2026-06-19T12:00:00Z",
            url="/v1/chat/completions",
            severity=Severity.INFO,
            event_type=EventType.PASS,
        )
        logger.log_event(event)

        backup = log_path.with_suffix(".1.gz")
        assert backup.exists(), f"Expected {backup} to exist"
        assert backup.stat().st_size > 0, "Backup must contain compressed data"

    def test_no_rotation_below_max_file_size(self, tmp_path: Path) -> None:
        """No backup is created when the file is under max_file_size."""
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path, max_file_size=10_000_000)

        event = AuditEvent(
            timestamp="2026-06-19T12:00:00Z",
            url="/v1/chat",
            severity=Severity.INFO,
            event_type=EventType.PASS,
        )
        logger.log_event(event)

        assert not (log_path.with_suffix(".1.gz")).exists()
        events = logger.read_events()
        assert len(events) == 1
        assert events[0].url == "/v1/chat"

    def test_backup_contains_original_data(self, tmp_path: Path) -> None:
        """The compressed backup preserves the exact pre-rotation content."""
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path, max_file_size=10)

        event = AuditEvent(
            timestamp="2026-06-19T12:00:00Z",
            url="/v1/chat/completions",
            severity=Severity.INFO,
            event_type=EventType.PASS,
            request_id="req-before-rotate",
        )
        logger.log_event(event)

        backup = log_path.with_suffix(".1.gz")
        assert backup.exists()

        with gzip.open(backup, "rt", encoding="utf-8") as f:
            content = f.read()
        parsed = json.loads(content.strip())
        assert parsed["request_id"] == "req-before-rotate"
        assert parsed["url"] == "/v1/chat/completions"

    def test_no_data_loss_across_rotation(self, tmp_path: Path) -> None:
        """All events ever written survive in current file or compressed backups."""
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path, max_file_size=50, max_backup_count=5)

        written_ids: set[str] = set()
        for i in range(10):
            rid = f"rid-{i:04d}"
            written_ids.add(rid)
            event = AuditEvent(
                timestamp=f"2026-06-19T{i:04d}Z",
                url=f"/api/{i}",
                severity=Severity.INFO,
                event_type=EventType.PASS,
                request_id=rid,
            )
            logger.log_event(event)

        # Collect all request_ids from the current file AND all backups
        found_ids: set[str] = set()
        for ev in logger.read_events():
            found_ids.add(ev.request_id)

        for backup in sorted(log_path.parent.glob("audit.jsonl.*.gz")):
            with gzip.open(backup, "rt", encoding="utf-8") as f:
                for line in f:
                    if stripped := line.strip():
                        parsed = json.loads(stripped)
                        found_ids.add(parsed["request_id"])

        missing = written_ids - found_ids
        assert not missing, f"Events missing from all files: {missing}"
        assert len(found_ids) >= len(written_ids)

    def test_backup_files_shift_on_subsequent_rotation(
        self, tmp_path: Path
    ) -> None:
        """After multiple rotations backup numbering shifts correctly."""
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path, max_file_size=10, max_backup_count=3)

        for i in range(15):
            event = AuditEvent(
                timestamp=f"2026-06-19T{i:04d}Z",
                url=f"/api/test/{i}",
                severity=Severity.INFO,
                event_type=EventType.PASS,
                request_id=f"req-{i}",
            )
            logger.log_event(event)

        # At most 3 backups (max_backup_count=3)
        backups = sorted(log_path.parent.glob("audit.jsonl.*.gz"))
        assert len(backups) <= 3, f"Expected ≤3 backups, got {len(backups)}"

        # All events still findable somewhere
        found_ids: set[str] = set()
        for ev in logger.read_events():
            found_ids.add(ev.request_id)
        for backup in backups:
            with gzip.open(backup, "rt", encoding="utf-8") as f:
                for line in f:
                    if stripped := line.strip():
                        found_ids.add(json.loads(stripped)["request_id"])
        assert len(found_ids) == 15, f"Only found {len(found_ids)}/15 events"

    def test_oldest_backup_removed_when_exceeding_max_backup_count(
        self, tmp_path: Path
    ) -> None:
        """Old backups beyond max_backup_count are removed."""
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path, max_file_size=10, max_backup_count=2)

        for i in range(30):
            event = AuditEvent(
                timestamp=f"2026-06-19T{i:04d}Z",
                url=f"/api/{i}",
                severity=Severity.INFO,
                event_type=EventType.PASS,
            )
            logger.log_event(event)

        backups = sorted(log_path.parent.glob("audit.jsonl.*.gz"))
        assert len(backups) <= 2, f"Expected ≤2 backups, got {len(backups)}"

        # Ensure no .3.gz exists (it shouldn't)
        assert not (log_path.with_suffix(".3.gz")).exists()
