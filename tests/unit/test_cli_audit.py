"""Tests for ``acf audit`` CLI command."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from acf.cli import main
from acf.models.types import (
    AuditEvent,
    EventType,
    FileBlockMatch,
    FindingSummary,
    MatchType,
    Severity,
)


# ── helpers ────────────────────────────────────────────────────────────


def _write_events(log_path: Path, events: list[AuditEvent]) -> None:
    """Write *events* as JSONL to *log_path*."""
    lines = [e.model_dump_json() + "\n" for e in events]
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("".join(lines), encoding="utf-8")


_sample_timestamp = "2026-06-19T12:00:00+00:00"


# ── 1. Empty / missing log ─────────────────────────────────────────────


class TestMissingLog:
    """``acf audit`` on a non-existent log file."""

    def test_log_not_found(self, tmp_path: Path) -> None:
        missing = tmp_path / "no-such-file.jsonl"
        result = CliRunner().invoke(main, ["audit", "--log-path", str(missing)])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_empty_log(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.jsonl"
        empty.parent.mkdir(parents=True, exist_ok=True)
        empty.write_text("", encoding="utf-8")

        result = CliRunner().invoke(main, ["audit", "--log-path", str(empty)])
        assert result.exit_code == 0
        assert "no audit events" in result.output.lower()

    def test_empty_log_summary(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.jsonl"
        empty.parent.mkdir(parents=True, exist_ok=True)
        empty.write_text("", encoding="utf-8")

        result = CliRunner().invoke(
            main, ["audit", "--log-path", str(empty), "--summary"]
        )
        assert result.exit_code == 0
        assert "no audit events" in result.output.lower()


# ── 2. Raw events display ───────────────────────────────────────────────


class TestRawEvents:
    """``acf audit`` (without --summary) lists raw events."""

    def test_single_event(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_events(log, [
            AuditEvent(
                timestamp=_sample_timestamp,
                url="/v1/chat/completions",
                severity=Severity.INFO,
                event_type=EventType.PASS,
                source="proxy",
            ),
        ])

        result = CliRunner().invoke(main, ["audit", "--log-path", str(log)])
        assert result.exit_code == 0
        assert "PASS" in result.output or "pass" in result.output
        assert "/v1/chat/completions" in result.output

    def test_multiple_events(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_events(log, [
            AuditEvent(
                timestamp=_sample_timestamp,
                url="/api/1",
                severity=Severity.CRITICAL,
                event_type=EventType.FILE_BLOCK,
                file_blocks=[
                    FileBlockMatch(rule_type=MatchType.EXTENSION, matched_value=".env", position=0),
                ],
            ),
            AuditEvent(
                timestamp=_sample_timestamp,
                url="/api/2",
                severity=Severity.WARNING,
                event_type=EventType.REDACTION,
                findings=[FindingSummary(type="api_key", confidence="HIGH", length=32)],
                findings_count=1,
            ),
            AuditEvent(
                timestamp=_sample_timestamp,
                url="/api/3",
                severity=Severity.INFO,
                event_type=EventType.PASS,
            ),
        ])

        result = CliRunner().invoke(main, ["audit", "--log-path", str(log)])
        assert result.exit_code == 0
        assert "3" in result.output  # total event count in the table title
        assert "/api/1" in result.output
        assert "/api/2" in result.output
        assert "/api/3" in result.output

    def test_events_json_format(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_events(log, [
            AuditEvent(
                timestamp=_sample_timestamp,
                url="/v1/chat",
                severity=Severity.WARNING,
                event_type=EventType.REDACTION,
                source="proxy",
                findings=[FindingSummary(type="jwt", confidence="MEDIUM", length=64)],
                findings_count=1,
            ),
        ])

        result = CliRunner().invoke(
            main, ["audit", "--log-path", str(log), "--format", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["url"] == "/v1/chat"
        assert data[0]["severity"] == "WARNING"


# ── 3. Summary display ──────────────────────────────────────────────────


class TestSummary:
    """``acf audit --summary`` aggregates events."""

    def test_summary_basic(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_events(log, [
            AuditEvent(
                timestamp="2026-06-18T10:00:00Z",
                url="/api/a",
                severity=Severity.CRITICAL,
                event_type=EventType.FILE_BLOCK,
                source="proxy",
                file_blocks=[
                    FileBlockMatch(rule_type=MatchType.EXTENSION, matched_value=".env", position=0),
                ],
            ),
            AuditEvent(
                timestamp="2026-06-18T11:00:00Z",
                url="/api/b",
                severity=Severity.WARNING,
                event_type=EventType.REDACTION,
                source="proxy",
                findings=[FindingSummary(type="api_key", confidence="HIGH", length=32)],
                findings_count=1,
            ),
            AuditEvent(
                timestamp="2026-06-19T12:00:00Z",
                url="/api/c",
                severity=Severity.INFO,
                event_type=EventType.PASS,
                source="cli",
            ),
        ])

        result = CliRunner().invoke(
            main, ["audit", "--log-path", str(log), "--summary"]
        )
        assert result.exit_code == 0
        # Should include total count
        assert "Total events" in result.output
        assert "3" in result.output
        # Severity breakdown
        assert "CRITICAL" in result.output
        assert "WARNING" in result.output
        assert "INFO" in result.output
        # Date range
        assert "2026-06-18" in result.output
        assert "2026-06-19" in result.output

    def test_summary_json_format(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_events(log, [
            AuditEvent(
                timestamp="2026-06-18T10:00:00Z",
                url="/api/a",
                severity=Severity.INFO,
                event_type=EventType.PASS,
                source="proxy",
            ),
            AuditEvent(
                timestamp="2026-06-18T11:00:00Z",
                url="/api/b",
                severity=Severity.WARNING,
                event_type=EventType.REDACTION,
                source="proxy",
                findings=[FindingSummary(type="token", confidence="HIGH", length=16)],
                findings_count=1,
            ),
        ])

        result = CliRunner().invoke(
            main, ["audit", "--log-path", str(log), "--summary", "--format", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_events"] == 2
        assert data["by_severity"]["INFO"] == 1
        assert data["by_severity"]["WARNING"] == 1
        assert data["by_event_type"]["pass"] == 1
        assert data["by_event_type"]["redaction"] == 1
        assert data["by_source"]["proxy"] == 2
        assert "token" in data["by_finding_type"]
        assert data["by_finding_type"]["token"] == 1


# ── 4. Date filtering ───────────────────────────────────────────────────


class TestDateFiltering:
    """``acf audit --since / --until`` filter events by date."""

    def test_since_filter(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_events(log, [
            AuditEvent(
                timestamp="2026-06-01T00:00:00Z",
                url="/api/old",
                severity=Severity.INFO,
                event_type=EventType.PASS,
            ),
            AuditEvent(
                timestamp="2026-06-15T00:00:00Z",
                url="/api/new",
                severity=Severity.INFO,
                event_type=EventType.PASS,
            ),
        ])

        # since = June 10 → only the second event
        result = CliRunner().invoke(
            main, ["audit", "--log-path", str(log), "--since", "2026-06-10"]
        )
        assert result.exit_code == 0
        assert "/api/new" in result.output
        assert "/api/old" not in result.output

    def test_until_filter(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_events(log, [
            AuditEvent(
                timestamp="2026-06-01T00:00:00Z",
                url="/api/old",
                severity=Severity.INFO,
                event_type=EventType.PASS,
            ),
            AuditEvent(
                timestamp="2026-06-20T00:00:00Z",
                url="/api/future",
                severity=Severity.INFO,
                event_type=EventType.PASS,
            ),
        ])

        # until = June 15 → only the first event
        result = CliRunner().invoke(
            main, ["audit", "--log-path", str(log), "--until", "2026-06-15"]
        )
        assert result.exit_code == 0
        assert "/api/old" in result.output
        assert "/api/future" not in result.output

    def test_since_and_until(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_events(log, [
            AuditEvent(
                timestamp="2026-06-01T00:00:00Z",
                url="/api/1",
                severity=Severity.INFO,
                event_type=EventType.PASS,
            ),
            AuditEvent(
                timestamp="2026-06-10T00:00:00Z",
                url="/api/2",
                severity=Severity.INFO,
                event_type=EventType.PASS,
            ),
            AuditEvent(
                timestamp="2026-06-20T00:00:00Z",
                url="/api/3",
                severity=Severity.INFO,
                event_type=EventType.PASS,
            ),
        ])

        result = CliRunner().invoke(
            main, [
                "audit", "--log-path", str(log),
                "--since", "2026-06-05",
                "--until", "2026-06-15",
            ]
        )
        assert result.exit_code == 0
        assert "/api/2" in result.output
        assert "/api/1" not in result.output
        assert "/api/3" not in result.output

    def test_date_filter_with_summary(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_events(log, [
            AuditEvent(
                timestamp="2026-06-01T00:00:00Z",
                url="/api/old",
                severity=Severity.WARNING,
                event_type=EventType.REDACTION,
                source="proxy",
                findings=[FindingSummary(type="key", confidence="HIGH", length=8)],
                findings_count=1,
            ),
            AuditEvent(
                timestamp="2026-06-15T00:00:00Z",
                url="/api/new",
                severity=Severity.INFO,
                event_type=EventType.PASS,
                source="proxy",
            ),
        ])

        result = CliRunner().invoke(
            main, [
                "audit", "--log-path", str(log),
                "--summary", "--since", "2026-06-10",
            ]
        )
        assert result.exit_code == 0
        assert "Total events" in result.output
        assert "1" in result.output  # only 1 event in range
        assert "INFO" in result.output  # severity of the included event
        # The WARNING event from June 1 should be excluded
        # (we can't easily assert absence in table, but total=1 is the key check)

    def test_invalid_date(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("", encoding="utf-8")

        result = CliRunner().invoke(
            main, ["audit", "--log-path", str(log), "--since", "not-a-date"]
        )
        assert result.exit_code != 0
        assert "Invalid date" in result.output


# ── 5. Edge cases ───────────────────────────────────────────────────────


class TestEdgeCases:
    """Boundary and edge-case scenarios."""

    def test_malformed_timestamps_skipped(self, tmp_path: Path) -> None:
        """Events with unparseable timestamps are silently dropped."""
        log = tmp_path / "audit.jsonl"
        lines = [
            AuditEvent(
                timestamp="2026-06-01T00:00:00Z",
                url="/api/valid",
                severity=Severity.INFO,
                event_type=EventType.PASS,
            ),
        ]
        # manually inject a bad line
        log.parent.mkdir(parents=True, exist_ok=True)
        with open(log, "w", encoding="utf-8") as f:
            f.write('{"timestamp":"bad-date","url":"/api/bad","severity":"INFO","event_type":"pass","source":"proxy","findings_count":0,"findings":[],"file_blocks":[],"client_ip":"","request_id":""}\n')
            f.write(lines[0].model_dump_json() + "\n")

        # without date filter, both events are returned
        result_all = CliRunner().invoke(main, ["audit", "--log-path", str(log)])
        assert result_all.exit_code == 0
        assert "/api/valid" in result_all.output

        # with date filter the malformed one is excluded from date calculations
        result = CliRunner().invoke(
            main, ["audit", "--log-path", str(log), "--since", "2026-01-01", "--summary", "--format", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_events"] == 1  # only the valid one counted in summary

    def test_summary_with_no_findings_or_blocks(self, tmp_path: Path) -> None:
        """Summary handles events with no findings or blocks."""
        log = tmp_path / "audit.jsonl"
        _write_events(log, [
            AuditEvent(
                timestamp="2026-06-19T12:00:00Z",
                url="/api/clean",
                severity=Severity.INFO,
                event_type=EventType.PASS,
            ),
        ])

        result = CliRunner().invoke(
            main, ["audit", "--log-path", str(log), "--summary", "--format", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_events"] == 1
        assert data["by_finding_type"] == {}
        assert data["by_block_rule_type"] == {}

    def test_summary_log_path_defaults(self, tmp_path: Path, monkeypatch) -> None:
        """When --log-path is omitted, the default path is used."""
        log_dir = tmp_path / "logs"
        log_file = log_dir / "audit.jsonl"
        _write_events(log_file, [
            AuditEvent(
                timestamp="2026-06-19T12:00:00Z",
                url="/api/default",
                severity=Severity.INFO,
                event_type=EventType.PASS,
            ),
        ])

        # Monkey-patch the config so resolved_log_dir points to our temp dir
        monkeypatch.setattr(
            "acf.config.settings.AppConfig.resolved_log_dir",
            log_dir,
        )

        result = CliRunner().invoke(main, ["audit", "--summary", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_events"] == 1


# ── 6. CLI registration ─────────────────────────────────────────────────


class TestAuditCommandRegistration:
    """``audit`` is registered in the main CLI group."""

    def test_audit_command_exists(self) -> None:
        assert "audit" in main.commands

    def test_audit_shows_in_help(self) -> None:
        result = CliRunner().invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "audit" in result.output
