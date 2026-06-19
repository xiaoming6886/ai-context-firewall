"""Unit tests for acf.models.types."""

import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from acf.models.types import (
    AuditEvent,
    EventType,
    FileBlockMatch,
    Finding,
    FindingSummary,
    MatchType,
    RuleDefinition,
    Severity,
)


# ── 1. Severity enum values ─────────────────────────────────────────


class TestSeverityEnum:
    def test_values(self) -> None:
        assert Severity.CRITICAL == "CRITICAL"
        assert Severity.WARNING == "WARNING"
        assert Severity.INFO == "INFO"

    def test_is_string_enum(self) -> None:
        assert isinstance(Severity.CRITICAL, str)


# ── 2. EventType enum values ────────────────────────────────────────


class TestEventTypeEnum:
    def test_values(self) -> None:
        assert EventType.FILE_BLOCK == "file_block"
        assert EventType.REDACTION == "redaction"
        assert EventType.PASS == "pass"

    def test_is_string_enum(self) -> None:
        assert isinstance(EventType.FILE_BLOCK, str)


# ── 3. MatchType enum values ────────────────────────────────────────


class TestMatchTypeEnum:
    def test_values(self) -> None:
        assert MatchType.EXTENSION == "extension"
        assert MatchType.PATH == "path"
        assert MatchType.PEM_BLOCK == "pem_block"


# ── 4. Finding creation / validation ─────────────────────────────────


class TestFinding:
    def test_create_valid(self) -> None:
        f = Finding(
            secret_type="api_key",
            start=10,
            end=45,
            confidence="HIGH",
            matched_rule="generic-api-key",
        )
        assert f.secret_type == "api_key"
        assert f.start == 10
        assert f.end == 45
        assert f.confidence == "HIGH"
        assert f.matched_rule == "generic-api-key"

    def test_create_medium_confidence(self) -> None:
        f = Finding(
            secret_type="jwt",
            start=0,
            end=100,
            confidence="MEDIUM",
            matched_rule="jwt-leak",
        )
        assert f.confidence == "MEDIUM"

    def test_missing_required_fields_raises(self) -> None:
        with pytest.raises(ValidationError):
            Finding(secret_type="x", start=0, end=1)


# ── 5. FindingSummary ────────────────────────────────────────────────


class TestFindingSummary:
    def test_create(self) -> None:
        fs = FindingSummary(type="api_key", confidence="HIGH", length=32)
        assert fs.type == "api_key"
        assert fs.confidence == "HIGH"
        assert fs.length == 32


# ── 6. FileBlockMatch — extension type ───────────────────────────────


class TestFileBlockMatch:
    def test_extension_type(self) -> None:
        match = FileBlockMatch(
            rule_type=MatchType.EXTENSION,
            matched_value=".env",
            position=0,
        )
        assert match.rule_type == MatchType.EXTENSION
        assert match.matched_value == ".env"

    def test_path_type(self) -> None:
        match = FileBlockMatch(
            rule_type=MatchType.PATH,
            matched_value="/etc/shadow",
            position=15,
        )
        assert match.rule_type == MatchType.PATH

    def test_pem_block_type(self) -> None:
        match = FileBlockMatch(
            rule_type=MatchType.PEM_BLOCK,
            matched_value="-----BEGIN RSA PRIVATE KEY-----",
            position=42,
        )
        assert match.rule_type == MatchType.PEM_BLOCK


# ── 7. AuditEvent — CRITICAL file_block ──────────────────────────────


class TestAuditEvent:
    def test_critical_file_block(self) -> None:
        event = AuditEvent(
            timestamp="2026-06-19T12:00:00Z",
            url="/v1/chat/completions",
            severity=Severity.CRITICAL,
            event_type=EventType.FILE_BLOCK,
            source="proxy",
            file_blocks=[
                FileBlockMatch(
                    rule_type=MatchType.EXTENSION,
                    matched_value=".env",
                    position=0,
                )
            ],
        )
        assert event.severity == Severity.CRITICAL
        assert event.event_type == EventType.FILE_BLOCK
        assert len(event.file_blocks) == 1
        assert event.file_blocks[0].matched_value == ".env"

    def test_warning_redaction(self) -> None:
        event = AuditEvent(
            timestamp="2026-06-19T13:00:00Z",
            url="/v1/chat/completions",
            severity=Severity.WARNING,
            event_type=EventType.REDACTION,
            findings_count=2,
            findings=[
                FindingSummary(type="api_key", confidence="HIGH", length=32),
                FindingSummary(type="jwt", confidence="MEDIUM", length=64),
            ],
        )
        assert event.severity == Severity.WARNING
        assert event.event_type == EventType.REDACTION
        assert event.findings_count == 2
        assert len(event.findings) == 2
        assert event.findings[0].type == "api_key"

    def test_info_pass(self) -> None:
        event = AuditEvent(
            timestamp="2026-06-19T14:00:00Z",
            url="/v1/chat/completions",
            severity=Severity.INFO,
            event_type=EventType.PASS,
        )
        assert event.severity == Severity.INFO
        assert event.event_type == EventType.PASS
        assert event.findings_count == 0
        assert event.findings == []

    def test_default_values(self) -> None:
        event = AuditEvent(
            timestamp="2026-06-19T15:00:00Z",
            url="https://api.example.com",
            severity=Severity.INFO,
            event_type=EventType.PASS,
        )
        assert event.source == "proxy"
        assert event.findings_count == 0
        assert event.findings == []
        assert event.file_blocks == []
        assert event.client_ip == ""
        assert event.request_id == ""

    def test_custom_client_ip_and_request_id(self) -> None:
        event = AuditEvent(
            timestamp="2026-06-19T16:00:00Z",
            url="/api",
            severity=Severity.WARNING,
            event_type=EventType.REDACTION,
            client_ip="192.168.1.100",
            request_id="req-abc-123",
        )
        assert event.client_ip == "192.168.1.100"
        assert event.request_id == "req-abc-123"


# ── 8. RuleDefinition ───────────────────────────────────────────────


class TestRuleDefinition:
    def test_create_minimal(self) -> None:
        rule = RuleDefinition(
            id="rule-001",
            name="Generic API Key",
            pattern=r"[aA][pP][iI][_-]?[kK][eE][yY].*['\"][A-Za-z0-9+/]{20,}['\"]",
        )
        assert rule.id == "rule-001"
        assert rule.name == "Generic API Key"
        assert rule.secret_group == 0
        assert rule.confidence == "HIGH"
        assert rule.entropy_check is False
        assert rule.keywords == []
        assert rule.severity == Severity.WARNING
        assert rule.category == "generic"

    def test_create_full(self) -> None:
        rule = RuleDefinition(
            id="rule-002",
            name="AWS Access Key",
            pattern=r"AKIA[0-9A-Z]{16}",
            secret_group=1,
            confidence="HIGH",
            entropy_check=True,
            keywords=["aws", "amazon", "access_key"],
            severity=Severity.CRITICAL,
            category="cloud",
        )
        assert rule.secret_group == 1
        assert rule.entropy_check is True
        assert rule.keywords == ["aws", "amazon", "access_key"]
        assert rule.severity == Severity.CRITICAL
        assert rule.category == "cloud"

    def test_missing_id_raises(self) -> None:
        with pytest.raises(ValidationError):
            RuleDefinition(name="test", pattern=".*")

    def test_missing_pattern_raises(self) -> None:
        with pytest.raises(ValidationError):
            RuleDefinition(id="r1", name="test")


# ── 9. JSON serialization roundtrip ──────────────────────────────────


class TestJsonRoundtrip:
    def test_finding_roundtrip(self) -> None:
        f = Finding(
            secret_type="private_key",
            start=5,
            end=50,
            confidence="HIGH",
            matched_rule="pem-priv-key",
        )
        data = f.model_dump()
        restored = Finding(**data)
        assert restored == f

    def test_audit_event_roundtrip(self) -> None:
        event = AuditEvent(
            timestamp="2026-06-19T12:00:00Z",
            url="/v1/chat",
            severity=Severity.CRITICAL,
            event_type=EventType.FILE_BLOCK,
            source="proxy",
            findings_count=1,
            findings=[FindingSummary(type="api_key", confidence="HIGH", length=32)],
            file_blocks=[
                FileBlockMatch(
                    rule_type=MatchType.PEM_BLOCK,
                    matched_value="-----BEGIN CERTIFICATE-----",
                    position=0,
                )
            ],
            client_ip="10.0.0.1",
            request_id="r1",
        )
        data = event.model_dump()
        restored = AuditEvent(**data)
        assert restored == event

    def test_rule_definition_roundtrip(self) -> None:
        rule = RuleDefinition(
            id="rd",
            name="Test Rule",
            pattern="secret",
            secret_group=2,
            confidence="MEDIUM",
            entropy_check=True,
            keywords=["secret", "key"],
            severity=Severity.INFO,
            category="test",
        )
        data = rule.model_dump()
        restored = RuleDefinition(**data)
        assert restored == rule

    def test_json_serialize_to_string(self) -> None:
        event = AuditEvent(
            timestamp="2026-06-19T12:00:00Z",
            url="/api",
            severity=Severity.INFO,
            event_type=EventType.PASS,
        )
        json_str = event.model_dump_json()
        parsed = json.loads(json_str)
        assert parsed["severity"] == "INFO"
        assert parsed["event_type"] == "pass"
        assert parsed["source"] == "proxy"

    def test_json_deserialize_from_string(self) -> None:
        json_str = json.dumps({
            "id": "r-deser",
            "name": "From JSON",
            "pattern": "test",
            "secret_group": 1,
            "confidence": "HIGH",
            "entropy_check": False,
            "keywords": ["tag"],
            "severity": "CRITICAL",
            "category": "secrets",
        })
        rule = RuleDefinition.model_validate_json(json_str)
        assert rule.id == "r-deser"
        assert rule.severity == Severity.CRITICAL


# ── 10. Invalid severity rejection ──────────────────────────────────


class TestInvalidInput:
    def test_invalid_severity_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvent(
                timestamp="2026-06-19T12:00:00Z",
                url="/",
                severity="UNKNOWN",
                event_type=EventType.PASS,
            )

    def test_invalid_event_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditEvent(
                timestamp="2026-06-19T12:00:00Z",
                url="/",
                severity=Severity.INFO,
                event_type="invalid_type",
            )


# ── 11. Field constraints / edge cases ──────────────────────────────


class TestEdgeCases:
    def test_finding_zero_length(self) -> None:
        f = Finding(
            secret_type="token",
            start=0,
            end=0,
            confidence="MEDIUM",
            matched_rule="empty-rule",
        )
        assert f.start == 0
        assert f.end == 0

    def test_audit_event_empty_findings_with_count(self) -> None:
        """findings_count can exceed len(findings) — it's a metadata field."""
        event = AuditEvent(
            timestamp="2026-06-19T12:00:00Z",
            url="/",
            severity=Severity.INFO,
            event_type=EventType.PASS,
            findings_count=5,
            findings=[],
        )
        assert event.findings_count == 5
        assert event.findings == []

    def test_file_block_match_position_edge(self) -> None:
        match = FileBlockMatch(
            rule_type=MatchType.PATH,
            matched_value="/some/deeply/nested/path",
            position=999999,
        )
        assert match.position == 999999
