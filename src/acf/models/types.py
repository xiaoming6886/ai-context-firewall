"""Core data models for AI Context Firewall.

Defines severity levels, event types, match types, and structured
records for findings, audit events, and rule definitions.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pydantic import BaseModel


class Severity(str, Enum):
    """Severity level for audit events and rules."""

    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


class EventType(str, Enum):
    """Type of audit event produced by the firewall."""

    FILE_BLOCK = "file_block"
    REDACTION = "redaction"
    PASS = "pass"


class MatchType(str, Enum):
    """How a file was matched for blocking."""

    EXTENSION = "extension"
    PATH = "path"
    PEM_BLOCK = "pem_block"


# ── Findings ────────────────────────────────────────────────────────


class Finding(BaseModel):
    """A single secret or sensitive-content finding within a payload."""

    secret_type: str
    start: int
    end: int
    confidence: str  # "HIGH" | "MEDIUM"
    matched_rule: str


class FindingSummary(BaseModel):
    """Lightweight summary of a finding for audit events."""

    type: str
    confidence: str
    length: int


# ── File blocks ─────────────────────────────────────────────────────


class FileBlockMatch(BaseModel):
    """Record of a file that was blocked by the firewall."""

    rule_type: MatchType
    matched_value: str
    position: int


# ── Audit event ─────────────────────────────────────────────────────


class AuditEvent(BaseModel):
    """Structured audit record produced for every firewall decision."""

    timestamp: str  # ISO 8601
    url: str
    severity: Severity
    event_type: EventType
    source: str = "proxy"
    findings_count: int = 0
    findings: list[FindingSummary] = []
    file_blocks: list[FileBlockMatch] = []
    client_ip: str = ""
    request_id: str = ""


# ── Rule definition ─────────────────────────────────────────────────


class RuleDefinition(BaseModel):
    """Definition of a single detection or blocking rule."""

    id: str
    name: str
    pattern: str
    secret_group: int = 0
    confidence: str = "HIGH"
    entropy_check: bool = False
    keywords: list[str] = []
    severity: Severity = Severity.WARNING
    category: str = "generic"
