"""JSONL audit logger for AI Context Firewall.

Writes structured AuditEvent records as newline-delimited JSON
with atomic append semantics for safe concurrent access.
"""

from __future__ import annotations

import gzip
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Sequence

from acf.models.types import (
    AuditEvent,
    EventType,
    FileBlockMatch,
    FindingSummary,
    Severity,
)

_DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
_DEFAULT_MAX_BACKUP_COUNT = 5


class AuditLogger:
    """Append-only JSONL audit logger with automatic log rotation.

    Each AuditEvent is serialised to a single JSON line and appended
    to the log file.  Writes use O_APPEND semantics + fsync so that
    individual lines are atomically visible to concurrent readers.

    When the active log file exceeds *max_file_size* bytes the file is
    automatically rotated: the current content is gzip-compressed to
    ``<path>.1.gz``, older backups are shifted (``.N.gz`` →
    ``.N+1.gz``), and a fresh empty log file is created.  At most
    *max_backup_count* compressed backups are retained.
    """

    def __init__(
        self,
        log_path: str | Path,
        max_file_size: int = _DEFAULT_MAX_FILE_SIZE,
        max_backup_count: int = _DEFAULT_MAX_BACKUP_COUNT,
    ) -> None:
        """Open (or create) the JSONL log file at *log_path*.

        Parameters
        ----------
        log_path:
            Path to the active JSONL log file.
        max_file_size:
            File size in bytes that triggers rotation (default 10 MB).
        max_backup_count:
            Number of gzip-compressed backups to retain (default 5).
        """
        self._log_path = Path(log_path)
        self._max_file_size = max_file_size
        self._max_backup_count = max_backup_count
        self._lock = threading.Lock()
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    # ── public API ──────────────────────────────────────────────────

    def log_event(self, event: AuditEvent) -> None:
        """Write a single *event* as a JSONL line.

        The write is flushed and fsync'd so that readers (including
        concurrent processes) see a complete line immediately.

        If the log file exceeds *max_file_size* after the write, it is
        automatically rotated.  The event is written to disk *before*
        any rotation takes place, guaranteeing no data loss.

        I/O errors (disk full, permission denied, etc.) are caught and
        logged so the proxy never crashes due to audit write failures
        (PLAN §6 failure mode: "Disk full → catch").
        """
        json_line = event.model_dump_json() + "\n"
        with self._lock:
            try:
                with open(self._log_path, "a", encoding="utf-8") as f:
                    f.write(json_line)
                    f.flush()
                    os.fsync(f.fileno())
            except OSError as exc:
                logging.getLogger(__name__).error(
                    "audit write failed (disk full? permissions?): %s",
                    exc,
                )
                return
            self._rotate_if_needed()

    def log_pass(
        self,
        url: str,
        *,
        client_ip: str = "",
        request_id: str = "",
        source: str = "proxy",
    ) -> None:
        """Log an INFO pass-through event for a clean request.

        Emitted when an AI endpoint request is inspected and no secrets
        or file blocks are found.  Records the event so operators can
        calculate the detection rate (PASS / total requests).
        """
        event = AuditEvent(
            timestamp=_now(),
            url=url,
            severity=Severity.INFO,
            event_type=EventType.PASS,
            source=source,
            findings=[],
            findings_count=0,
            file_blocks=[],
            client_ip=client_ip,
            request_id=request_id,
        )
        self.log_event(event)

    def log_file_block(
        self,
        url: str,
        matches: Sequence[FileBlockMatch],
        *,
        client_ip: str = "",
        request_id: str = "",
        source: str = "proxy",
    ) -> None:
        """Log a CRITICAL file-block event with *matches*."""
        event = AuditEvent(
            timestamp=_now(),
            url=url,
            severity=Severity.CRITICAL,
            event_type=EventType.FILE_BLOCK,
            source=source,
            file_blocks=list(matches),
            findings=[],
            findings_count=0,
            client_ip=client_ip,
            request_id=request_id,
        )
        self.log_event(event)

    def log_redaction(
        self,
        url: str,
        findings: Sequence[FindingSummary],
        *,
        client_ip: str = "",
        request_id: str = "",
        source: str = "proxy",
    ) -> None:
        """Log a WARNING redaction event with *findings*."""
        event = AuditEvent(
            timestamp=_now(),
            url=url,
            severity=Severity.WARNING,
            event_type=EventType.REDACTION,
            source=source,
            findings=list(findings),
            findings_count=len(findings),
            file_blocks=[],
            client_ip=client_ip,
            request_id=request_id,
        )
        self.log_event(event)

    # ── read-back  (useful for testing & recovery) ──────────────────

    def read_events(self) -> list[AuditEvent]:
        """Parse and return every valid AuditEvent in the log file.

        Malformed JSON lines are silently skipped; a warning is
        written to stderr so operators can investigate.
        """
        if not self._log_path.exists():
            return []

        events: list[AuditEvent] = []
        with open(self._log_path, encoding="utf-8") as f:
            for line_no, raw in enumerate(f, start=1):
                stripped = raw.strip()
                if not stripped:
                    continue
                try:
                    events.append(AuditEvent.model_validate_json(stripped))
                except Exception:
                    logging.getLogger(__name__).warning(
                        "skipping malformed line %d in %s", line_no, self._log_path,
                    )
        return events

    # ── rotation ──────────────────────────────────────────────────

    def _rotate_if_needed(self) -> None:
        """Atomically rotate the log file if it exceeds *max_file_size*.

        The check-and-rotate sequence is serialised by ``self._lock``
        to prevent concurrent rotation from multiple threads using the
        same AuditLogger instance.
        """
        if not self._log_path.exists():
            return
        if self._log_path.stat().st_size < self._max_file_size:
            return

        # 1. Remove the oldest backup if we're at capacity.
        oldest = Path(str(self._log_path) + f".{self._max_backup_count}.gz")
        if oldest.exists():
            oldest.unlink()

        # 2. Shift existing backups: .N.gz → .N+1.gz
        for i in range(self._max_backup_count - 1, 0, -1):
            src = Path(str(self._log_path) + f".{i}.gz")
            if src.exists():
                dst = Path(str(self._log_path) + f".{i + 1}.gz")
                src.rename(dst)

        # 3. Gzip-compress the current log file into .1.gz
        backup_path = Path(str(self._log_path) + ".1.gz")
        with open(self._log_path, "rb") as f_in:
            with gzip.open(backup_path, "wb") as f_out:
                f_out.write(f_in.read())

        # 4. Truncate the active log file (fresh empty file).
        #    Using write_text("") on an existing file truncates it
        #    while preserving the same inode / file identity.
        self._log_path.write_text("", encoding="utf-8")


# ── helpers ────────────────────────────────────────────────────────


def _now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()
