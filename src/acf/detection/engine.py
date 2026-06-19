"""Detection engine orchestrating PatternDetector and EntropyDetector.

Provides :class:`DetectionEngine`, the central orchestrator that runs both
the pattern-based and entropy-based secret detectors, then merges and
deduplicates their findings into a single sorted result set.

Guards:
  - Empty / excessively large / binary content → short-circuit with ``[]``
  - Regex timeout via ``concurrent.futures`` → safe fallback on runaway patterns
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from acf.config.settings import AppConfig
from acf.detection.entropy import EntropyDetector
from acf.detection.patterns import PatternDetector
from acf.models.types import Finding

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────

_REGEX_TIMEOUT_SECONDS: float = 5.0
"""Per-detector timeout.  A single ``detect()`` call is killed after this."""

_BINARY_NULL_RATIO: float = 0.0
"""Any null byte → binary."""

_BINARY_NONPRINTABLE_RATIO: float = 0.3
""">30 % non-printable characters (outside 32–126 + \\n\\r\\t) → binary."""


# ── Helpers ────────────────────────────────────────────────────────────


def _is_binary(text: str) -> bool:
    """Return ``True`` if *text* appears to be binary content.

    Two heuristics (OR'd):
      1. Contains a null byte (``\\x00``).
      2. More than ``_BINARY_NONPRINTABLE_RATIO`` of characters are not
         printable ASCII (including common whitespace).
    """
    if not text:
        return False

    length = len(text)
    non_printable = 0

    for ch in text:
        if ch == "\x00":
            return True
        if ch not in "\n\r\t" and (ord(ch) < 32 or ord(ch) > 126):
            non_printable += 1

    return (non_printable / length) > _BINARY_NONPRINTABLE_RATIO


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove overlapping findings, preferring pattern matches.

    Strategy
    --------
    1. Sort findings by ``(start, end, entropy_penalty)`` so pattern
       matches come before entropy matches at the same position.
    2. Greedy keep-first: if a candidate is **fully contained** in the
       last-kept finding, skip it.  Overlap (partial) is kept to avoid
       discarding a distinct secret that happens to start within another.
    3. Final sort by position for deterministic output.
    """
    if not findings:
        return []

    def _sort_key(f: Finding) -> tuple[int, int, int]:
        entropy_penalty = 1 if f.matched_rule.startswith("high-entropy-") else 0
        return (f.start, -f.end, entropy_penalty)

    sorted_findings = sorted(findings, key=_sort_key)

    kept: list[Finding] = []
    for f in sorted_findings:
        if kept:
            last = kept[-1]
            # Fully contained inside the last-kept finding → skip
            if f.start >= last.start and f.end <= last.end:
                continue
        kept.append(f)

    kept.sort(key=lambda f: (f.start, f.end))
    return kept


# ── DetectionEngine ────────────────────────────────────────────────────


class DetectionEngine:
    """Orchestrate pattern + entropy secret detection.

    Typical usage::

        from acf.config.settings import AppConfig
        from acf.detection.engine import DetectionEngine

        engine = DetectionEngine(AppConfig())
        results = engine.scan('text with AKIAIOSFODNN7EXAMPLE embedded')

    Parameters
    ----------
    config:
        Application configuration controlling size limits and
        feature flags (e.g. ``entropy_enabled``).
    pattern_detector:
        Pre-built :class:`PatternDetector` (optional, for testing).
    entropy_detector:
        Pre-built :class:`EntropyDetector` (optional, for testing).
    """

    def __init__(
        self,
        config: AppConfig,
        *,
        pattern_detector: PatternDetector | None = None,
        entropy_detector: EntropyDetector | None = None,
    ) -> None:
        self._config = config
        self._pattern_detector = pattern_detector or PatternDetector()
        self._entropy_detector = entropy_detector or EntropyDetector(config)

    # ── Public API ────────────────────────────────────────────────────

    def scan(self, text: str) -> list[Finding]:
        """Scan *text* for secrets and sensitive content.

        Returns an empty list when:
          - *text* is empty
          - *text* exceeds ``config.max_body_size_bytes``
          - *text* appears to be binary
        """
        if not text:
            return []

        # ── Size guard ────────────────────────────────────────────────
        max_bytes = self._config.max_body_size_bytes
        if len(text.encode("utf-8")) > max_bytes:
            logger.debug("skipping body: %d bytes > %d limit", len(text.encode("utf-8")), max_bytes)
            return []

        # ── Binary guard ──────────────────────────────────────────────
        if _is_binary(text):
            logger.debug("skipping binary body")
            return []

        # ── Pattern detection ─────────────────────────────────────────
        try:
            pattern_findings = self._run_with_timeout(
                self._pattern_detector.detect, text
            )
        except Exception:
            logger.exception("pattern detection failed")
            pattern_findings = []

        # ── Entropy detection ─────────────────────────────────────────
        entropy_findings: list[Finding] = []
        if self._config.entropy_enabled:
            try:
                entropy_findings = self._run_with_timeout(
                    self._entropy_detector.detect, text
                )
            except Exception:
                logger.exception("entropy detection failed")
                entropy_findings = []

        # ── Merge & deduplicate ───────────────────────────────────────
        return _deduplicate(pattern_findings + entropy_findings)

    # ── Internal ──────────────────────────────────────────────────────

    def _run_with_timeout(self, detect_fn: Callable[[str], list[Finding]], text: str) -> list[Finding]:
        """Execute *detect_fn(text)* with a timeout guard.

        Uses a single-thread executor so that a runaway regex cannot
        block the caller indefinitely.  On timeout or error an empty
        list is returned.
        """
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(detect_fn, text)
        try:
            return future.result(timeout=_REGEX_TIMEOUT_SECONDS)
        except FuturesTimeoutError:
            logger.warning("detector timed out after %.1fs", _REGEX_TIMEOUT_SECONDS)
            # Cancel the future and shut down without waiting so the
            # runaway regex thread does not block the caller on exit.
            future.cancel()
            executor.shutdown(wait=False)
            return []
        else:
            executor.shutdown(wait=True)
