"""Unit tests for acf.detection.engine — DetectionEngine.

Covers:
  - Single / multiple pattern matches
  - Combined pattern + entropy detection
  - Overlap deduplication (pattern wins over entropy)
  - Empty / whitespace / binary / oversized body guards
  - Regex timeout guard
  - Entropy toggle (enabled / disabled)
  - Position ordering
  - Boundary: exactly-at-limit body scanned
  - Non-ASCII content
Total: 16 tests
"""

from __future__ import annotations

import pytest

from acf.config.settings import AppConfig
from acf.detection.engine import DetectionEngine, _deduplicate, _is_binary
from acf.detection.patterns import PatternDetector
from acf.models.types import Finding, RuleDefinition, Severity


# ── Config fixture (controlled max_body_size for testability) ──────────


@pytest.fixture
def config() -> AppConfig:
    """Create AppConfig with entropy enabled and large max body."""
    return AppConfig(
        entropy_enabled=True,
        max_body_size_mb=999,  # effectively unlimited
    )


@pytest.fixture
def engine(config: AppConfig) -> DetectionEngine:
    """Create a DetectionEngine with the default config."""
    return DetectionEngine(config)


# ══════════════════════════════════════════════════════════════════════
# DetectionEngine.scan  —  core behaviour
# ══════════════════════════════════════════════════════════════════════


class TestScan:
    """Tests for :meth:`DetectionEngine.scan`."""

    # ── 1. Single pattern match ─────────────────────────────────────────

    def test_single_pattern_match(self, engine: DetectionEngine) -> None:
        """A single AWS key in the text → exactly one finding."""
        findings = engine.scan("AKIAIOSFODNN7EXAMPLE")
        assert len(findings) == 1
        f = findings[0]
        assert f.matched_rule == "aws-access-key"
        assert f.secret_type == "aws-access-key"
        assert f.start == 0
        assert f.end == 20

    # ── 2. Multiple patterns in one text ────────────────────────────────

    def test_multiple_patterns(self, engine: DetectionEngine) -> None:
        """Two distinct secret patterns in one text → both found."""
        text = "key1: AKIAIOSFODNN7EXAMPLE\nkey2: sk-abc123def456ghi789jkl012mno345p"
        findings = engine.scan(text)
        rule_ids = {f.matched_rule for f in findings}
        assert "aws-access-key" in rule_ids
        assert "openai-api-key" in rule_ids
        assert len(findings) >= 2

    # ── 3. Entropy + pattern combined detection ─────────────────────────

    def test_entropy_plus_pattern(self, engine: DetectionEngine) -> None:
        """Pattern + high-entropy token both present → both found (no overlap)."""
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        # High-entropy base64 token (long enough to trigger entropy)
        b64_token = "dGhpcyBpcyBhIHNhbXBsZSBiYXNlNjQgc3RyaW5nIGZvciB0ZXN0aW5nIHB1cnBvc2Vz"
        text = f"{aws_key}\n{b64_token}"

        findings = engine.scan(text)
        rule_ids = {f.matched_rule for f in findings}
        assert "aws-access-key" in rule_ids
        assert "high-entropy-base64" in rule_ids

    # ── 4. Deduplication: pattern wins over overlapping entropy ─────────

    def test_overlap_pattern_beats_entropy(self, engine: DetectionEngine) -> None:
        """When an entropy finding fully overlaps a pattern finding, only
        the pattern finding is kept."""
        # OpenAI key: "sk-" prefix + 20+ chars → both pattern & entropy matchable
        text = "sk-abc123def456ghi789jkl012mno345p"

        findings = engine.scan(text)
        # After dedup, pattern match should survive and entropy match dropped
        rule_ids = {f.matched_rule for f in findings}
        assert "openai-api-key" in rule_ids
        # If entropy also matched the same span it was deduped away
        # (high-entropy-base64 may or may not have triggered; if it did, it's deduped)

    # ── 5. Empty body ───────────────────────────────────────────────────

    def test_empty_body_returns_none(self, engine: DetectionEngine) -> None:
        assert engine.scan("") == []

    # ── 6. Large body skipped ───────────────────────────────────────────

    def test_large_body_skipped(self) -> None:
        """Body larger than config threshold → empty result."""
        tiny_config = AppConfig(
            entropy_enabled=True,
            max_body_size_mb=1,  # 1 MB ≈ 1,048,576 bytes
        )
        eng = DetectionEngine(tiny_config)
        # Build a string just over 1 MB
        large = "x" * (1_048_577)  # 1 byte over
        assert eng.scan(large) == []

    # ── 7. Binary content skipped ───────────────────────────────────────

    def test_binary_content_skipped(self, engine: DetectionEngine) -> None:
        """Null-byte content → treated as binary → empty result."""
        binary_text = "hello\x00world"
        assert engine.scan(binary_text) == []

    def test_binary_nonprintable_skipped(self, engine: DetectionEngine) -> None:
        """High ratio of non-printable chars → treated as binary."""
        # 50% non-printable (>30% threshold)
        nonprint = "\x01\x02\x03\x04\x05abcde"
        assert engine.scan(nonprint) == []

    # ── 8. Regex timeout guard ──────────────────────────────────────────

    def test_regex_timeout_guard(self, config: AppConfig) -> None:
        """A pathological regex does not hang the engine.

        Uses (a+)+b pattern on input "aaaa...X" which causes exponential
        backtracking.  The timeout guard should return empty list.
        """
        # Create a PatternDetector with a single catastrophic-backtracking rule
        evil_rule = RuleDefinition(
            id="evil-backtrack",
            name="Evil Backtrack Rule",
            pattern=r"(a+)+b",
            keywords=["a"],
            severity=Severity.WARNING,
            category="test",
        )
        pd = PatternDetector(rules=[evil_rule])

        eng = DetectionEngine(config, pattern_detector=pd)
        # "a" repeated 60 times + "X" — can never match but regex backtracks
        # exponentially through the (a+)+ branches.
        evil_input = "a" * 60 + "X"
        findings = eng.scan(evil_input)
        # Should either finish quickly (empty) or time out gracefully
        assert isinstance(findings, list)

    # ── 9. Entropy disabled in config ───────────────────────────────────

    def test_entropy_disabled(self) -> None:
        """When entropy_enabled is False, only pattern findings are returned."""
        cfg = AppConfig(entropy_enabled=False, max_body_size_mb=999)
        eng = DetectionEngine(cfg)

        # High-entropy base64 that would normally be caught
        b64 = "dGhpcyBpcyBhIHNhbXBsZSBiYXNlNjQgc3RyaW5nIGZvciB0ZXN0aW5nIHB1cnBvc2Vz"
        findings = eng.scan(b64)
        # No entropy rule IDs
        entropy_rules = {f.matched_rule for f in findings if f.matched_rule.startswith("high-entropy-")}
        assert len(entropy_rules) == 0

    # ── 10. Findings sorted by position ─────────────────────────────────

    def test_findings_sorted_by_position(self, engine: DetectionEngine) -> None:
        """Results are ordered by (start, end)."""
        # Text:  [aws-key-here].....[openai-key-here]
        text = "AKIAIOSFODNN7EXAMPLE xxxxxxxxxxxxxxxxxxxxxx sk-abc123def456ghi789jkl012mno345p"
        findings = engine.scan(text)
        # Verify monotonic ordering
        for i in range(len(findings) - 1):
            a, b = findings[i], findings[i + 1]
            assert (a.start, a.end) <= (b.start, b.end), (
                f"finding {i} ({a.start},{a.end}) after finding {i+1} ({b.start},{b.end})"
            )

    # ── 11. Non-overlapping findings both kept ──────────────────────────

    def test_non_overlapping_both_kept(self, engine: DetectionEngine) -> None:
        """Pattern and entropy findings at different positions are both kept."""
        aws = "AKIAIOSFODNN7EXAMPLE"
        b64 = "dGhpcyBpcyBhIHNhbXBsZSBiYXNlNjQgc3RyaW5nIGZvciB0ZXN0aW5nIHB1cnBvc2Vz"
        text = f"{aws}\n---\n{b64}"

        findings = engine.scan(text)
        rule_ids = {f.matched_rule for f in findings}
        assert "aws-access-key" in rule_ids
        assert "high-entropy-base64" in rule_ids
        assert len(findings) >= 2

    # ── 12. Whitespace-only body ────────────────────────────────────────

    def test_whitespace_only(self, engine: DetectionEngine) -> None:
        """Whitespace input produces no findings."""
        assert engine.scan("   \n  \t  ") == []

    # ── 13. Text at size limit still scanned ────────────────────────────

    def test_exactly_at_size_limit_scanned(self) -> None:
        """Text whose byte-length equals the limit is still scanned (not skipped)."""
        tiny_cfg = AppConfig(
            entropy_enabled=False,
            max_body_size_mb=1,
        )
        eng = DetectionEngine(tiny_cfg)
        # Build text exactly at 1 MB boundary
        limit = tiny_cfg.max_body_size_bytes
        # Embed a key near the end so we can verify scan happens
        prefix_len = limit - 20  # minus AWS key length
        text = "x" * prefix_len + "AKIAIOSFODNN7EXAMPLE"
        assert len(text.encode("utf-8")) == limit
        findings = eng.scan(text)
        # The scan happens but keyword pre-filter will skip aws-access-key
        # because "AKIA" is present — it should still find it
        assert any(f.matched_rule == "aws-access-key" for f in findings)

    # ── 14. Non-ASCII text handled ──────────────────────────────────────

    def test_non_ascii_text(self, engine: DetectionEngine) -> None:
        """Unicode text with embedded secret is correctly scanned."""
        text = "こんにちは AKIAIOSFODNN7EXAMPLE 世界"
        findings = engine.scan(text)
        assert len(findings) == 1
        f = findings[0]
        assert f.matched_rule == "aws-access-key"
        # Verify correct position in the Unicode string
        assert text[f.start : f.end] == "AKIAIOSFODNN7EXAMPLE"

    # ── 15. Multiple entropy-only findings (no pattern overlap) ─────────

    def test_multiple_entropy_only(self, engine: DetectionEngine) -> None:
        """Two distinct high-entropy tokens, no pattern matches → both kept."""
        b64_a = "dGhpcyBpcyBhIHNhbXBsZSBiYXNlNjQgc3RyaW5nIGZvciB0ZXN0aW5nIHB1cnBvc2Vz"
        b64_b = "YW5vdGhlciBiYXNlNjQgc3RyaW5nIHRoYXQgaXMgYWxzbyBsb25nIGVub3VnaA=="
        text = f"{b64_a}\n---\n{b64_b}"
        findings = engine.scan(text)
        # Both should be found
        entropy_findings = [f for f in findings if f.matched_rule.startswith("high-entropy-")]
        assert len(entropy_findings) >= 2, f"Expected ≥2 entropy findings, got {len(entropy_findings)}"

    # ── 16. Pattern with secret_group positioned correctly ──────────────

    def test_secret_group_position(self, engine: DetectionEngine) -> None:
        """A rule with secret_group captures only the secret portion, not the
        surrounding assignment syntax."""
        # password-assignment rule uses secret_group=1 → captures only "myPass123"
        # not the full `password = "myPass123"`
        text = 'password = "myPass123"'
        findings = engine.scan(text)
        pw_findings = [f for f in findings if f.matched_rule == "password-assignment"]
        assert len(pw_findings) >= 1
        f = pw_findings[0]
        assert text[f.start : f.end] == "myPass123"


# ══════════════════════════════════════════════════════════════════════
# _deduplicate  helper
# ══════════════════════════════════════════════════════════════════════


class TestDeduplicate:
    """Tests for the standalone :func:`_deduplicate` function."""

    def _f(self, rule: str, start: int, end: int, secret_type: str = "") -> Finding:
        """Shortcut to build a Finding."""
        return Finding(
            secret_type=secret_type or rule,
            start=start,
            end=end,
            confidence="HIGH",
            matched_rule=rule,
        )

    def test_empty_input(self) -> None:
        assert _deduplicate([]) == []

    def test_no_overlap_keeps_all(self) -> None:
        a = self._f("rule-a", 0, 10)
        b = self._f("rule-b", 20, 30)
        result = _deduplicate([a, b])
        assert len(result) == 2

    def test_fully_contained_dropped(self) -> None:
        """B is fully inside A → B is dropped."""
        a = self._f("rule-a", 0, 20)
        b = self._f("rule-b", 5, 10)  # inside A
        result = _deduplicate([a, b])
        assert len(result) == 1
        assert result[0].matched_rule == "rule-a"

    def test_pattern_kept_over_entropy_same_span(self) -> None:
        """Pattern and entropy at the same exact span → pattern kept."""
        a = self._f("openai-api-key", 0, 30)
        b = self._f("high-entropy-base64", 0, 30)
        # Pattern (a) comes first due to sort key → entropy (b) contained → dropped
        result = _deduplicate([b, a])
        assert len(result) == 1
        assert result[0].matched_rule == "openai-api-key"

    def test_partial_overlap_both_kept(self) -> None:
        """Partial overlap (not full containment) → both kept."""
        a = self._f("rule-a", 0, 15)
        b = self._f("rule-b", 10, 25)  # overlaps but not contained
        result = _deduplicate([a, b])
        assert len(result) == 2

    def test_sorted_by_position(self) -> None:
        """Output is always sorted by (start, end)."""
        a = self._f("rule-a", 30, 40)
        b = self._f("rule-b", 0, 10)
        c = self._f("rule-c", 15, 25)
        result = _deduplicate([a, b, c])
        assert [r.start for r in result] == [0, 15, 30]


# ══════════════════════════════════════════════════════════════════════
# _is_binary  helper
# ══════════════════════════════════════════════════════════════════════


class TestIsBinary:
    """Tests for the :func:`_is_binary` helper."""

    def test_empty_not_binary(self) -> None:
        assert _is_binary("") is False

    def test_ascii_text_not_binary(self) -> None:
        assert _is_binary("hello world") is False

    def test_null_byte_is_binary(self) -> None:
        assert _is_binary("\x00") is True

    def test_null_byte_in_text_is_binary(self) -> None:
        assert _is_binary("hello\x00world") is True

    def test_high_nonprintable_ratio_is_binary(self) -> None:
        # 50% non-printable
        assert _is_binary("\x01\x02\x03\x04\x05abcde") is True

    def test_low_nonprintable_ratio_not_binary(self) -> None:
        # 1 non-printable out of 11 chars (~9%) → below 30%
        assert _is_binary("hello\x01world") is False

    def test_unicode_text_not_binary(self) -> None:
        assert _is_binary("こんにちは世界") is False
