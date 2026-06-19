"""Tests for the redaction engine."""

import pytest
from acf.models import Finding
from acf.redaction.redactor import Redactor


class TestRedactor:
    """Test suite for ``Redactor.redact``."""

    # ── Core behaviour ─────────────────────────────────────────────

    def test_single_finding_redacted(self):
        """A single finding span is replaced by its [REDACTED:] marker."""
        redactor = Redactor()
        text = "My API key is sk-1234567890abcdef and more text."
        findings = [
            Finding(
                secret_type="openai_api_key",
                start=14,
                end=33,
                confidence="HIGH",
                matched_rule="openai_key",
            )
        ]
        result = redactor.redact(text, findings)

        assert "[REDACTED:openai_api_key]" in result
        assert "sk-1234567890abcdef" not in result
        assert result == "My API key is [REDACTED:openai_api_key] and more text."

    def test_multiple_findings_redacted(self):
        """Multiple non-overlapping findings are each replaced."""
        redactor = Redactor()
        text = "Key1: abc123, Key2: def456, rest."
        findings = [
            Finding(
                secret_type="api_key",
                start=6,
                end=12,
                confidence="HIGH",
                matched_rule="key_pattern",
            ),
            Finding(
                secret_type="api_key",
                start=20,
                end=26,
                confidence="HIGH",
                matched_rule="key_pattern",
            ),
        ]
        result = redactor.redact(text, findings)

        assert result == "Key1: [REDACTED:api_key], Key2: [REDACTED:api_key], rest."
        assert "abc123" not in result
        assert "def456" not in result

    def test_no_findings_text_unchanged(self):
        """With an empty findings list the text is returned verbatim."""
        redactor = Redactor()
        text = "This text contains nothing sensitive."
        result = redactor.redact(text, [])

        assert result == text

    def test_redacted_value_format(self):
        """The replacement marker follows the pattern [REDACTED:<type>]."""
        redactor = Redactor()
        text = "Bearer ghp_token12345"
        findings = [
            Finding(
                secret_type="github_token",
                start=7,
                end=21,
                confidence="HIGH",
                matched_rule="gh_token",
            )
        ]
        result = redactor.redact(text, findings)

        assert result == "Bearer [REDACTED:github_token]"

    # ── Offset correctness ─────────────────────────────────────────

    def test_offsets_correct_after_multi_replace(self):
        """Reverse-order processing keeps early offsets valid.

        Three separate spans in a single string — processing from
        highest start first must not corrupt earlier positions.
        """
        redactor = Redactor()
        # Positions: A B C <sp> D E F <sp> G H I
        #             0 1 2  3  4 5 6  7  8 9 10
        text = "ABC DEF GHI"
        findings = [
            Finding(secret_type="key_a", start=0, end=3,
                    confidence="HIGH", matched_rule="rule_a"),
            Finding(secret_type="key_b", start=4, end=7,
                    confidence="HIGH", matched_rule="rule_b"),
            Finding(secret_type="key_c", start=8, end=11,
                    confidence="HIGH", matched_rule="rule_c"),
        ]
        result = redactor.redact(text, findings)

        assert result == "[REDACTED:key_a] [REDACTED:key_b] [REDACTED:key_c]"

    # ── Overlap handling ───────────────────────────────────────────

    def test_overlapping_findings_merged(self):
        """Findings that overlap are merged into a single span."""
        redactor = Redactor()
        text = "Token: abcdefghijklmnop"
        # finding1 → [7, 15), finding2 → [10, 23) — they overlap
        findings = [
            Finding(secret_type="secret", start=7, end=15,
                    confidence="HIGH", matched_rule="rule_1"),
            Finding(secret_type="secret", start=10, end=23,
                    confidence="HIGH", matched_rule="rule_2"),
        ]
        result = redactor.redact(text, findings)

        # Merged span covers 7–23
        assert result == "Token: [REDACTED:secret]"

    def test_adjacent_findings_not_merged(self):
        """Touching (non-overlapping) findings are replaced independently."""
        redactor = Redactor()
        text = "AABBCCDD"
        findings = [
            Finding(secret_type="part_a", start=0, end=4,
                    confidence="HIGH", matched_rule="rule_a"),
            Finding(secret_type="part_b", start=4, end=8,
                    confidence="HIGH", matched_rule="rule_b"),
        ]
        result = redactor.redact(text, findings)

        assert result == "[REDACTED:part_a][REDACTED:part_b]"

    def test_findings_same_start_merged(self):
        """Two findings starting at the same position are merged."""
        redactor = Redactor()
        text = "The password is P@ssw0rd!"
        findings = [
            Finding(secret_type="password", start=16, end=24,
                    confidence="HIGH", matched_rule="pwd"),
            Finding(secret_type="credential", start=16, end=25,
                    confidence="MEDIUM", matched_rule="cred"),
        ]
        result = redactor.redact(text, findings)

        # Merged: start=16, end=max(24,25)=25; type from first finding
        assert result == "The password is [REDACTED:password]"

    def test_different_types_overlap(self):
        """Overlapping findings with different types use the first type."""
        redactor = Redactor()
        text = "header: abc123xyz secret"
        findings = [
            Finding(secret_type="api_token", start=8, end=15,
                    confidence="HIGH", matched_rule="rule1"),
            Finding(secret_type="session_id", start=12, end=24,
                    confidence="MEDIUM", matched_rule="rule2"),
        ]
        result = redactor.redact(text, findings)

        # Merged: 8–24, type from first finding
        assert result == "header: [REDACTED:api_token]"

    # ── Boundary conditions ────────────────────────────────────────

    def test_finding_at_start_of_text(self):
        """A finding anchored at position 0 is handled correctly."""
        redactor = Redactor()
        text = "SECRET_DATA rest of text"
        findings = [
            Finding(secret_type="secret", start=0, end=11,
                    confidence="HIGH", matched_rule="rule"),
        ]
        result = redactor.redact(text, findings)

        assert result == "[REDACTED:secret] rest of text"

    def test_finding_at_end_of_text(self):
        """A finding covering the last characters is handled correctly."""
        redactor = Redactor()
        text = "Some text ends with SECRET"
        findings = [
            Finding(secret_type="secret", start=20, end=26,
                    confidence="HIGH", matched_rule="rule"),
        ]
        result = redactor.redact(text, findings)

        assert result == "Some text ends with [REDACTED:secret]"

    def test_empty_text(self):
        """Redacting an empty string does not raise."""
        redactor = Redactor()
        text = ""
        findings = [
            Finding(secret_type="empty", start=0, end=0,
                    confidence="HIGH", matched_rule="rule"),
        ]
        result = redactor.redact(text, findings)

        assert result == "[REDACTED:empty]"
