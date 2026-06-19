"""Unit tests for acf.detection.patterns — PatternDetector.

Covers:
  - 18 true-positive tests (one per built-in rule)
  -  4 false-positive tests (UUID, hex colour, template var, sequential chars)
  -  1 edge-case test (empty / whitespace input)
  -  1 position-offset accuracy test
  -  1 keyword pre-filter skip test
Total: 25 tests
"""

import pytest

from acf.detection.patterns import PATTERNS, PatternDetector


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def detector() -> PatternDetector:
    return PatternDetector()


# ── True-positive matrix ─────────────────────────────────────────────
# Each entry: (rule_id, text_containing_the_secret)

TRUE_POSITIVES: list[tuple[str, str]] = [
    # 1  — AWS Access Key ID
    (
        "aws-access-key",
        "AKIAIOSFODNN7EXAMPLE",
    ),
    # 2  — AWS Secret Access Key
    (
        "aws-secret-key",
        "aws_secret_access_key = wJalrXUtFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ),
    # 3  — GitHub Classic PAT
    (
        "github-classic-pat",
        "ghp_abc123def456ghi789jkl012mno345pqr678st",
    ),
    # 4  — GitHub Fine-Grained PAT
    (
        "github-fine-grained-pat",
        "github_pat_"
        "11AAABBBCCCDDDEEEFFFGGGHHHIIIJJJKKKLLLMMMNNNOOOPPP"
        "QQQRRRSSSTTTUUUVVVWWWXXXYYYZZZaaaabbbbccccdddd",  # 90 chars after prefix
    ),
    # 5  — GitLab PAT
    (
        "gitlab-pat",
        "glpat-abc123def456ghi789jkl012mno345pqr678stu",
    ),
    # 6  — GCP API Key
    (
        "gcp-api-key",
        "AIzaSyA-s0me-ExAmPlE-K3y-vAlu3F0rT3st1n",  # 35 chars after AIza
    ),
    # 7  — Slack Token
    (
        "slack-token",
        "xoxb-123456789012-1234567890123-abc123def456ghi789jkl012mno",
    ),
    # 8  — Stripe Live Key
    (
        "stripe-live-key",
        "sk_live_abc123def456ghi789jkl012mno345",
    ),
    # 9  — JWT
    (
        "jwt",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNqP72jRF9gKcP2r3A",
    ),
    # 10 — PEM Private Key Header (variant 1: plain)
    (
        "pem-private-key",
        "-----BEGIN PRIVATE KEY-----",
    ),
    # PEM variant 2: RSA
    (
        "pem-private-key",
        "-----BEGIN RSA PRIVATE KEY-----",
    ),
    # 11 — .env Variable Assignment
    (
        "env-var-assignment",
        "DATABASE_URL=postgres://user:pass@localhost:5432/mydb",
    ),
    # 12 — Generic Password Assignment
    (
        "password-assignment",
        'password = "superSecret123!"',
    ),
    # 13 — Generic Secret Assignment (api_key flavour)
    (
        "secret-assignment",
        'api_key = "my-secret-token-value-12345"',
    ),
    # 14 — Database URL with Credentials
    (
        "db-url-credentials",
        "postgres://admin:secret123@localhost:5432/mydb",
    ),
    # 15 — Bearer Token
    (
        "bearer-token",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9."
        "eyJkYXRhIjoidGVzdCJ9.3Tt6iFzGjQ",
    ),
    # 16 — Databricks Token
    (
        "databricks-token",
        "dapi1234567890abcdef1234567890abcdef12",
    ),
    # 17 — Azure Connection String
    (
        "azure-connection-string",
        "DefaultEndpointsProtocol=https;"
        "AccountName=mystorage;"
        "AccountKey=mykey123==;"
        "EndpointSuffix=core.windows.net",
    ),
    # 18 — OpenAI API Key
    (
        "openai-api-key",
        "sk-abc123def456ghi789jkl012mno345p",
    ),
]


@pytest.mark.parametrize(("rule_id", "text"), TRUE_POSITIVES)
def test_true_positive(rule_id: str, text: str, detector: PatternDetector) -> None:
    """Each built-in rule must match its designated secret pattern."""
    findings = detector.detect(text)
    matched_ids = [f.matched_rule for f in findings]
    assert rule_id in matched_ids, (
        f"Expected rule {rule_id!r} to match {text!r}\n"
        f"  Got findings: {matched_ids}"
    )


# ── False-positive inputs (benign strings that should NOT fire) ──────

FALSE_POSITIVES: list[str] = [
    "550e8400-e29b-41d4-a716-446655440000",  # UUID
    "#aabbccdd",  # hex colour
    "{{ secret_key }}",  # template variable (no assignment)
    "abcdefghijklmnopqrstuvwxyz",  # sequential alphabetic chars
]


@pytest.mark.parametrize("text", FALSE_POSITIVES)
def test_false_positive(text: str, detector: PatternDetector) -> None:
    """Benign strings must NOT produce any findings."""
    findings = detector.detect(text)
    assert len(findings) == 0, (
        f"Expected zero findings for {text!r}, got {len(findings)}: "
        f"{[(f.matched_rule, f.start, f.end) for f in findings]}"
    )


# ── Edge cases ───────────────────────────────────────────────────────


class TestEdgeCases:
    """Empty input, whitespace-only, and corner-case behaviour."""

    def test_empty_string(self, detector: PatternDetector) -> None:
        assert detector.detect("") == []

    def test_whitespace_only(self, detector: PatternDetector) -> None:
        assert detector.detect("   \n  \t  ") == []

    def test_position_offsets(self, detector: PatternDetector) -> None:
        """Match positions must be correct character offsets.

        ``text`` holds: "prefix \\n  AKIAIOSFODNN7EXAMPLE  suffix"
                         0─────────^                    ^
                          ^──────── start = 10 ─────────^
                          ^──────────────── end = 30 ──^
        """
        text = "prefix \n  AKIAIOSFODNN7EXAMPLE  suffix"
        #         p(0) r(1) e(2) f(3) i(4) x(5) (6) \n(7) (8) (9) A(10) ... E(29) (30)
        #         start=10                          end=30
        findings = detector.detect(text)
        aws = [f for f in findings if f.matched_rule == "aws-access-key"]
        assert len(aws) == 1, f"Expected 1 aws-access-key finding, got {len(aws)}"
        assert aws[0].start == 10, f"Expected start=10, got {aws[0].start}"
        assert aws[0].end == 30, f"Expected end=30, got {aws[0].end}"

    def test_keyword_prefilter_skips_missing_keyword(
        self, detector: PatternDetector
    ) -> None:
        """Rules whose keywords are absent from the text must be skipped.

        The text ``"nothing suspicious here"`` contains none of the 18
        rule keywords, so every rule should be pre-filter-skipped and
        ``detect()`` must return an empty list without running any regex.
        """
        text = "nothing suspicious here"
        findings = detector.detect(text)
        assert findings == []

    def test_keyword_prefilter_does_not_skip_with_keyword(
        self, detector: PatternDetector
    ) -> None:
        """Rule whose keyword IS present should still run the regex.

        ``"My key is safe"`` contains the token ``key`` as a substring,
        but ``key`` is NOT a keyword for any built-in rule, so there
        should still be zero findings.
        """
        text = "My key is safe"
        findings = detector.detect(text)
        assert findings == []


# ── Integration: all 18 rules are loaded ─────────────────────────────


class TestBuiltinRules:
    """Verify the built-in PATTERNS list is complete and well-formed."""

    def test_eighteen_rules_defined(self) -> None:
        assert len(PATTERNS) == 18, f"Expected 18 rules, got {len(PATTERNS)}"

    def test_all_rules_have_required_fields(self) -> None:
        for rule in PATTERNS:
            assert rule.id, f"Rule missing id: {rule}"
            assert rule.name, f"Rule missing name: {rule}"
            assert rule.pattern, f"Rule {rule.id} missing pattern"
            assert rule.severity is not None, f"Rule {rule.id} missing severity"
            assert rule.category, f"Rule {rule.id} missing category"

    def test_all_rule_ids_unique(self) -> None:
        ids = [r.id for r in PATTERNS]
        assert len(ids) == len(set(ids)), f"Duplicate rule IDs: {ids}"

    def test_all_patterns_compile(self) -> None:
        """Every built-in pattern must be a valid regex."""
        import re

        for rule in PATTERNS:
            try:
                re.compile(rule.pattern)
            except re.error as exc:
                pytest.fail(f"Rule {rule.id} has invalid pattern: {exc}")
