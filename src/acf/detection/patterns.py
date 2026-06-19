"""Pattern detection rules for AI Context Firewall.

Provides 18 built-in detection rules covering cloud provider secrets,
API tokens, private keys, database URLs, and generic secret patterns.
Each rule is a RuleDefinition with a compiled regex, keyword pre-filter,
severity rating, and optional entropy check flag.

Built-in Rules (18 total):
  ┌─────┬────────────────────────────────┬──────────────────────────────────────┬──────────┐
  │  #  │ Name                           │ Pattern (abbreviated)               │ Severity │
  ├─────┼────────────────────────────────┼──────────────────────────────────────┼──────────┤
  │  1  │ AWS Access Key ID              │ AKIA[0-9A-Z]{16}                    │ CRITICAL │
  │  2  │ AWS Secret Access Key          │ aws_secret_access_key = <40-chars>  │ CRITICAL │
  │  3  │ GitHub Classic PAT             │ ghp_[0-9A-Za-z]{36}                │ CRITICAL │
  │  4  │ GitHub Fine-Grained PAT        │ github_pat_[0-9A-Za-z]{82,}        │ CRITICAL │
  │  5  │ GitLab PAT                     │ glpat-[0-9A-Za-z_-]{20,}           │ CRITICAL │
  │  6  │ GCP API Key                    │ AIza[0-9A-Za-z_-]{35}              │ CRITICAL │
  │  7  │ Slack Token                    │ xox[baprs]-[0-9A-Za-z]{10,48}      │ CRITICAL │
  │  8  │ Stripe Live Key                │ sk_live_[0-9A-Za-z]{24,}           │ CRITICAL │
  │  9  │ JWT                            │ eyJ...3-dot-segment base64url      │ WARNING  │
  │ 10  │ PEM Private Key Header         │ -----BEGIN ... PRIVATE KEY-----    │ CRITICAL │
  │ 11  │ .env Variable Assignment       │ KNOWN_ENV_VAR=<value>              │ WARNING  │
  │ 12  │ Generic Password Assignment    │ password = "..." (quoted)          │ WARNING  │
  │ 13  │ Generic Secret Assignment      │ secret / api_key = "..." (quoted)  │ WARNING  │
  │ 14  │ DB URL with Credentials        │ postgres://user:pass@host/db       │ CRITICAL │
  │ 15  │ Bearer Token                   │ Bearer <token (20+ chars)>         │ WARNING  │
  │ 16  │ Databricks Token               │ dapi[0-9A-Za-z_-]{32,}            │ CRITICAL │
  │ 17  │ Azure Connection String        │ DefaultEndpointsProtocol=...       │ CRITICAL │
  │ 18  │ OpenAI API Key                 │ sk-[A-Za-z0-9]{20,}               │ CRITICAL │
  └─────┴────────────────────────────────┴──────────────────────────────────────┴──────────┘
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from acf.models.types import Finding, RuleDefinition, Severity

# ── Built-in pattern definitions ─────────────────────────────────────

PATTERNS: list[RuleDefinition] = [
    # ── 1. AWS Access Key ID ───────────────────────────────────────
    RuleDefinition(
        id="aws-access-key",
        name="AWS Access Key ID",
        pattern=r"AKIA[0-9A-Z]{16}",
        keywords=["AKIA"],
        severity=Severity.CRITICAL,
        category="cloud",
    ),
    # ── 2. AWS Secret Access Key ──────────────────────────────────
    # Matches assignment of a 35-45 char base64-ish value to aws_secret_access_key
    RuleDefinition(
        id="aws-secret-key",
        name="AWS Secret Access Key",
        pattern=r"(?i)(?:aws_secret_access_key)\s*[=:]\s*['\"]?([A-Za-z0-9+/]{35,45})['\"]?",
        keywords=["secret_access_key"],
        secret_group=1,
        severity=Severity.CRITICAL,
        category="cloud",
    ),
    # ── 3. GitHub Classic PAT ─────────────────────────────────────
    RuleDefinition(
        id="github-classic-pat",
        name="GitHub Classic PAT",
        pattern=r"ghp_[0-9A-Za-z]{36}",
        keywords=["ghp_"],
        severity=Severity.CRITICAL,
        category="vcs",
    ),
    # ── 4. GitHub Fine-Grained PAT ────────────────────────────────
    RuleDefinition(
        id="github-fine-grained-pat",
        name="GitHub Fine-Grained PAT",
        pattern=r"github_pat_[0-9A-Za-z]{82,}",
        keywords=["github_pat_"],
        severity=Severity.CRITICAL,
        category="vcs",
    ),
    # ── 5. GitLab PAT ─────────────────────────────────────────────
    RuleDefinition(
        id="gitlab-pat",
        name="GitLab PAT",
        pattern=r"glpat-[0-9A-Za-z_-]{20,}",
        keywords=["glpat-"],
        severity=Severity.CRITICAL,
        category="vcs",
    ),
    # ── 6. GCP API Key ────────────────────────────────────────────
    RuleDefinition(
        id="gcp-api-key",
        name="GCP API Key",
        pattern=r"AIza[0-9A-Za-z_-]{35}",
        keywords=["AIza"],
        severity=Severity.CRITICAL,
        category="cloud",
    ),
    # ── 7. Slack Token ────────────────────────────────────────────
    RuleDefinition(
        id="slack-token",
        name="Slack Token",
        pattern=r"xox[baprs]-[0-9A-Za-z]{10,48}",
        keywords=["xox"],
        severity=Severity.CRITICAL,
        category="messaging",
    ),
    # ── 8. Stripe Live Key ────────────────────────────────────────
    RuleDefinition(
        id="stripe-live-key",
        name="Stripe Live Key",
        pattern=r"sk_live_[0-9A-Za-z]{24,}",
        keywords=["sk_live_"],
        severity=Severity.CRITICAL,
        category="payment",
    ),
    # ── 9. JWT ────────────────────────────────────────────────────
    # Matches three-dot-segment base64url-encoded JWT
    RuleDefinition(
        id="jwt",
        name="JWT",
        pattern=r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        keywords=["eyJ"],
        confidence="MEDIUM",
        severity=Severity.WARNING,
        category="auth",
    ),
    # ── 10. PEM Private Key Header ────────────────────────────────
    RuleDefinition(
        id="pem-private-key",
        name="PEM Private Key Header",
        pattern=r"-----BEGIN\s+(?:[A-Za-z]+\s+)?PRIVATE\s+KEY-----",
        keywords=["BEGIN PRIVATE KEY"],
        severity=Severity.CRITICAL,
        category="crypto",
    ),
    # ── 11. .env Variable Assignment ──────────────────────────────
    RuleDefinition(
        id="env-var-assignment",
        name=".env Variable Assignment",
        pattern=r"(?m)^(?:DATABASE_URL|SECRET_KEY|DB_PASSWORD|API_KEY|ACCESS_KEY)[A-Z_]*=\S{10,}",
        keywords=["DATABASE_URL", "SECRET_KEY", "DB_PASSWORD", "API_KEY", "ACCESS_KEY"],
        confidence="MEDIUM",
        severity=Severity.WARNING,
        category="config",
    ),
    # ── 12. Generic Password Assignment ───────────────────────────
    RuleDefinition(
        id="password-assignment",
        name="Generic Password Assignment",
        pattern=r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        keywords=["password", "passwd", "pwd"],
        secret_group=1,
        confidence="MEDIUM",
        severity=Severity.WARNING,
        category="generic",
    ),
    # ── 13. Generic Secret Assignment ─────────────────────────────
    RuleDefinition(
        id="secret-assignment",
        name="Generic Secret Assignment",
        pattern=r"(?i)(?:secret|api_key|apikey|token)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        keywords=["secret", "api_key", "apikey", "token"],
        secret_group=1,
        confidence="MEDIUM",
        severity=Severity.WARNING,
        category="generic",
    ),
    # ── 14. Database URL with Credentials ─────────────────────────
    RuleDefinition(
        id="db-url-credentials",
        name="Database URL with Credentials",
        pattern=r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss?)://[A-Za-z0-9_%]+:[A-Za-z0-9_%!@#$^&*]+@",
        keywords=["://"],
        severity=Severity.CRITICAL,
        category="database",
    ),
    # ── 15. Bearer Token ──────────────────────────────────────────
    RuleDefinition(
        id="bearer-token",
        name="Bearer Token",
        pattern=r"(?i)bearer\s+([A-Za-z0-9\-_.~+/]{20,})",
        keywords=["Bearer"],
        secret_group=1,
        confidence="MEDIUM",
        severity=Severity.WARNING,
        category="auth",
    ),
    # ── 16. Databricks Token ──────────────────────────────────────
    RuleDefinition(
        id="databricks-token",
        name="Databricks Token",
        pattern=r"dapi[0-9A-Za-z_-]{32,}",
        keywords=["dapi"],
        severity=Severity.CRITICAL,
        category="cloud",
    ),
    # ── 17. Azure Connection String ───────────────────────────────
    RuleDefinition(
        id="azure-connection-string",
        name="Azure Connection String",
        pattern=r"(?i)DefaultEndpointsProtocol\s*=\s*https\s*;\s*(?:AccountName|AccountKey)\s*=[^;]+;",
        keywords=["DefaultEndpointsProtocol"],
        severity=Severity.CRITICAL,
        category="cloud",
    ),
    # ── 18. OpenAI API Key ────────────────────────────────────────
    RuleDefinition(
        id="openai-api-key",
        name="OpenAI API Key",
        pattern=r"sk-[A-Za-z0-9]{20,}",
        keywords=["sk-"],
        severity=Severity.CRITICAL,
        category="ai",
    ),
]


# ── Pattern Detector ────────────────────────────────────────────────


class PatternDetector:
    """Scans text for secret / sensitive-content patterns.

    Uses a keyword pre-filter (``rule.keywords``) to skip rules whose
    keywords are absent from the input — significantly reducing regex
    calls on benign text.

    Typical usage::

        detector = PatternDetector()
        findings = detector.detect("some text with AKIAIOSFODNN7EXAMPLE")
        # → [Finding(secret_type="aws-access-key", start=15, end=35, ...)]
    """

    def __init__(self, rules: list[RuleDefinition] | None = None) -> None:
        self._rules = rules if rules is not None else PATTERNS
        self._compiled: dict[str, re.Pattern] = {}
        self._precompile()

    # ── internal ────────────────────────────────────────────────────

    def _precompile(self) -> None:
        for rule in self._rules:
            self._compiled[rule.id] = re.compile(rule.pattern)

    def _iter_matches(self, text: str, rule: RuleDefinition) -> Iterator[Finding]:
        """Yield Findings for *rule* matches in *text*."""
        pattern = self._compiled[rule.id]
        for m in pattern.finditer(text):
            grp = rule.secret_group
            if grp > 0 and grp <= len(m.groups()):
                start, end = m.start(grp), m.end(grp)
            else:
                start, end = m.start(), m.end()

            yield Finding(
                secret_type=rule.id,
                start=start,
                end=end,
                confidence=rule.confidence,
                matched_rule=rule.id,
            )

    # ── public API ──────────────────────────────────────────────────

    def detect(self, text: str) -> list[Finding]:
        """Return all findings in *text*.

        For each configured rule:
          1. Check if any keyword from ``rule.keywords`` appears in *text*
             (when the keyword list is non-empty).  Skip the rule entirely
             when no keyword is found — this is the performance pre-filter.
          2. Run the compiled regex and collect all matches as Findings
             with correct *start* / *end* character offsets.
        """
        findings: list[Finding] = []

        for rule in self._rules:
            # Keyword pre-filter — skip if no keyword is present in text.
            if rule.keywords:
                if not any(kw in text for kw in rule.keywords):
                    continue

            findings.extend(self._iter_matches(text, rule))

        return findings

    @property
    def rules(self) -> list[RuleDefinition]:
        """Read-only view of the configured rules."""
        return list(self._rules)
