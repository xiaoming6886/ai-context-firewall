"""File-filter pre-filter for AI Context Firewall.

Blocks sensitive files by extension, path pattern, and inline PEM content
before they reach the detection engine.
"""

from __future__ import annotations

import re

from acf.models.types import FileBlockMatch, MatchType


class FileFilter:
    """Pre-filter that classifies files as blocked or clean.

    Applies three categories of blocking rules:

      1. **Dangerous file extensions** – ``.env``, ``.pem``, ``.p12``,
         ``.pfx``, ``.key``, ``.p8``, ``.jks``, ``.keystore``, ``.secret``
      2. **Sensitive directory paths** – ``~/.ssh/``, ``~/.aws/``,
         ``~/.gcloud/``, ``~/.azure/``
      3. **Inline PEM private keys** exceeding 100 base-64 characters
    """

    # ── Class-level constants ────────────────────────────────────────

    BLOCKED_EXTENSIONS: frozenset[str] = frozenset({
        ".env", ".pem", ".p12", ".pfx",
        ".key", ".p8", ".jks", ".keystore", ".secret",
    })

    BLOCKED_PATH_PATTERNS: list[re.Pattern] = [
        re.compile(r"~[/\\]\.ssh[/\\]"),
        re.compile(r"~[/\\]\.aws[/\\]"),
        re.compile(r"~[/\\]\.gcloud[/\\]"),
        re.compile(r"~[/\\]\.azure[/\\]"),
    ]

    # Matches PEM private-key blocks whose base-64 content (between the
    # BEGIN and END markers) is at least 101 characters long, i.e. it
    # exceeds the 100-character threshold.
    PEM_BLOCK_PATTERN: re.Pattern = re.compile(
        r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
        r"[A-Za-z0-9+/=\s]{101,}?"
        r"-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----"
    )

    # ── Public API ───────────────────────────────────────────────────

    def check(self, body: str) -> list[FileBlockMatch]:
        """Run all blocking rules against *body*.

        When called from the proxy pipeline (*intercept.py*) the *body*
        parameter contains the decoded HTTP request body text (not a file
        path).  In this context:

        - **Extension checks** match only when the entire body text ends
          with a blocked extension (rare).  For file-upload detection,
          consider passing ``Content-Disposition`` filename metadata
          separately.
        - **Path-pattern checks** match ``~/.ssh/`` etc. inside the text
          — useful when paths happen to appear verbatim in JSON or code
          prompts.
        - **PEM inline** check is the primary proxy-context guard: it
          scans for embedded ``-----BEGIN ... PRIVATE KEY-----`` blocks
          with ≥100 chars of base64 body content.

        When called standalone (e.g. CLI ``acf scan``) the method also
        works correctly with literal file paths.
        """
        matches: list[FileBlockMatch] = []

        # 1. Extension check (case-insensitive)
        lower = body.lower()
        for ext in self.BLOCKED_EXTENSIONS:
            if lower.endswith(ext):
                matches.append(FileBlockMatch(
                    rule_type=MatchType.EXTENSION,
                    matched_value=ext,
                    position=len(body) - len(ext),
                ))
                break  # one extension hit is enough

        # 2. Path-pattern check
        for pattern in self.BLOCKED_PATH_PATTERNS:
            m = pattern.search(body)
            if m:
                matches.append(FileBlockMatch(
                    rule_type=MatchType.PATH,
                    matched_value=m.group(),
                    position=m.start(),
                ))

        # 3. PEM inline content check
        for m in self.PEM_BLOCK_PATTERN.finditer(body):
            snippet = m.group()
            matches.append(FileBlockMatch(
                rule_type=MatchType.PEM_BLOCK,
                matched_value=snippet[:50],
                position=m.start(),
            ))

        return matches

    def should_block(self, body: str) -> tuple[bool, list[FileBlockMatch]]:
        """Convenience wrapper — returns ``(blocked, matches)``."""
        matches = self.check(body)
        return (len(matches) > 0, matches)
