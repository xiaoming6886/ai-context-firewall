"""Shannon entropy-based secret detection.

Provides a standalone entropy calculator and an EntropyDetector that
scans text for high-entropy tokens (base64, hex, or generic) that may
represent API keys, tokens, or other secrets.

When constructed with an :class:`~acf.config.settings.AppConfig`, the
detector uses the configured entropy thresholds.  Without a config it
falls back to the module-level defaults.
"""

from __future__ import annotations

import math
import re
import string
from typing import TYPE_CHECKING

from acf.models.types import Finding

if TYPE_CHECKING:
    from acf.config.settings import AppConfig

# ── Constants ────────────────────────────────────────────────────────

BASE64_CHARS: str = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/="
HEX_CHARS: str = "0123456789abcdefABCDEF"

BASE64_THRESHOLD: float = 4.5
HEX_THRESHOLD: float = 3.0
MIN_SECRET_LENGTH: int = 20

# Pre-computed sets for fast membership checks
_BASE64_SET: set[str] = set(BASE64_CHARS)
_HEX_SET: set[str] = set(HEX_CHARS)


# ── Public helpers ───────────────────────────────────────────────────


def shannon_entropy(data: str, charset: str | None = None) -> float:
    """Compute Shannon entropy (bits per character) for *data*.

    If *charset* is provided, only characters in that set are counted;
    characters outside it are silently ignored.  When *charset* is
    ``None`` the full observed character set is used.

    Returns ``0.0`` for empty or single-character-only input.
    """
    if not data:
        return 0.0

    if charset is not None:
        # Filter to only the characters we care about
        filtered = [c for c in data if c in charset]
        if not filtered:
            return 0.0
        length = len(filtered)
        freq: dict[str, int] = {}
        for c in filtered:
            freq[c] = freq.get(c, 0) + 1
    else:
        length = len(data)
        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def _classify_token(
    token: str,
    base64_threshold: float = BASE64_THRESHOLD,
    hex_threshold: float = HEX_THRESHOLD,
) -> tuple[str, float, str, str]:
    """Classify *token* and return ``(secret_type, threshold, rule, confidence)``.

    Determines whether the token looks like base64, hex, or generic
    high-entropy text and returns the appropriate metadata tuple.
    Thresholds can be overridden from AppConfig.
    """
    tlen = len(token)
    base64_count = sum(1 for c in token if c in _BASE64_SET)
    hex_count = sum(1 for c in token if c in _HEX_SET)

    base64_ratio = base64_count / tlen
    hex_ratio = hex_count / tlen

    # Check hex first because HEX_CHARS ⊂ BASE64_CHARS; a hex-only string
    # would otherwise be misclassified as base64 with too strict a threshold.
    if hex_ratio > 0.95:
        return ("high_entropy_hex", hex_threshold, "high-entropy-hex", "MEDIUM")

    if base64_ratio > 0.95:
        conf = "HIGH" if tlen >= 40 else "MEDIUM"
        return ("high_entropy_base64", base64_threshold, "high-entropy-base64", conf)

    # Generic high-entropy with the stricter threshold
    return ("high_entropy", base64_threshold, "high-entropy-generic", "MEDIUM")


# ── Detector ─────────────────────────────────────────────────────────


class EntropyDetector:
    """Scan text for high-entropy strings that may represent secrets.

    Parameters
    ----------
    config:
        Optional :class:`~acf.config.settings.AppConfig` supplying
        custom entropy thresholds.  When ``None`` the module-level
        defaults (``BASE64_THRESHOLD=4.5``, ``HEX_THRESHOLD=3.0``,
        ``MIN_SECRET_LENGTH=20``) are used.

    Usage::

        detector = EntropyDetector()
        findings = detector.detect("some text with a token g0dG9rZW4...")

        # With config-driven thresholds:
        cfg = AppConfig(entropy_base64_threshold=5.0)
        detector = EntropyDetector(cfg)
    """

    def __init__(self, config: AppConfig | None = None) -> None:
        if config is not None:
            self._base64_threshold = config.entropy_base64_threshold
            self._hex_threshold = config.entropy_hex_threshold
            self._min_secret_length = config.entropy_min_length
        else:
            self._base64_threshold = BASE64_THRESHOLD
            self._hex_threshold = HEX_THRESHOLD
            self._min_secret_length = MIN_SECRET_LENGTH

        self._token_re: re.Pattern = re.compile(
            r"[A-Za-z0-9+/=]{" + str(self._min_secret_length) + r",}"
        )

    def detect(self, text: str) -> list[Finding]:
        """Scan *text* and return a list of :class:`Finding` objects.

        Each finding corresponds to a contiguous substring whose Shannon
        entropy exceeds the threshold appropriate for its detected
        character class (base64, hex, or generic).
        """
        findings: list[Finding] = []

        for match in self._token_re.finditer(text):
            token = match.group()
            start = match.start()
            end = match.end()

            secret_type, threshold, rule, confidence = _classify_token(
                token,
                base64_threshold=self._base64_threshold,
                hex_threshold=self._hex_threshold,
            )
            entropy = shannon_entropy(
                token,
                BASE64_CHARS if secret_type == "high_entropy_base64" else None,
            )

            if entropy >= threshold:
                findings.append(
                    Finding(
                        secret_type=secret_type,
                        start=start,
                        end=end,
                        confidence=confidence,
                        matched_rule=rule,
                    )
                )

        return findings
