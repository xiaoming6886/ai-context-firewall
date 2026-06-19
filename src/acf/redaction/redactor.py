"""Redaction engine for AI Context Firewall.

Replaces sensitive findings in text payloads with [REDACTED:type] markers.
"""

from acf.models import Finding


class Redactor:
    """Redacts sensitive findings from text payloads.

    Process findings in reverse start-position order so that earlier
    offsets are not invalidated by later replacements. Overlapping
    findings are merged before processing.
    """

    def redact(self, text: str, findings: list[Finding]) -> str:
        """Replace each finding span with a ``[REDACTED:<secret_type>]`` marker.

        Parameters
        ----------
        text:
            The raw payload text to redact.
        findings:
            Detected sensitive-content findings, ordered arbitrarily.

        Returns
        -------
        str
            Text with all finding spans replaced by redaction markers.
        """
        if not findings:
            return text

        # ── Merge overlapping findings ──────────────────────────────
        sorted_f = sorted(findings, key=lambda f: f.start)
        merged: list[tuple[int, int, str]] = []

        for f in sorted_f:
            if merged and f.start <= merged[-1][1]:
                # Extend the previous merged span
                prev_start, prev_end, prev_type = merged[-1]
                merged[-1] = (
                    prev_start,
                    max(prev_end, f.end),
                    prev_type,
                )
            else:
                merged.append((f.start, f.end, f.secret_type))

        # ── Apply replacements in reverse order ─────────────────────
        result = text
        for start, end, secret_type in reversed(merged):
            replacement = f"[REDACTED:{secret_type}]"
            result = result[:start] + replacement + result[end:]

        return result
