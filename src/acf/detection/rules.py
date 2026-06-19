"""YAML rule loader and rule-merging for AI Context Firewall.

Provides a YAML-based custom-rule loader and a merge routine that
de‑duplicates by rule id, giving custom rules precedence.  The
canonical set of built-in rules is imported from
:mod:`acf.detection.patterns` and re-exported as ``BUILTIN_RULES``
for backwards compatibility.

Usage::

    from acf.detection.rules import BUILTIN_RULES, load_custom_rules, merge_rules

    custom = load_custom_rules("path/to/rules.yaml")
    combined = merge_rules(BUILTIN_RULES, custom)

# TODO: v2 — schema validation via JSON Schema, conflict detection
#       (overlapping patterns with different severities), rule testing
#       harness.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from acf.models.types import RuleDefinition

logger = logging.getLogger(__name__)

# ── Helpers ──────────────────────────────────────────────────────────

# Defaults applied when a YAML entry omits optional fields.
_YAML_FIELD_DEFAULTS: dict[str, Any] = {
    "confidence": "MEDIUM",
    "severity": "WARNING",
    "category": "custom",
}


# ── Built-in rules ───────────────────────────────────────────────────
#
# Imported from patterns.py, the single source of truth for the 18
# built-in detection rules.  Previously rules.py maintained an
# independent (and conflicting) set — that duplicate has been removed
# (Gate 3 Oracle CRITICAL 2.1 fix).

from acf.detection.patterns import PATTERNS as BUILTIN_RULES  # noqa: E402


# ── Public API ───────────────────────────────────────────────────────


def load_custom_rules(path: str | Path) -> list[RuleDefinition]:
    """Load custom rules from a YAML file.

    Expected YAML format — a list of entries with the following keys:

    .. code:: yaml

        - id: my-rule
          name: My custom rule
          pattern: "SECRET_PREFIX_.*"
          confidence: HIGH          # optional, default ``MEDIUM``
          severity: CRITICAL         # optional, default ``WARNING``
          category: my_custom        # optional, default ``custom``

    Parameters
    ----------
    path:
        Path to the YAML file (string or :class:`~pathlib.Path`).

    Returns
    -------
    list[RuleDefinition]
        Validated rule objects.  Entries that fail validation are
        logged as warnings and silently skipped.

    Raises
    ------
    OSError
        If the file cannot be read (permissions, etc.).
    """
    path = Path(path)

    if not path.exists():
        logger.warning("Custom rules file not found: %s", path)
        return []

    raw: list[dict[str, Any]] = yaml.safe_load(path.read_text(encoding="utf-8"))

    if not isinstance(raw, list):
        logger.error(
            "Expected a list of rule entries in %s, got %s", path, type(raw).__name__
        )
        return []

    rules: list[RuleDefinition] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            logger.warning("Entry %d in %s is not a mapping, skipping", idx, path)
            continue

        # Apply defaults for optional fields so that a minimal YAML
        # entry (id + name + pattern) always produces a valid definition.
        for field, default in _YAML_FIELD_DEFAULTS.items():
            entry.setdefault(field, default)

        try:
            rule = RuleDefinition(**entry)
        except ValidationError as exc:
            logger.warning(
                "Entry %d in %s failed validation: %s", idx, path, exc
            )
            continue

        rules.append(rule)

    logger.info("Loaded %d / %d custom rule(s) from %s", len(rules), len(raw), path)
    return rules


def merge_rules(
    builtin: list[RuleDefinition],
    custom: list[RuleDefinition],
) -> list[RuleDefinition]:
    """Merge built-in and custom rule lists, deduplicating by *id*.

    Custom rules **override** built-in rules that share the same id.
    Within custom rules themselves, later entries win when ids collide.
    The resulting list orders custom rules first (preserving their
    relative order after dedup), followed by built-in rules that were
    not overridden.

    Parameters
    ----------
    builtin:
        The built-in rule list (e.g. :data:`BUILTIN_RULES`).
    custom:
        Custom rules loaded from a YAML file.

    Returns
    -------
    list[RuleDefinition]
        Merged, deduplicated list.
    """
    # Deduplicate custom rules: later entries override earlier ones
    seen_custom: dict[str, RuleDefinition] = {}
    for r in custom:
        seen_custom[r.id] = r  # later wins

    custom_ids: set[str] = set(seen_custom.keys())
    merged: list[RuleDefinition] = list(seen_custom.values())

    for rule in builtin:
        if rule.id not in custom_ids:
            merged.append(rule)

    return merged
