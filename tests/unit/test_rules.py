"""Tests for the YAML rule loader (``acf.detection.rules``).

Covers built-in rules, custom YAML loading, error handling, and
merge/dedup logic.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from acf.detection.rules import BUILTIN_RULES, load_custom_rules, merge_rules
from acf.models.types import RuleDefinition, Severity


# ======================================================================
# Built-in rules
# ======================================================================


class TestBuiltinRules:
    """Verify the 18 built-in rule definitions."""

    def test_count(self) -> None:
        """There should be exactly 18 built-in rules."""
        assert len(BUILTIN_RULES) == 18

    def test_all_have_required_fields(self) -> None:
        """Every built-in rule must have a non-empty id, name, and pattern."""
        for rule in BUILTIN_RULES:
            assert rule.id, f"Rule missing id: {rule}"
            assert rule.name, f"Rule missing name: {rule}"
            assert rule.pattern, f"Rule missing pattern: {rule}"

    def test_all_have_valid_severity(self) -> None:
        """Severity must be a recognised member of the Severity enum."""
        valid = {Severity.CRITICAL, Severity.WARNING, Severity.INFO}
        for rule in BUILTIN_RULES:
            assert rule.severity in valid, f"Invalid severity on {rule.id}"

    def test_ids_are_unique(self) -> None:
        """No two built-in rules may share the same id."""
        ids = [r.id for r in BUILTIN_RULES]
        assert len(ids) == len(set(ids)), f"Duplicate ids: {ids}"

    def test_coverage_categories(self) -> None:
        """Built-in rules should cover all expected categories."""
        categories = {r.category for r in BUILTIN_RULES}
        for expected in ("api_key", "token", "private_key", "credential"):
            assert expected in categories, f"Missing category: {expected}"


# ======================================================================
# YAML loading
# ======================================================================


class TestLoadCustomRules:
    """Loading rules from YAML files."""

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        """A non-existent file should produce an empty list, not crash."""
        missing = tmp_path / "does_not_exist.yaml"
        assert load_custom_rules(missing) == []

    def test_empty_file_returns_empty(self, tmp_path: Path) -> None:
        """An empty YAML file (valid but null) returns empty list."""
        f = tmp_path / "empty.yaml"
        f.write_text("", encoding="utf-8")
        assert load_custom_rules(f) == []

    def test_single_rule(self, tmp_path: Path) -> None:
        """A YAML file with one rule loads correctly."""
        f = tmp_path / "single.yaml"
        f.write_text(
            yaml.dump([
                {
                    "id": "test-rule-1",
                    "name": "Test Rule",
                    "pattern": "TEST_PATTERN",
                }
            ]),
            encoding="utf-8",
        )
        rules = load_custom_rules(f)
        assert len(rules) == 1
        assert rules[0].id == "test-rule-1"
        assert rules[0].name == "Test Rule"
        assert rules[0].pattern == "TEST_PATTERN"
        # Defaults applied
        assert rules[0].confidence == "MEDIUM"
        assert rules[0].severity == Severity.WARNING
        assert rules[0].category == "custom"

    def test_multi_rule(self, fixtures_dir: Path) -> None:
        """Load the bundled multi-rule fixture file."""
        f = fixtures_dir / "custom_rules.yaml"
        assert f.exists(), f"Fixture not found: {f}"
        rules = load_custom_rules(f)
        assert len(rules) == 4

    def test_single_rule_explicit_defaults(self, tmp_path: Path) -> None:
        """YAML with explicit confidence / severity / category works."""
        f = tmp_path / "explicit.yaml"
        f.write_text(
            yaml.dump([
                {
                    "id": "explicit-rule",
                    "name": "Explicit",
                    "pattern": "EXPLICIT_.*",
                    "confidence": "HIGH",
                    "severity": "CRITICAL",
                    "category": "test",
                }
            ]),
            encoding="utf-8",
        )
        rules = load_custom_rules(f)
        assert len(rules) == 1
        assert rules[0].confidence == "HIGH"
        assert rules[0].severity == Severity.CRITICAL
        assert rules[0].category == "test"

    def test_invalid_yaml_handled_gracefully(self, tmp_path: Path) -> None:
        """Malformed YAML raises a YAML parse error, not a crash."""
        f = tmp_path / "bad.yaml"
        f.write_text("{not: valid: yaml: [[[", encoding="utf-8")
        with pytest.raises(yaml.YAMLError):
            load_custom_rules(f)

    def test_yaml_not_a_list(self, tmp_path: Path) -> None:
        """When the YAML root is not a list, return empty list."""
        f = tmp_path / "scalar.yaml"
        f.write_text(yaml.dump("just a string"), encoding="utf-8")
        rules = load_custom_rules(f)
        assert rules == []

    def test_invalid_entry_skipped(self, tmp_path: Path) -> None:
        """An entry that fails validation is skipped with a warning."""
        f = tmp_path / "partial.yaml"
        # Missing required field "pattern" -> ValidationError
        f.write_text(
            yaml.dump([
                {"id": "bad-rule", "name": "No Pattern"},
                {"id": "good-rule", "name": "Good", "pattern": "OK"},
            ]),
            encoding="utf-8",
        )
        rules = load_custom_rules(f)
        assert len(rules) == 1
        assert rules[0].id == "good-rule"

    def test_entry_not_a_dict_skipped(self, tmp_path: Path) -> None:
        """A list entry that is not a mapping is skipped."""
        f = tmp_path / "mixed.yaml"
        f.write_text(
            yaml.dump([
                "just a string",
                {"id": "r1", "name": "R1", "pattern": "P1"},
            ]),
            encoding="utf-8",
        )
        rules = load_custom_rules(f)
        assert len(rules) == 1
        assert rules[0].id == "r1"

    def test_extra_fields_ignored(self, tmp_path: Path) -> None:
        """Extra YAML keys not in RuleDefinition are silently accepted."""
        f = tmp_path / "extra.yaml"
        f.write_text(
            yaml.dump([
                {
                    "id": "extra",
                    "name": "Extra",
                    "pattern": "X",
                    "extra_field": "ignored",
                    "notes": "also ignored",
                }
            ]),
            encoding="utf-8",
        )
        rules = load_custom_rules(f)
        assert len(rules) == 1
        assert rules[0].id == "extra"


# ======================================================================
# Merge logic
# ======================================================================


class TestMergeRules:
    """Deduplication and precedence in ``merge_rules``."""

    def test_merge_preserves_builtins(self) -> None:
        """Built-in rules survive merge when no custom rule overrides them."""
        custom = [
            RuleDefinition(id="custom-only", name="Custom", pattern="C"),
        ]
        merged = merge_rules(BUILTIN_RULES, custom)
        # All 18 builtins + 1 custom = 19, unless a builtin was overridden
        builtin_ids = {r.id for r in BUILTIN_RULES}
        merged_ids = {r.id for r in merged}
        assert "custom-only" in merged_ids
        # Every builtin id should still be present
        assert builtin_ids.issubset(merged_ids)

    def test_custom_rule_overrides_builtin(self) -> None:
        """Custom rule with the same id replaces the built-in."""
        overrider = RuleDefinition(
            id="openai-api-key",
            name="Overridden",
            pattern="OVERRIDDEN",
            confidence="LOW",
            severity=Severity.INFO,
            category="override",
        )
        merged = merge_rules(BUILTIN_RULES, [overrider])
        openai = [r for r in merged if r.id == "openai-api-key"]
        assert len(openai) == 1, "Duplicate id leak in merged list"
        assert openai[0].name == "Overridden"
        assert openai[0].pattern == "OVERRIDDEN"
        # Builtin count is 18, merged count should still be 18
        # (because the override replaces, not adds)
        assert len(merged) == 18

    def test_duplicate_custom_ids_last_wins(self) -> None:
        """When two custom rules share an id, the later one wins."""
        custom = [
            RuleDefinition(id="dup", name="First", pattern="A"),
            RuleDefinition(id="dup", name="Second", pattern="B"),
        ]
        merged = merge_rules(BUILTIN_RULES, custom)
        dup = [r for r in merged if r.id == "dup"]
        assert len(dup) == 1
        assert dup[0].name == "Second"

    def test_merge_order_custom_first(self) -> None:
        """Custom rules appear before built-in rules in the merged list."""
        custom = [
            RuleDefinition(id="z-custom", name="A Custom", pattern="C"),
        ]
        merged = merge_rules(BUILTIN_RULES, custom)
        # The first entry should be the custom one
        assert merged[0].id == "z-custom"

    def test_full_fixture_merge(self, fixtures_dir: Path) -> None:
        """Merge the fixture file with builtins and verify dedup."""
        f = fixtures_dir / "custom_rules.yaml"
        custom = load_custom_rules(f)
        merged = merge_rules(BUILTIN_RULES, custom)

        # 18 builtins + 3 unique customs (1 overrides builtin) = 21 …
        # Actually: 18 builtins + 4 customs, but 1 is an override,
        # so count = 18 + (4 - 1) = 21
        assert len(merged) == 21

        # The override should be the custom version
        openai = [r for r in merged if r.id == "openai-api-key"]
        assert len(openai) == 1
        assert openai[0].pattern == "sk-proj-[A-Za-z0-9]{48,}"
