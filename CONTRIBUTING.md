# Contributing to AI Context Firewall

Thank you for your interest in contributing! This document outlines the guidelines and workflows for contributing to this project.

## Table of Contents

- [Development Setup](#development-setup)
- [Adding Custom Detection Rules](#adding-custom-detection-rules)
- [Reporting False Positives](#reporting-false-positives)
- [Code Style](#code-style)
- [Testing Requirements](#testing-requirements)
- [Pull Request Checklist](#pull-request-checklist)

---

## Development Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your-org/ai-context-firewall.git
   cd ai-context-firewall
   ```

2. **Create a virtual environment:**

   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux/macOS
   venv\Scripts\activate      # Windows
   ```

3. **Install the package in editable mode with dev dependencies:**

   ```bash
   pip install -e ".[dev]"
   ```

4. **Install pre-commit hooks:**

   ```bash
   pre-commit install
   ```

   This ensures that linting (ruff), formatting, and other checks run automatically before each commit.

---

## Adding Custom Detection Rules

Detection rules are defined in YAML format under the `rules/` directory. Each rule file describes a pattern that the firewall scans for in AI context payloads.

### Rule Structure

```yaml
# rules/my_custom_rule.yaml
name: my-custom-rule
description: Detects patterns that match [describe threat/scenario]
severity: high            # one of: low, medium, high, critical
tags:
  - prompt-injection
  - custom-pattern

patterns:
  - type: regex
    value: "(?:pattern_one|pattern_two)"
    description: "Matches obfuscated instruction override attempts"

  - type: keyword
    value: "ignore previous instructions"
    case_sensitive: false

  - type: semantic
    value: "attempt to override system prompt"
    threshold: 0.85       # optional similarity threshold (0.0 - 1.0)

actions:
  - block                 # one or more of: block, log, alert, sanitize
```

### Rule Fields

| Field        | Required | Description |
|-------------|----------|-------------|
| `name`      | Yes      | Unique rule identifier (kebab-case) |
| `description` | Yes    | Human-readable explanation of the rule |
| `severity`  | Yes      | Risk level (`low`, `medium`, `high`, `critical`) |
| `tags`      | Yes      | List of categorization tags |
| `patterns`  | Yes      | One or more detection patterns (see below) |
| `actions`   | Yes      | Actions to take when the rule triggers |

### Pattern Types

- **`regex`**: Regular expression pattern matching against context payloads.
- **`keyword`**: Exact or case-insensitive keyword matching.
- **`semantic`**: Semantic similarity detection using embeddings (requires `threshold`).

### Validation

Run the rule validator to ensure your YAML is correct:

```bash
python -m firewall validate-rules
```

---

## Reporting False Positives

We take false positives seriously. If a detection rule incorrectly flags legitimate content:

1. **Check open issues** — someone may have already reported it:  
   [https://github.com/your-org/ai-context-firewall/issues](https://github.com/your-org/ai-context-firewall/issues)

2. **Open a new issue** using the **"False Positive Report"** template and include:
   - The rule name that triggered (from logs or alert output)
   - The payload or content that was incorrectly flagged (sanitize any sensitive data)
   - Expected behavior — why this content should be allowed
   - Environment details (version, deployment mode)

3. **For urgent false positives** (blocking production workflows), tag the issue with `critical` and `false-positive`.

Our maintainers aim to confirm or resolve false positive reports within 48 hours.

---

## Code Style

This project uses **ruff** for both linting and formatting.

- **Linting:** Ruff enforces rules equivalent to Flake8, isort, and pyupgrade.
- **Formatting:** Ruff auto-formats code to a consistent style.

Check your code before committing:

```bash
ruff check .
ruff format --check .
```

Auto-fix issues:

```bash
ruff check --fix .
ruff format .
```

Pre-commit runs these checks automatically on `git commit`.

---

## Testing Requirements

- **Coverage threshold:** All contributions must maintain or exceed **80% code coverage**.
- **Test framework:** We use `pytest` with `pytest-cov` for coverage reporting.

Run tests with coverage:

```bash
pytest --cov=firewall --cov-fail-under=80
```

- New features **must** include corresponding unit tests and/or integration tests.
- Bug fixes **must** include a test that reproduces the bug before the fix.
- Tests should cover both positive cases (rule triggers correctly) and negative cases (rule does not trigger on benign content).

---

## Pull Request Checklist

Before submitting a PR, ensure:

- [ ] Code follows the project's style (passes `ruff check .` and `ruff format --check .`)
- [ ] All existing tests pass (`pytest`)
- [ ] New tests cover the changes, with 80%+ overall coverage maintained
- [ ] New detection rules include a test case for expected behavior
- [ ] Documentation is updated if behavior or APIs changed
- [ ] No new false positives introduced — run the false positive test suite if applicable
- [ ] Pre-commit hooks pass on all changed files

### PR Title Format

Use descriptive titles:

```
feat: add sql-injection detection rule
fix: reduce false positives in system-prompt-override rule
docs: update contributing guide with rule examples
test: add coverage for regex pattern edge cases
```

---

Thank you for contributing to making AI context safer for everyone!
