# Changelog

All notable changes to the **AI Context Firewall** project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## 0.1.0 (2026-06-19)

### Phase 1 — Project Scaffolding (commits 1–3)

- Initialize project structure with `pyproject.toml`, `src/acf/` package layout
- Configure build system, dependencies (mitmproxy, click, pydantic, structlog, rich, pyyaml)
- Add dev dependencies: pytest, pytest-cov, pytest-asyncio, httpx, ruff, mypy
- Create `__init__.py` and `__main__.py` entry points

### Phase 2 — Configuration (commits 4–6)

- Implement `config/settings.py` with `AppConfig` class using `pydantic-settings`
- Support all `ACF_*` environment variables (proxy host/port, log dir/level, entropy thresholds, etc.)
- Add `resolved_log_dir` property for `~` expansion
- Add typed defaults and validation

### Phase 3 — Data Models (commits 7–9)

- Define `models/types.py` with core types: `Severity` enum (INFO, WARNING, CRITICAL)
- Add `EventType` enum (pass, redaction, file_block)
- Implement `FileBlockDetail` with `FileBlockRule` enum
- Implement `Finding` model with `FindingSeverity`, source spans, confidence
- Implement `AuditEvent` model for structured audit logging

### Phase 4 — Detection Engine (commits 10–15)

- Build `detection/engine.py` orchestrator coordinating pattern + entropy scanners
- Implement `detection/patterns.py` with 18 built-in regex rules:
  - AWS Access Key ID, AWS Secret Access Key
  - GitHub Classic PAT, GitHub Fine-Grained PAT
  - GitLab PAT, GCP API Key, Slack Token, Stripe Live Key
  - JWT, PEM Private Key Header
  - .env Variable Assignment, Generic Password/Secret Assignment
  - Database URL with Credentials, Bearer Token
  - Databricks Token, Azure Connection String, OpenAI API Key
- Add keyword pre-filtering for performance optimization
- Implement `detection/entropy.py` with Shannon entropy calculator
- Add separate thresholds for base64 and hex strings
- Support minimum length filtering and false-positive suppression
- Implement `detection/rules.py` for YAML custom rule loading and merging with built-ins

### Phase 5 — File Filter (commits 16–18)

- Implement `proxy/file_filter.py` with multi-layered sensitive file blocking
- Extension-based blocking: `.env`, `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`, `.secret`
- Path-based blocking: `~/.ssh/`, `~/.aws/`, `~/.gcloud/`, `~/.azure/` directories
- Content-based blocking: inline PEM private key detection
- Return HTTP 403 with `X-Blocked-By: ACF` header on all blocked requests
- Add `findings_to_block_details()` for converting detection engine findings to block events

### Phase 6 — Redaction (commits 19–21)

- Implement `redaction/redactor.py` with `Finding`-to-`[REDACTED:type]` replacement
- Handle overlapping findings via span merging
- Preserve original text outside redacted spans
- Update `Content-Length` header after modification
- Support both `request_content` and `response_content` redaction contexts

### Phase 7 — Audit Logger (commits 22–24)

- Implement `audit/logger.py` with JSONL log format
- Add automatic log rotation: gzip compression, 5 backup files, 10 MB threshold
- Support `fsync` after every write for crash safety
- Implement `read_events()` for querying the audit trail
- Add thread-safe I/O via `threading.Lock`

### Phase 8 — Proxy Server (commits 25–28)

- Implement `proxy/server.py` with `ProxyServer` class wrapping mitmproxy's `DumpMaster`
- Add background thread execution with asyncio event loop
- Add signal handlers (SIGINT/SIGTERM) for graceful shutdown
- Add PID file management (`write_pid_file`, `read_pid`, `_remove_pid_file`)
- Add daemon mode support: `_redirect_stdio()` for stdout/stderr → log file
- Implement `proxy/targets.py` with known AI API endpoint definitions
- Implement `proxy/intercept.py` with `InterceptAddon` request pipeline addon
- Wire up the full pipeline: Target Filter → File Filter → Detection Engine → Redactor → Audit Logger

### Phase 9 — CLI (commits 29–32)

- Implement `cli.py` with Click-based CLI group and sub-commands
- `acf start` — start the proxy server (`--port`, `--daemon` flags)
- `acf stop` — stop the proxy via PID file + SIGTERM
- `acf status` — show proxy status (running/stopped, PID, port, host)
- `acf scan` — offline scan of files/directories for secrets (`--pretty`)
- `acf audit` — inspect audit log with `--summary`, `--since`, `--until`, `--format`, `--log-path`
- `acf config show` — display current configuration
- `acf setup` — generate CA certificate trust instructions (`--ci` flag)
- Add PID file helpers (`_read_pid`, `_write_pid`, `_remove_pid`)
- Add version reporting via `__version__`

### Phase 10 — Testing & CI (commits 33–34)

- Add `[tool.coverage.run]` with `branch = true` and `[tool.coverage.report]` with `fail_under = 80`
- Add Ruff configuration (`select = ["ALL"]`, `target-version = "py311"`)
- Add mypy strict mode configuration
- Add `pytest.ini_options` with test discovery paths
- Configure comprehensive Python classifiers (3.11–3.13, MIT License, Security topic)

### Phase 11 — Documentation & Release (commits 35–36)

- Create comprehensive `README.md` with:
  - Problem statement and motivation
  - 30-second quickstart with `curl` verification
  - Architecture diagram and pipeline step explanations
  - Full CLI reference for all commands
  - Integration guides for Cursor, GitHub Copilot, Claude Code
  - CI/CD deployment examples (Docker, GitHub Actions, GitLab CI)
  - Security model with threat analysis and audit guarantees
  - Troubleshooting section
  - Contributor guide and project layout
- Create `CHANGELOG.md` (this file)
- Set version to `0.1.0` for initial alpha release
- Add author metadata and classifiers to `pyproject.toml`

---

## [Unreleased]

### Planned

- S4: WebSocket message interception (`websocket_message` hook)
- Custom rule hot-reload without proxy restart
- `acf rules` sub-command for listing/testing custom rules
- Prometheus metrics endpoint
- Docker official image
- macOS tray app for visual status
- v0.2: Structured output mode (JSON events to stdout for container environments)
