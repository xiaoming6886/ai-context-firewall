# AI Context Firewall

> Your AI coding assistant is uploading your secrets. Stop it.

[![CI](https://github.com/xiaoming6886/ai-context-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/xiaoming6886/ai-context-firewall/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/ai-context-firewall)](https://pypi.org/project/ai-context-firewall/)
[![Python 3.11+](https://img.shields.io/pypi/pyversions/ai-context-firewall)](https://pypi.org/project/ai-context-firewall/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Table of Contents

1. [The Problem](#1-the-problem)
2. [30-Second Quickstart](#2-30-second-quickstart)
3. [Architecture](#3-architecture)
4. [CLI Reference](#4-cli-reference)
5. [Integration Guide](#5-integration-guide)
6. [CI/CD Deployment](#6-cicd-deployment)
7. [Security Model](#7-security-model)
8. [Troubleshooting](#8-troubleshooting)
9. [Contributing](#9-contributing)
10. [License](#10-license)

---

## 1. The Problem

In 2023, Samsung employees pasted proprietary source code and internal data into ChatGPT. The data ended up on OpenAI's servers. There was no alert, no block, no audit trail. Just a leak.

This is not a one-off. Every day, developers feed AI coding assistants sensitive content:

- **API keys and tokens** stored in `.env` files, passed directly in prompts
- **AWS credentials** and cloud provider secrets embedded in config files
- **Private keys** (SSH, PGP, TLS) sitting in `~/.ssh/` or project directories
- **Database connection strings** with hardcoded passwords
- **Proprietary source code** that never should have left the building

Cursor, Copilot, and Claude Code are powerful, but they are also HTTPS clients. Their traffic goes to external servers. Without a guard in the middle, you have no idea what is leaving your machine.

AI Context Firewall (ACF) is that guard. It sits between your AI tools and their upstream APIs, intercepting every request, inspecting the payload, and redacting or blocking sensitive content before it goes anywhere. And it logs everything so you know exactly what was caught.

---

## 2. 30-Second Quickstart

```bash
# Install
pip install ai-context-firewall

# Start the proxy (default: http://127.0.0.1:8080)
acf start

# Set your AI tool to route through ACF
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
export NO_PROXY=localhost,127.0.0.1

# Use your AI tool as normal. ACF inspects every request.
# Check what it caught:
acf audit --summary
```

That is it. Your AI traffic is now firewalled.

### Verify it works

Open a new terminal and send a test payload with a fake secret:

```bash
curl -x http://127.0.0.1:8080 \
  -H "Content-Type: application/json" \
  -d '{"code": "My API key is sk-abc123def456xyz"}' \
  https://api.anthropic.com/v1/messages
```

Then check the audit log:

```bash
$ acf audit --summary
Total events   1
Date range     2026-06-19 — 2026-06-19

By severity
  WARNING      1

By event type
  redaction    1
```

The secret was caught and redacted before it reached the API.

---

## 3. Architecture

ACF is an MITM (man-in-the-middle) proxy that plugs into mitmproxy's request pipeline. Here is how it works:

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │                        AI Context Firewall                           │
  │                                                                      │
  │  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐       │
  │  │  1.      │    │  2.      │    │  3.      │    │  4.      │       │
  │  │  Target  │───▶│  File    │───▶│  Detect  │───▶│  Redact  │──┐    │
  │  │  Filter  │    │  Filter  │    │  Engine  │    │          │  │    │
  │  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │    │
  │       │               │               │               │         │    │
  │       │  not AI       │  sensitive    │  no secrets   │         │    │
  │       │  endpoint     │  file found   │  found        │         │    │
  │       ▼               ▼               ▼               │         │    │
  │  ┌──────────┐    ┌──────────┐    ┌──────────┐         │         │    │
  │  │  Pass    │    │  Block   │    │  Pass    │         │         │    │
  │  │  Through │    │  403     │    │  Through │         │         │    │
  │  └──────────┘    └──────────┘    └──────────┘         │         │    │
  │                                                       │         │    │
  │                                          ┌────────────┘         │    │
  │                                          ▼                      ▼    │
  │                                    ┌───────────────────────────────┐ │
  │                                    │  5. Audit Logger (JSONL)      │ │
  │                                    │  - file_block: CRITICAL       │ │
  │                                    │  - redaction: WARNING         │ │
  │                                    │  - pass: INFO                 │ │
  │                                    └───────────────────────────────┘ │
  └──────────────────────────────────────────────────────────────────────┘
            │
            ▼
  ┌─────────────────────┐
  │   AI API Provider   │
  │   (Anthropic,       │
  │    OpenAI, GitHub,  │
  │    Cursor)          │
  └─────────────────────┘
```

### Pipeline steps explained

1. **Target Filter** — checks the request URL against known AI API endpoints (`api.anthropic.com`, `api.githubcopilot.com`, `api2.cursor.sh`, `api.openai.com`). Non-AI traffic passes through without inspection.

2. **File Filter** — blocks sensitive files before they can be scanned. Checks for dangerous extensions (`.env`, `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`, `.secret`), sensitive directory paths (`~/.ssh/`, `~/.aws/`, `~/.gcloud/`, `~/.azure/`), and inline PEM private key blocks. Returns HTTP 403 with a `X-Blocked-By: ACF` header.

3. **Detection Engine** — runs two parallel scanners:
   - **Pattern Detector** — 18 built-in regex rules for API keys (AWS, GitHub, GitLab, GCP, OpenAI, Stripe, Slack, Databricks), JWT tokens, private key headers, database URLs, and more. Uses keyword pre-filtering to skip irrelevant rules.
   - **Entropy Detector** — finds high-entropy strings (base64, hex) that match secret patterns, catching things no regex covers.

4. **Redactor** — replaces each finding with a `[REDACTED:<secret_type>]` marker. Handles overlapping findings by merging spans. Updates Content-Length on the modified request.

5. **Audit Logger** — writes every decision to a JSONL file with automatic rotation (gzip, 5 backups). Events are categorized by severity: CRITICAL (file blocks), WARNING (redactions), INFO (pass-throughs).

### Built-in detection rules (18)

| # | Rule | Example Match | Severity |
|---|------|---------------|----------|
| 1 | AWS Access Key ID | `AKIAIOSFODNN7EXAMPLE` | CRITICAL |
| 2 | AWS Secret Access Key | `aws_secret_access_key = ...` | CRITICAL |
| 3 | GitHub Classic PAT | `ghp_abc...` (36 chars) | CRITICAL |
| 4 | GitHub Fine-Grained PAT | `github_pat_...` (82+ chars) | CRITICAL |
| 5 | GitLab PAT | `glpat-...` (20+ chars) | CRITICAL |
| 6 | GCP API Key | `AIza...` (35 chars) | CRITICAL |
| 7 | Slack Token | `xoxb-...` | CRITICAL |
| 8 | Stripe Live Key | `sk_live_...` (24+ chars) | CRITICAL |
| 9 | JWT | `eyJ...` three-dot base64url | WARNING |
| 10 | PEM Private Key Header | `-----BEGIN ... PRIVATE KEY-----` | CRITICAL |
| 11 | .env Variable Assignment | `DATABASE_URL=...`, `SECRET_KEY=...` | WARNING |
| 12 | Generic Password Assignment | `password = "..."` (quoted) | WARNING |
| 13 | Generic Secret Assignment | `api_key = "..."` (quoted) | WARNING |
| 14 | Database URL with Credentials | `postgres://user:pass@host/db` | CRITICAL |
| 15 | Bearer Token | `Bearer <token>` (20+ chars) | WARNING |
| 16 | Databricks Token | `dapi...` (32+ chars) | CRITICAL |
| 17 | Azure Connection String | `DefaultEndpointsProtocol=https;...` | CRITICAL |
| 18 | OpenAI API Key | `sk-...` (20+ chars) | CRITICAL |

Custom rules can be added via YAML. See the [rules documentation](docs/rules.md).

---

## 4. CLI Reference

All commands are accessed through the `acf` binary.

### `acf start`

Start the proxy server.

```bash
acf start                          # default port 8080
acf start --port 9090              # custom port
acf start --daemon                 # background process
```

Output:

```
$ acf start
Starting ACF proxy on 127.0.0.1:8080...
Proxy started (PID 45231).
```

### `acf stop`

Stop the running proxy.

```bash
acf stop
```

Output:

```
$ acf stop
Stopping ACF proxy (PID 45231)...
Proxy stopped.
```

### `acf status`

Check if the proxy is running.

```bash
acf status
```

Output when running:

```
Status: running
PID:    45231
Port:   8080
Host:   127.0.0.1
```

Output when stopped:

```
Status: stopped
```

### `acf scan`

Offline scan a file or directory for secrets without running the proxy.

```bash
acf scan ./project                 # scan a directory
acf scan .env                      # scan a single file
acf scan ./project --pretty        # pretty-print JSON output
```

Output:

```json
$ acf scan .env --pretty
[
  {
    "secret_type": "env-var-assignment",
    "start": 0,
    "end": 36,
    "confidence": "MEDIUM",
    "matched_rule": "env-var-assignment",
    "file": ".env"
  },
  {
    "secret_type": "openai-api-key",
    "start": 42,
    "end": 65,
    "confidence": "HIGH",
    "matched_rule": "openai-api-key",
    "file": ".env"
  }
]
```

Skips binary files, large files (>5 MB), and common compiled extensions automatically.

### `acf audit`

View the audit log. Shows events recorded by the proxy.

```bash
acf audit                          # table of all events
acf audit --summary                # aggregated summary
acf audit --since 2026-06-01       # filter by start date
acf audit --until 2026-06-19       # filter by end date
acf audit --format json            # JSON output
acf audit --log-path ~/custom/audit.jsonl  # custom log path
```

Summary output:

```
$ acf audit --summary
Total events   14
Date range     2026-06-18 — 2026-06-19

By severity
  CRITICAL      2
  WARNING       3
  INFO          9

By event type
  file_block    2
  redaction     3
  pass          9

By source
  proxy         14

Top finding types
  openai-api-key      2
  aws-access-key      1

Events per day
  2026-06-18          6
  2026-06-19          8
```

Events table:

```
$ acf audit
                          Audit events (5 total)
┏━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━┳━━━━━━━━┓
┃ Timestamp               ┃ Severity ┃ Type       ┃ URL                     ┃ Source┃ Findings ┃ Blocks ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━╇━━━━━━━━┩
│ 2026-06-19T10:15:30+00 │ CRITICAL │ file_block │ https://api.anthropic... │ proxy │        0 │      1 │
│ 2026-06-19T10:16:00+00 │ WARNING  │ redaction  │ https://api.openai.co... │ proxy │        2 │      0 │
│ 2026-06-19T10:16:30+00 │ WARNING  │ redaction  │ https://api.anthropic... │ proxy │        1 │      0 │
│ 2026-06-19T10:17:00+00 │ INFO     │ pass       │ https://api.githubcop... │ proxy │        0 │      0 │
│ 2026-06-19T10:17:30+00 │ INFO     │ pass       │ https://api2.cursor.sh   │ proxy │        0 │      0 │
└────────────────────────┴──────────┴────────────┴─────────────────────────┴───────┴──────────┴────────┘
```

### `acf config show`

Display the current configuration.

```bash
acf config show
```

Output:

```
$ acf config show
ACF Configuration
========================================
proxy_host:                127.0.0.1
proxy_port:                8080
log_dir:                   ~/.acf/logs
log_level:                 INFO
file_filter_enabled:       True
entropy_enabled:           True
entropy_base64_threshold:  4.5
entropy_hex_threshold:     3.0
entropy_min_length:        20
max_body_size_mb:          10
```

### `acf setup`

Generate CA certificate trust instructions and proxy configuration.

```bash
acf setup                        # interactive instructions
acf setup --ci                    # CI/CD-friendly output
```

### `acf --help`

Top-level help:

```
$ acf --help
Usage: acf [OPTIONS] COMMAND [ARGS]...

  AI Context Firewall - intercept, inspect, and sanitize AI context windows.

Options:
  --version  Show version and exit.
  --help     Show this message and exit.

Commands:
  audit   Inspect and analyze audit log records
  config  Manage ACF configuration
  scan    Offline scan of a file or directory for secrets
  setup   Generate CA certificate trust instructions
  start   Start the proxy server
  status  Show proxy status (running/stopped, port, PID)
  stop    Stop the proxy server
```

### Environment variables

All settings can be configured via `ACF_` prefixed environment variables. No config file is required.

| Variable | Default | Description |
|----------|---------|-------------|
| `ACF_PROXY_HOST` | `127.0.0.1` | Address the proxy binds to |
| `ACF_PROXY_PORT` | `8080` | Port the proxy listens on |
| `ACF_LOG_DIR` | `~/.acf/logs` | Directory for log files |
| `ACF_LOG_LEVEL` | `INFO` | Logging verbosity |
| `ACF_FILE_FILTER_ENABLED` | `true` | Enable file path/content filter |
| `ACF_ENTROPY_ENABLED` | `true` | Enable entropy-based scanning |
| `ACF_ENTROPY_BASE64_THRESHOLD` | `4.5` | Base64 entropy threshold (0.0-8.0) |
| `ACF_ENTROPY_HEX_THRESHOLD` | `3.0` | Hex entropy threshold (0.0-8.0) |
| `ACF_ENTROPY_MIN_LENGTH` | `20` | Min string length for entropy analysis |
| `ACF_MAX_BODY_SIZE_MB` | `10` | Max request/response body size |

---

## 5. Integration Guide

### Cursor

Edit `~/.cursor/settings.json`:

```json
{
  "proxy": {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080",
    "no_proxy": "localhost,127.0.0.1"
  }
}
```

Restart Cursor. ACF intercepts all traffic to `api2.cursor.sh`.

### GitHub Copilot (VS Code)

Set environment variables before launching VS Code:

```bash
export HTTPS_PROXY=http://localhost:8080
export HTTP_PROXY=http://localhost:8080
export NO_PROXY=localhost,127.0.0.1
code .
```

Alternatively, in VS Code `settings.json`:

```json
{
  "http.proxy": "http://localhost:8080",
  "http.proxyStrictSSL": false
}
```

### Claude Code

```bash
export HTTPS_PROXY=http://localhost:8080
export HTTP_PROXY=http://localhost:8080
export NO_PROXY=localhost,127.0.0.1
claude
```

Claude Code reads proxy settings from environment at startup. Restart if you change the proxy while it is running.

### Other tools

Most AI tools that respect `HTTPS_PROXY` just need the environment variable set. For tools that don't, check their documentation for proxy configuration.

### CA certificate

The proxy needs a trusted CA certificate to inspect HTTPS traffic. Run `acf setup` for platform-specific instructions.

```bash
# Generate the CA certificate
acf setup

# Linux (Debian/Ubuntu)
sudo cp ~/.acf/certs/acf-ca-cert.pem /usr/local/share/ca-certificates/
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.acf/certs/acf-ca-cert.pem

# Windows
certutil -addstore -f "ROOT" %USERPROFILE%\.acf\certs\acf-ca-cert.pem
```

---

## 6. CI/CD Deployment

ACF runs as a sidecar proxy in CI pipelines. See the full [CI/CD Deployment Guide](docs/ci-deployment.md) for Docker, GitHub Actions, and GitLab CI setups.

### Docker

```dockerfile
FROM python:3.11-alpine
RUN pip install ai-context-firewall
EXPOSE 8080
CMD ["acf", "start"]
```

### GitHub Actions (quick start)

```yaml
- name: Install and start ACF
  run: |
    pip install ai-context-firewall
    acf start --daemon
    for i in $(seq 1 10); do
      acf status | grep -q "running" && break
      sleep 1
    done

- name: Run tests with ACF protection
  run: |
    export HTTPS_PROXY=http://127.0.0.1:8080
    export HTTP_PROXY=http://127.0.0.1:8080
    export NO_PROXY=localhost,127.0.0.1
    pytest

- name: Check audit log
  run: acf audit --summary

- name: Stop ACF
  run: acf stop
```

---

## 7. Security Model

### What ACF protects

- **API keys and tokens** sent in prompts or context to AI coding assistants
- **Cloud credentials** (AWS, GCP, Azure) leaked through config files or code
- **Private keys** (SSH, TLS, PGP) accidentally included in context windows
- **Database credentials** embedded in connection strings
- **Sensitive files** (`.env`, `.pem`, `.key`) blocked before they can be uploaded
- **High-entropy secrets** that match no known pattern but look like credentials

### What ACF does NOT protect

- **Non-AI traffic** — ACF only inspects requests to known AI API endpoints. Traffic to other destinations passes through untouched.
- **WebSocket connections** — The current version inspects HTTP request/response bodies only. WebSocket messages are not intercepted (planned for v0.2).
- **Outbound DNS / network-layer exfiltration** — ACF works at the application layer. It cannot stop a compromised tool from exfiltrating data through DNS tunnels or other network-level channels.
- **Encrypted local storage** — ACF does not encrypt your files or secrets on disk. It only prevents them from being sent to AI providers.
- **Zero-day secrets** — Custom secrets that do not match any known pattern and fall below the entropy threshold may pass through. You can add custom rules to cover them.

### Threat model

| Threat | Mitigated? | Notes |
|--------|-----------|-------|
| Accidental secret in prompt | ✅ Yes | Caught by pattern + entropy detection |
| Malicious AI tool leaking data | ✅ Yes | Proxy intercepts all outbound requests |
| Insider threat (local) | ❌ No | ACF is a local process; admin can disable it |
| Certificate bypass (pinning) | ⚠️ Partial | Pinned connections fail; logged as WARNING |
| WebSocket exfiltration | ❌ No | Not yet intercepted (v0.2 roadmap) |
| Side-channel timing attacks | ❌ No | Not in scope |

### Audit guarantees

Every audit event is flushed and fsynced to disk before the request is forwarded. This guarantees that if the proxy crashes, no event is lost after the write. Logs are JSONL format for easy ingestion into SIEM systems.

---

## 8. Troubleshooting

### Proxy won't start

```
Error: address already in use
```

Something is already on port 8080. Find it with `lsof -i :8080` (macOS/Linux) or `netstat -ano | findstr :8080` (Windows), or pick a different port:

```bash
acf start --port 9090
```

### Traffic is not being intercepted

1. Is the proxy running? `acf status`
2. Is your tool configured to use the proxy? Check `HTTPS_PROXY` is set.
3. Is your tool one of the supported targets? ACF only inspects traffic to `api.anthropic.com`, `api.githubcopilot.com`, `api2.cursor.sh`, and `api.openai.com`.
4. Does the tool trust the ACF CA certificate? Run `acf setup` for instructions.

### Nothing in the audit log

Run this test to verify interception works:

```bash
curl -x http://127.0.0.1:8080 \
  -H "Content-Type: application/json" \
  -d '{"code": "sk-test1234567890abcdef"}' \
  https://api.anthropic.com/v1/messages

acf audit --summary
```

If you see a WARNING event, interception is working.

### TLS / certificate errors

Set the ACF CA certificate as trusted:

```bash
export REQUESTS_CA_BUNDLE=~/.acf/certs/acf-ca-cert.pem
export SSL_CERT_FILE=~/.acf/certs/acf-ca-cert.pem
export NODE_EXTRA_CA_CERTS=~/.acf/certs/acf-ca-cert.pem
```

### Certificate pinning

Some services (like S3) pin their TLS certificates. ACF cannot intercept pinned connections. The proxy logs a WARNING and the connection fails open. Add pinned domains to `NO_PROXY`:

```bash
export NO_PROXY="localhost,127.0.0.1,*.s3.amazonaws.com,*.amazonaws.com"
```

---

## 9. Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:

- Setting up a development environment
- Running tests (`pytest`)
- Code style (ruff + mypy strict mode)
- Adding new detection rules
- Submitting pull requests

### Quick start for contributors

```bash
git clone https://github.com/xiaoming6886/ai-context-firewall.git
cd ai-context-firewall
pip install -e ".[dev]"
pytest
```

### Project layout

```
src/acf/
  cli.py              # CLI commands (start, stop, status, scan, audit, config, setup)
  proxy/
    server.py         # mitmproxy lifecycle management
    intercept.py      # request pipeline addon (filter -> detect -> redact -> audit)
    targets.py        # AI API endpoint definitions
    file_filter.py    # file extension/path/content blocker
  detection/
    engine.py         # orchestrates pattern + entropy detectors
    patterns.py       # 18 built-in regex rules + PatternDetector
    entropy.py        # Shannon entropy scanner for high-entropy strings
    rules.py          # YAML custom rule loader + merge logic
  redaction/
    redactor.py       # finding-to-[REDACTED:type] replacement
  audit/
    logger.py         # JSONL audit logger with rotation
  config/
    settings.py       # pydantic-settings (ACF_ env vars)
  models/
    types.py          # Finding, AuditEvent, RuleDefinition, enums
```

---

## 10. License

MIT License. See [LICENSE](LICENSE) for details.

---

*AI Context Firewall v0.1.0*  
*Last updated: 2026-06-19*
