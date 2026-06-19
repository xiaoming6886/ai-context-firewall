# CI/CD Deployment — AI Context Firewall

> Run ACF as a sidecar proxy in CI pipelines, Docker containers, and headless environments.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Daemon Startup Mode](#2-daemon-startup-mode)
3. [Docker Sidecar Setup](#3-docker-sidecar-setup)
4. [GitHub Actions](#4-github-actions)
5. [GitLab CI](#5-gitlab-ci)
6. [Environment Variable Configuration](#6-environment-variable-configuration)
7. [Verification in CI](#7-verification-in-ci)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Overview

AI Context Firewall (ACF) is designed to run as a **sidecar proxy** in CI/CD pipelines.
It intercepts HTTPS traffic from AI coding assistants (Cursor, Copilot, Claude Code)
and prevents sensitive data (API keys, credentials, secrets) from leaking to AI providers.

### CI deployment model

```
┌──────────────────────────────────────────┐
│              CI Job Container            │
│                                          │
│  ┌────────────────┐  ┌────────────────┐  │
│  │   AI Tool /    │  │  ACF Sidecar   │  │
│  │   Test Suite   │──│  (acf --daemon) │  │
│  │                │  │                │  │
│  │ HTTPS_PROXY ───┼──▶ localhost:8080  │  │
│  └────────────────┘  └────────────────┘  │
└──────────────────────────────────────────┘
```

**Key principles:**

- ACF starts **before** the tool under test / AI assistant
- ACF runs in **daemon mode** (background process)
- The tool is configured to route through ACF via `HTTPS_PROXY`
- ACF stops **after** the pipeline step completes
- Audit logs are collected for compliance verification

---

## 2. Daemon Startup Mode

The `--daemon` flag runs ACF as a **background process** that detaches from the
terminal, making it suitable for CI pipelines, Docker containers, and headless
environments.

### Basic usage

```bash
# Start in background — returns immediately
acf start --daemon

# The proxy is now listening (default: http://127.0.0.1:8080)
# PID is written to ~/.acf/acf.pid

# Check status
acf status

# Run your AI tool or tests here ...

# Stop the proxy
acf stop
```

### How it works

| Aspect              | Behavior                                                     |
|---------------------|--------------------------------------------------------------|
| Process model       | Forks to background; parent shell exits immediately           |
| PID file            | Written to `~/.acf/acf.pid` for lifecycle management          |
| Log output          | Redirected to `~/.acf/logs/proxy.log` (not stdout)           |
| Signal handling     | `SIGTERM` triggers graceful shutdown via `acf stop`           |
| Startup check       | `acf status` returns `running` with PID when ready            |
| Stop behavior       | `acf stop` sends `SIGTERM`, waits for shutdown, removes PID   |

### Example: start → work → stop lifecycle

```bash
# 1. Start daemon
acf start --daemon

# 2. Wait until proxy is ready
for i in $(seq 1 10); do
  if acf status | grep -q "running"; then
    echo "ACF is ready"
    break
  fi
  sleep 1
done

# 3. Run your AI-dependent tasks
export HTTPS_PROXY=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
export NO_PROXY=localhost,127.0.0.1

# 4. Collect audit summary
acf audit --summary

# 5. Stop daemon
acf stop
```

### Startup failure handling

If the proxy fails to start (e.g., port conflict, missing CA certificate),
`acf start --daemon` exits with a non-zero code and writes an error to the log:

```bash
acf start --daemon && sleep 2 && acf status
# If status is not "running", check logs:
cat ~/.acf/logs/proxy.log
```

---

## 3. Docker Sidecar Setup

### Dockerfile

Use this multi-stage Dockerfile to build a minimal ACF sidecar image:

```dockerfile
# Stage 1: Build from source (optional — use pip image for release)
FROM python:3.11-slim AS builder

WORKDIR /build
COPY . .
RUN pip install --no-cache-dir .

# Stage 2: Minimal runtime image
FROM python:3.11-alpine

RUN apk add --no-cache ca-certificates

# Copy installed ACF from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/acf /usr/local/bin/acf

# Expose the proxy port
EXPOSE 8080

# Generate CA certificate on first start
RUN acf setup --ci || true

# Health check — ensure proxy is responsive
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=3 \
  CMD acf status | grep -q "running" || exit 1

# Default command: start in daemon mode
CMD ["acf", "start", "--daemon"]
```

> **Tip**: For production use, replace the builder stage with
> `FROM ai-context-firewall:latest` or pull from your registry.

### docker-compose.yml

Sidecar alongside an AI tool or test suite:

```yaml
version: "3.8"

services:
  # ── ACF sidecar ──────────────────────────────────────────────
  acf:
    build:
      context: .
      dockerfile: Dockerfile.acf
    image: ai-context-firewall:latest
    container_name: acf-sidecar
    ports:
      - "8080:8080"
    environment:
      ACF_PROXY_PORT: "8080"
      ACF_LOG_LEVEL: "INFO"
      ACF_FILE_FILTER_ENABLED: "true"
      ACF_ENTROPY_ENABLED: "true"
    volumes:
      - acf-data:/root/.acf
    healthcheck:
      test: ["CMD", "acf", "status"]
      interval: 5s
      timeout: 3s
      retries: 5
      start_period: 5s
    restart: unless-stopped

  # ── Your application (example) ───────────────────────────────
  app:
    build: .
    container_name: ai-workload
    depends_on:
      acf:
        condition: service_healthy
    environment:
      HTTPS_PROXY: "http://acf:8080"
      HTTP_PROXY: "http://acf:8080"
      NO_PROXY: "localhost,127.0.0.1"
    volumes:
      - .:/work

volumes:
  acf-data:
```

### Docker Compose — CI variant (ephemeral)

For one-shot CI jobs, use `docker compose run` instead of `up`:

```yaml
# docker-compose.ci.yml
version: "3.8"

services:
  acf:
    image: ai-context-firewall:latest
    environment:
      ACF_PROXY_PORT: "8080"
      ACF_LOG_LEVEL: "WARNING"
    healthcheck:
      test: ["CMD", "acf", "status"]
      interval: 2s
      timeout: 2s
      retries: 10
      start_period: 3s

  test:
    build: .
    depends_on:
      acf:
        condition: service_healthy
    environment:
      HTTPS_PROXY: "http://acf:8080"
      HTTP_PROXY: "http://acf:8080"
      NO_PROXY: "localhost,127.0.0.1"
      ACF_AUDIT_LOG: "/tmp/acf-audit.jsonl"
    command: ["pytest", "tests/"]
```

Run with:

```bash
docker compose -f docker-compose.ci.yml run --rm test
docker compose -f docker-compose.ci.yml logs acf
docker compose -f docker-compose.ci.yml down
```

### Kubernetes sidecar (Pod spec)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ai-workload-with-acf
spec:
  containers:
    - name: acf
      image: ai-context-firewall:latest
      command: ["acf", "start", "--daemon"]
      ports:
        - containerPort: 8080
      env:
        - name: ACF_PROXY_PORT
          value: "8080"
        - name: ACF_LOG_LEVEL
          value: "INFO"
      readinessProbe:
        exec:
          command: ["acf", "status"]
        initialDelaySeconds: 3
        periodSeconds: 5

    - name: app
      image: my-ai-workload:latest
      env:
        - name: HTTPS_PROXY
          value: "http://localhost:8080"
        - name: HTTP_PROXY
          value: "http://localhost:8080"
        - name: NO_PROXY
          value: "localhost,127.0.0.1"
```

---

## 4. GitHub Actions

### Basic workflow

```yaml
name: CI with ACF

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  ai-safety-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install ACF
        run: |
          pip install ai-context-firewall
          acf setup --ci

      - name: Install CA certificate (Linux)
        run: |
          sudo cp ~/.acf/ca/acf-ca-cert.pem /usr/local/share/ca-certificates/
          sudo update-ca-certificates

      - name: Start ACF daemon
        run: |
          acf start --daemon
          # Wait for proxy to be ready
          for i in $(seq 1 10); do
            if acf status | grep -q "running"; then
              echo "ACF proxy is running"
              break
            fi
            sleep 1
          done

      - name: Run tests (traffic routed through ACF)
        run: |
          export HTTPS_PROXY=http://127.0.0.1:8080
          export HTTP_PROXY=http://127.0.0.1:8080
          export NO_PROXY=localhost,127.0.0.1
          # Your AI-dependent commands here
          pytest tests/ --ai-integration

      - name: Collect ACF audit summary
        run: acf audit --summary

      - name: Stop ACF daemon
        run: acf stop
```

### Advanced workflow with Docker Compose

```yaml
name: CI with ACF (Docker)

on:
  push:
    branches: [main]

jobs:
  docker-ci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build ACF Docker image
        run: docker build -f Dockerfile.acf -t ai-context-firewall:ci .

      - name: Start services
        run: docker compose -f docker-compose.ci.yml up -d acf

      - name: Wait for ACF health
        run: |
          timeout 30s bash -c '
            until docker compose -f docker-compose.ci.yml exec acf acf status | grep running; do
              sleep 2
            done
          '

      - name: Run test suite
        run: |
          docker compose -f docker-compose.ci.yml run --rm test

      - name: Collect ACF audit logs
        run: |
          docker compose -f docker-compose.ci.yml logs acf
          docker compose -f docker-compose.ci.yml exec acf cat ~/.acf/logs/audit.log

      - name: Stop services
        run: docker compose -f docker-compose.ci.yml down
```

### Matrix: multiple ACF configs

```yaml
jobs:
  acf-matrix:
    strategy:
      matrix:
        entropy-threshold: [3.0, 4.5, 6.0]
        file-filter: [true, false]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install ACF
        run: pip install ai-context-firewall

      - name: Start ACF with config
        run: |
          export ACF_ENTROPY_BASE64_THRESHOLD=${{ matrix.entropy-threshold }}
          export ACF_FILE_FILTER_ENABLED=${{ matrix.file-filter }}
          acf start --daemon
          sleep 3

      - name: Run tests
        run: |
          export HTTPS_PROXY=http://127.0.0.1:8080
          pytest tests/

      - name: Audit
        run: acf audit --summary

      - name: Stop
        run: acf stop
```

---

## 5. GitLab CI

### Basic job

```yaml
# .gitlab-ci.yml

stages:
  - setup
  - test
  - audit

variables:
  ACF_PROXY_PORT: "8080"
  ACF_LOG_LEVEL: "WARNING"
  ACF_FILE_FILTER_ENABLED: "true"
  ACF_ENTROPY_ENABLED: "true"

image: python:3.11-slim

acf-setup:
  stage: setup
  script:
    - pip install ai-context-firewall
    - acf setup --ci
    - apt-get update && apt-get install -y ca-certificates
    - cp ~/.acf/ca/acf-ca-cert.pem /usr/local/share/ca-certificates/
    - update-ca-certificates
  artifacts:
    paths:
      - ~/.acf/
    expire_in: 1 hour

acf-test:
  stage: test
  needs: ["acf-setup"]
  script:
    # Start ACF in background
    - acf start --daemon
    # Wait until proxy is ready
    - 'for i in $(seq 1 10); do acf status | grep -q running && break; sleep 1; done'
    # Route AI traffic through ACF
    - export HTTPS_PROXY=http://127.0.0.1:8080
    - export HTTP_PROXY=http://127.0.0.1:8080
    - export NO_PROXY=localhost,127.0.0.1
    # Run your AI-dependent tests
    - pytest tests/ --ai-integration
    # Stop ACF
    - acf stop

acf-audit:
  stage: audit
  needs: ["acf-test"]
  script:
    # The audit log should still be available if ACF left it behind
    - acf audit --summary || echo "No audit log available"
  artifacts:
    paths:
      - ~/.acf/logs/
    reports:
      metrics: ~/.acf/logs/audit.log
    expire_in: 30 days
```

### Docker-based GitLab job

```yaml
acf-docker-test:
  stage: test
  image: docker:27
  services:
    - docker:dind
  variables:
    DOCKER_COMPOSE_VERSION: "2"
  before_script:
    - apk add --no-cache docker-compose
  script:
    - docker compose -f docker-compose.ci.yml up -d acf
    - docker compose -f docker-compose.ci.yml run --rm test
    - docker compose -f docker-compose.ci.yml logs acf
    - docker compose -f docker-compose.ci.yml down
```

### GitLab CI with parallel matrix

```yaml
acf-matrix-test:
  stage: test
  parallel:
    matrix:
      - ACF_ENTROPY_BASE64_THRESHOLD: ["3.0", "4.5", "6.0"]
        ACF_FILE_FILTER_ENABLED: ["true", "false"]
  script:
    - pip install ai-context-firewall
    - export ACF_ENTROPY_BASE64_THRESHOLD=$ACF_ENTROPY_BASE64_THRESHOLD
    - export ACF_FILE_FILTER_ENABLED=$ACF_FILE_FILTER_ENABLED
    - acf start --daemon
    - sleep 3
    - export HTTPS_PROXY=http://127.0.0.1:8080
    - pytest tests/
    - acf audit --summary
    - acf stop
```

---

## 6. Environment Variable Configuration

All ACF configuration is driven by environment variables with the `ACF_` prefix.
No config file is required — ideal for containerised and CI environments.

### Complete reference

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ACF_PROXY_HOST` | `str` | `127.0.0.1` | Address the mitmproxy binds to |
| `ACF_PROXY_PORT` | `int` | `8080` | Port the mitmproxy listens on (1–65535) |
| `ACF_LOG_DIR` | `str` | `~/.acf/logs` | Directory for log files (`~` is expanded) |
| `ACF_LOG_LEVEL` | `str` | `INFO` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `ACF_FILE_FILTER_ENABLED` | `bool` | `true` | Enable file-path/content filter (blocks `.env`, `.pem`, etc.) |
| `ACF_ENTROPY_ENABLED` | `bool` | `true` | Enable entropy-based secret scanner |
| `ACF_ENTROPY_BASE64_THRESHOLD` | `float` | `4.5` | Base64 entropy threshold (0.0–8.0) |
| `ACF_ENTROPY_HEX_THRESHOLD` | `float` | `3.0` | Hex entropy threshold (0.0–8.0) |
| `ACF_ENTROPY_MIN_LENGTH` | `int` | `20` | Minimum string length before entropy analysis (≥1) |
| `ACF_MAX_BODY_SIZE_MB` | `int` | `10` | Maximum request/response body size in MB (≥1) |

### Quick reference (cheatsheet)

```bash
export ACF_PROXY_PORT=8080          # Port to listen on
export ACF_LOG_LEVEL=INFO            # Log verbosity
export ACF_FILE_FILTER_ENABLED=true  # Block sensitive files
export ACF_ENTROPY_ENABLED=true      # Enable entropy scanning
export ACF_ENTROPY_BASE64_THRESHOLD=4.5  # Base64 sensitivity
export ACF_ENTROPY_HEX_THRESHOLD=3.0     # Hex sensitivity
export ACF_MAX_BODY_SIZE_MB=10       # Max body size
```

### Configuration via `.env` file

ACF also reads a `.env` file (if present) for local development:

```
# .env (ACF_ prefix required)
ACF_PROXY_PORT=9090
ACF_LOG_LEVEL=DEBUG
ACF_FILE_FILTER_ENABLED=false
ACF_ENTROPY_BASE64_THRESHOLD=6.0
```

> **Note**: In CI/Docker environments, prefer explicit `environment:` blocks
> or `export` commands over `.env` files, since the file may not be present
> in the container image.

### CI-specific configuration patterns

**Disable file filter in trusted CI environments** (e.g., internal test suite
that intentionally sends fixture credentials):

```bash
export ACF_FILE_FILTER_ENABLED=false
```

**Lower entropy threshold for stricter scanning** (catch more potential secrets,
at the cost of more false positives):

```bash
export ACF_ENTROPY_BASE64_THRESHOLD=3.5
export ACF_ENTROPY_HEX_THRESHOLD=2.5
```

**Limit log verbosity in CI** (reduce log noise):

```bash
export ACF_LOG_LEVEL=WARNING
```

---

## 7. Verification in CI

### Minimal smoke test

Add this step to confirm ACF is intercepting traffic correctly:

```bash
# Start ACF
acf start --daemon
sleep 3

# Send a test request with a known secret pattern
curl -x http://127.0.0.1:8080 \
  -H "Content-Type: application/json" \
  -d '{"text": "My API key is sk-abc123def456"}' \
  https://httpbin.org/post 2>/dev/null

# Check that the audit log registered the event
acf audit --summary | grep -q "CRITICAL" && echo "✅ ACF intercepted the secret"

# Stop ACF
acf stop
```

### Audit log collection

The audit log (`~/.acf/logs/audit.log`) is a JSONL file with one event per line.
In CI, expose it as a build artifact for compliance:

```bash
# After tests complete
mkdir -p artifacts
cp ~/.acf/logs/audit.log artifacts/
echo "Audit log collected: $(wc -l < ~/.acf/logs/audit.log) events"
```

### Health check endpoint

The proxy exposes a minimal health endpoint for readiness probes:

```bash
# Check via HTTP
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/health
# Expected: 200
```

---

## 8. Troubleshooting

### ACF won't start in CI

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `address already in use` | Port 8080 occupied | Set `ACF_PROXY_PORT` to an available port |
| `CA certificate not found` | `acf setup --ci` not run | Run `acf setup --ci` before `acf start` |
| `Permission denied` | Running as non-root on restricted system | Use `--port 1024+` (unprivileged range) |
| `Command not found` | ACF not installed | Verify `pip install ai-context-firewall` succeeded |

### Traffic not intercepted

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Audit log empty | `HTTPS_PROXY` not set | Export `HTTPS_PROXY=http://127.0.0.1:8080` |
| TLS errors in tool | CA cert not trusted | Run CA trust commands (see [setup-guide](setup-guide.md)) |
| Tool connects but no events | Target host not in known AI endpoints | Proxy only inspects known AI tool hosts |

### Daemon doesn't stop

If `acf stop` fails to kill the process:

```bash
# Manual cleanup
kill $(cat ~/.acf/acf.pid 2>/dev/null) 2>/dev/null || true
rm -f ~/.acf/acf.pid

# Verify nothing is listening
lsof -i :8080 || echo "Port is free"
```

### Docker-specific

```bash
# Check ACF logs inside container
docker compose exec acf tail -f ~/.acf/logs/proxy.log

# Verify proxy is listening
docker compose exec acf netstat -tlnp | grep 8080

# Run a quick test from inside the app container
docker compose exec app curl -x http://acf:8080 -s -o /dev/null -w "%{http_code}" https://httpbin.org/get
```

---

## Quick Reference

```text
┌──────────────────────────────────────────────────────────────┐
│            ACF CI/CD — Quick Reference                       │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Install:     pip install ai-context-firewall                │
│  Setup CA:    acf setup --ci                                 │
│  Start:       acf start --daemon                             │
│  Check:       acf status          → "running" or "stopped"   │
│  Route:       export HTTPS_PROXY=http://127.0.0.1:8080       │
│  Audit:       acf audit --summary                            │
│  Stop:        acf stop                                       │
│                                                              │
│  Docker:      docker compose up -d acf                       │
│  Health:      docker compose exec acf acf status             │
│  Logs:        ~/.acf/logs/proxy.log                          │
│  Config:      ACF_* env vars (see §6)                        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

*AI Context Firewall v0.1 — CI/CD Deployment Guide*  
*Last updated: 2026-06-19*
