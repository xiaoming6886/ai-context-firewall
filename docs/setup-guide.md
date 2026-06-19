# Setup Guide — AI Context Firewall

> Install, configure, and verify AI Context Firewall on your machine.

---

## Table of Contents

1. [Installation](#1-installation)
2. [CA Certificate Setup](#2-ca-certificate-setup)
3. [Proxy Configuration per Tool](#3-proxy-configuration-per-tool)
4. [Verification](#4-verification)
5. [Troubleshooting](#5-troubleshooting)
6. [WebSocket Limitation](#6-websocket-limitation)

---

## 1. Installation

### Prerequisites

- Python **3.11 or later**
- `pip` (Python package installer)

### Install via pip

```bash
pip install ai-context-firewall
```

### Verify installation

```bash
acf --help
```

Expected output:

```
Usage: acf [OPTIONS] COMMAND [ARGS]...

  AI Context Firewall — intercept, inspect, and sanitize AI context windows.

Options:
  --help  Show this message and exit.

Commands:
  start   Start the proxy server
  stop    Stop the running proxy
  status  Show proxy status
  scan    One-shot offline scan of a file
  config  Show or set configuration
  setup   Generate CA certificate and proxy config instructions
  audit   View audit log summary
```

You can also verify the Python package imports correctly:

```bash
python -c "import acf; print(acf.__version__)"
```

### Install from source

```bash
git clone https://github.com/your-org/ai-context-firewall.git
cd ai-context-firewall
pip install -e .
```

---

## 2. CA Certificate Setup

AI Context Firewall uses a **man-in-the-middle (MITM) proxy** to inspect HTTPS traffic. Your system and AI tools must trust the firewall's Certificate Authority (CA) for HTTPS interception to work.

### Generate the CA certificate

Run the setup command to generate the certificate:

```bash
acf setup
```

This creates:
- `~/.acf/ca/ca.pem` — the CA certificate (public)
- `~/.acf/ca/ca-key.pem` — the CA private key (keep secure)

> **Warning**: The CA private key can decrypt all traffic passing through the proxy.
> Keep `ca-key.pem` safe — anyone with access to this file can decrypt your AI tool traffic.

### Platform-specific trust installation

#### Windows

```powershell
# Install CA certificate into the Trusted Root Certification Authorities store
certutil -addstore -user Root %USERPROFILE%\.acf\ca\ca.pem

# Verify installation
certutil -store -user Root | findstr "AI Context Firewall"
```

#### macOS

```bash
# Install CA certificate into the system keychain
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.acf/ca/ca.pem

# Verify installation
security find-certificate -a -p /Library/Keychains/System.keychain | openssl x509 -text -noout | grep "AI Context Firewall"
```

#### Linux (Debian/Ubuntu)

```bash
# Copy CA certificate to system trust store
sudo cp ~/.acf/ca/ca.pem /usr/local/share/ca-certificates/ai-context-firewall.crt

# Update the system certificate bundle
sudo update-ca-certificates

# Verify
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt ~/.acf/ca/ca.pem
```

#### Linux (RHEL/Fedora/CentOS)

```bash
# Copy CA certificate
sudo cp ~/.acf/ca/ca.pem /etc/pki/ca-trust/source/anchors/ai-context-firewall.crt

# Update the system certificate bundle
sudo update-ca-trust

# Verify
openssl verify -CAfile /etc/pki/tls/certs/ca-bundle.crt ~/.acf/ca/ca.pem
```

### Docker / CI Trust

When running in Docker, mount the certificate and install it in the container's trust store:

```dockerfile
COPY ca.pem /usr/local/share/ca-certificates/ai-context-firewall.crt
RUN update-ca-certificates
```

---

## 3. Proxy Configuration per Tool

Each AI tool must be configured to route its traffic through the firewall proxy.
The proxy listens on **`http://localhost:8080`** by default (configurable via `--port`).

### Cursor

Edit `~/.cursor/settings.json` (or your project's `.cursor/settings.json`):

```json
{
  "proxy": {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080",
    "no_proxy": "localhost,127.0.0.1"
  }
}
```

Restart Cursor after making this change. Verify in Cursor's settings UI that "Proxy" shows the configured address.

> **Note**: Cursor does not use the system `HTTPS_PROXY` environment variable — it reads only from `settings.json`.

### GitHub Copilot (VS Code / JetBrains)

Set the `HTTPS_PROXY` environment variable **before launching your editor**:

#### Terminal (macOS / Linux)

```bash
export HTTPS_PROXY=http://localhost:8080
export HTTP_PROXY=http://localhost:8080
export NO_PROXY=localhost,127.0.0.1

# Launch VS Code from this same terminal
code .
```

#### PowerShell (Windows)

```powershell
$env:HTTPS_PROXY="http://localhost:8080"
$env:HTTP_PROXY="http://localhost:8080"
$env:NO_PROXY="localhost,127.0.0.1"

# Launch VS Code from this same terminal
code .
```

#### VS Code `settings.json` (alternative)

You can also set proxy in VS Code's user settings:

```json
{
  "http.proxy": "http://localhost:8080",
  "http.proxyStrictSSL": false
}
```

> **Note**: `http.proxyStrictSSL: false` is required if the CA certificate is not fully trusted by VS Code.

### Claude Code (Anthropic)

Set the `HTTPS_PROXY` environment variable:

#### Terminal (macOS / Linux)

```bash
export HTTPS_PROXY=http://localhost:8080
export HTTP_PROXY=http://localhost:8080
export NO_PROXY=localhost,127.0.0.1

claude
```

#### PowerShell (Windows)

```powershell
$env:HTTPS_PROXY="http://localhost:8080"
$env:HTTP_PROXY="http://localhost:8080"
$env:NO_PROXY="localhost,127.0.0.1"

claude
```

> Claude Code respects `HTTPS_PROXY` and `HTTP_PROXY` from the environment at startup. If you change the proxy while Claude is running, restart it.

### Configuration reference table

| Tool | Config method | Config location | Key field |
|------|--------------|-----------------|-----------|
| Cursor | `settings.json` | `~/.cursor/settings.json` | `proxy.https` |
| Copilot (VS Code) | Environment variable | Before launching `code` | `HTTPS_PROXY` |
| Copilot (JetBrains) | IDE Settings | Settings → Appearance & Behavior → System Settings → HTTP Proxy | Manual proxy |
| Claude Code | Environment variable | Before launching `claude` | `HTTPS_PROXY` |

---

## 4. Verification

### Step 1: Start the proxy

```bash
acf start --port 8080
```

Expected output:

```
[INFO] AI Context Firewall proxy started on http://localhost:8080
[INFO] CA certificate: ~/.acf/ca/ca.pem
[INFO] Audit log: ~/.acf/logs/audit.log
```

### Step 2: Test via curl

Send a test request through the proxy:

```bash
curl -x http://localhost:8080 \
  --cacert ~/.acf/ca/ca.pem \
  -H "Content-Type: application/json" \
  -d '{"text": "My API key is sk-abc123def456"}' \
  https://api.anthropic.com/v1/messages
```

Expected behavior:
- If the proxy is working but the request does **not** match sensitive patterns, you see the normal API response.
- If the request **does** contain sensitive data (like the `sk-` key above), the proxy redacts it and returns a modified request to the upstream.

### Step 3: Check the audit log

```bash
acf audit --summary
```

Expected output:

```
Events Summary
┏━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Severity       ┃ Count ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ CRITICAL       │     0 │
│ WARNING        │     1 │
│ INFO           │     2 │
└────────────────┴───────┘
```

### Step 4: Test file blocking

Create a test `.env` file and try to send it through the proxy:

```bash
echo "DB_PASSWORD=supersecret123" > test.env

# Attempt to fetch it via HTTP (simulating an AI tool reading the file)
curl -x http://localhost:8080 --cacert ~/.acf/ca/ca.pem \
  -H "Content-Type: text/plain" \
  --data-binary @test.env \
  https://api.cursor.sh/ai/completions
```

Expected result: HTTP **403 Forbidden** with a `X-Blocked-By: ACF` header and a `FileBlockMatch` JSON body.

### Step 5: Verify with your AI tool

1. Start the proxy: `acf start`
2. Launch your AI tool with proxy configured (see [Section 3](#3-proxy-configuration-per-tool))
3. Open a project that contains a `.env` file with test credentials
4. Ask the AI to read or explain the `.env` file
5. **Expected**: The AI responds with something like "[The content of .env has been redacted]" or reports it cannot access the file
6. Check the audit log: `acf audit --summary` should show at least one **CRITICAL** event

---

## 5. Troubleshooting

### TLS / Certificate Errors

**Symptom**: AI tools show "certificate verification failed" or "SSL handshake error".

**Causes**:
1. The CA certificate is not trusted by the system or tool
2. The AI tool uses **certificate pinning** (see note below)
3. The proxy is intercepting traffic before the CA is installed

**Solutions**:

| Issue | Fix |
|-------|-----|
| CA not installed | Run the platform-specific trust command in [Section 2](#2-ca-certificate-setup) |
| CA installed but not picked up | Reboot the tool (some tools cache certificates at startup) |
| Python requests verify error | `export REQUESTS_CA_BUNDLE=~/.acf/ca/ca.pem` (or `SSL_CERT_FILE`) |
| Node.js / npm verify error | `export NODE_EXTRA_CA_CERTS=~/.acf/ca/ca.pem` |

General environment variable to trust the CA across most tools:

```bash
export SSL_CERT_FILE=~/.acf/ca/ca.pem
export REQUESTS_CA_BUNDLE=~/.acf/ca/ca.pem
export NODE_EXTRA_CA_CERTS=~/.acf/ca/ca.pem
```

### Port Conflicts

**Symptom**: `acf start` fails with "address already in use" or "port 8080 is occupied".

**Solutions**:

1. **Find what's using the port**:
   ```bash
   # macOS / Linux
   lsof -i :8080
   
   # Windows (as Administrator)
   netstat -ano | findstr :8080
   ```

2. **Use a different port**:
   ```bash
   acf start --port 9090
   ```
   Then update all tool configurations to use `http://localhost:9090`.

3. **Kill the conflicting process** (if safe):
   ```bash
   # macOS / Linux
   kill -9 <PID>
   
   # Windows
   taskkill /F /PID <PID>
   ```

### Proxy Not Intercepting Traffic

**Symptom**: Traffic goes through but nothing appears in the audit log.

**Check**:
1. Is the proxy running? `acf status`
2. Is the tool configured to use the proxy? See [Section 3](#3-proxy-configuration-per-tool)
3. Does the traffic match a known target? The proxy only inspects traffic to known AI tool endpoints (Cursor, Copilot, Claude Code). Traffic to other hosts passes through uninspected.
4. Check the proxy logs directly: `cat ~/.acf/logs/proxy.log`

### DNS / Connection Refused

**Symptom**: Tools show "connection refused" or DNS errors after configuring the proxy.

**Causes**:
- The proxy is not running when the tool starts
- The `NO_PROXY` setting is missing `localhost,127.0.0.1` — this causes infinite loop when the tool tries to reach local services

**Fix**: Ensure `NO_PROXY` includes `localhost,127.0.0.1` in all configurations.

### Certificate Pinning Risk ⚠️

> **Important**: Some AI tools and services use **certificate pinning** — they accept only a specific, hardcoded certificate rather than trusting the system CA store.

**Affected services may include:**
- **Amazon S3** and other AWS services (known to use pinning)
- Some enterprise-managed Copilot instances
- Custom-built AI tool integrations

**What happens**: When the proxy presents its own certificate to a pinned service, the connection fails with a TLS error or the tool refuses to connect.

**What this means for you:**

| Scenario | Works? | Notes |
|----------|--------|-------|
| Cursor → api.cursor.sh | ✅ | No pinning observed |
| Copilot → api.github.com | ✅ | No pinning observed |
| Claude Code → api.anthropic.com | ✅ | No pinning observed |
| S3 → s3.amazonaws.com | ❌ | Known pinning — traffic bypasses proxy |
| Enterprise Copilot with custom CA | ⚠️ | Depends on enterprise configuration |

**ACF behavior on pinned connections**: The proxy detects the handshake failure and logs a `WARNING` event in the audit log. The request **fails open** — the tool can either skip the proxy or fail to connect, depending on the tool's fallback behavior.

**Mitigation**:

1. **Add pinned hosts to `NO_PROXY`** to bypass proxy for those specific endpoints:
   ```bash
   export NO_PROXY="localhost,127.0.0.1,*.s3.amazonaws.com,*.amazonaws.com"
   ```

2. **Do not disable TLS verification globally** — setting `http.proxyStrictSSL: false` or equivalent is a workaround, but it reduces security. Use it only for specific hosts if possible.

3. **Monitor audit logs** — if you see repeated TLS errors for a specific host, it may be using pinning. Add it to the bypass list.

---

## 6. WebSocket Limitation

> **Known limitation**: AI Context Firewall currently does **not** intercept or inspect WebSocket (`ws://` / `wss://`) traffic.

### What this means

Some AI tools use WebSocket connections for:

- **Cursor**: Real-time code suggestions and streaming completions may fall back to WebSocket
- **Claude Code**: Streaming responses use SSE (Server-Sent Events) over HTTPS, which **is** intercepted
- **Copilot**: Primarily uses HTTPS for API calls; WebSocket is not the primary transport

### Current behavior

| Traffic type | Intercepted? | Inspected? | Redacted? |
|-------------|-------------|------------|-----------|
| HTTPS request/response | ✅ Yes | ✅ Yes | ✅ Yes |
| HTTP request/response | ✅ Yes | ✅ Yes | ✅ Yes |
| WebSocket messages (ws/wss) | ❌ No | ❌ No | ❌ No |

### Impact assessment

For typical use cases, this limitation is **low severity**:

- Most AI tool API calls use **HTTPS REST** endpoints, which are fully intercepted
- Code content sent for review/completion goes through HTTPS POST bodies
- WebSocket is primarily used for peripheral features (real-time status updates, connection keep-alive)

### Planned improvement

WebSocket message interception is on the roadmap for a future release (v0.2+). It requires:

1. Implementing WS message capture in the mitmproxy addon layer
2. Applying the same detection/redaction pipeline to WS message payloads
3. Handling the streaming nature of WS (partial frames, fragmentation)

### What you can do now

- **Verify your AI tool's transport**: Most tools list their API endpoints in documentation. If they use HTTPS (likely), you are covered.
- **Monitor audit logs**: If you see requests passing with no intercept events and suspect WebSocket, check the proxy logs for `[WS]` markers (when present, they indicate WebSocket connection bypass).
- **Use environment-level blocking** as a fallback: Configure your firewall or network rules to block WebSocket upgrades to AI tool endpoints if you need comprehensive coverage.

---

## Quick Reference Card

```text
┌─────────────────────────────────────────────────────────┐
│               AI Context Firewall — Quick Start          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. Install:    pip install ai-context-firewall          │
│  2. Setup CA:   acf setup                               │
│  3. Trust CA:   see §2 for your OS                      │
│  4. Start:      acf start                               │
│  5. Configure:  set HTTPS_PROXY=http://localhost:8080    │
│                 (see §3 for tool-specific config)        │
│  6. Verify:     curl -x http://localhost:8080 ...        │
│  7. Audit:      acf audit --summary                     │
│                                                         │
│  Need help?    acf --help                               │
│  Logs:         ~/.acf/logs/                             │
│  Config:       ~/.acf/config.yaml                       │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

*AI Context Firewall v0.1 — Setup Guide*  
*Last updated: 2026-06-19*
