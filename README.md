# AI-WAF — AI-Powered Web Application Firewall

An intelligent Web Application Firewall that combines **OWASP-inspired rule-based detection** with a **scikit-learn ML pipeline** to identify and block web-layer attacks in real time.

---

## Features

| Capability | Details |
|---|---|
| **ML threat detection** | Character-level TF-IDF + Random Forest classifier trained on labelled attack samples |
| **Rule engine** | 30+ regex rules covering SQLi, XSS, CMDi, Path Traversal, LDAP, XXE, SSRF, scanner detection |
| **Transparent proxy** | FastAPI app that inspects every request before forwarding to the upstream service |
| **Dual mode** | `block` (return 403) or `monitor` (log & pass) |
| **Rate limiting** | Sliding-window per-IP rate limiter |
| **Management API** | `/waf/health`, `/waf/stats`, `/waf/evaluate` |
| **Structured logging** | JSON log lines with threat type, rule IDs, ML confidence, client IP |

---

## Architecture

```
Client → [AI-WAF Proxy :8000]
                │
         ┌──────┴──────┐
         │  WAFEngine  │
         ├─────────────┤
         │ RateLimit   │  ← per-IP sliding window
         │ Features    │  ← URL decode, char stats
         │ RuleEngine  │  ← 30+ OWASP regex rules
         │ MLDetector  │  ← TF-IDF + RandomForest
         └──────┬──────┘
                │ allow / block
         [Upstream :8080]
```

---

## Quick Start

### 1. Install

```bash
pip install -e .
```

### 2. Train the ML model

```bash
python -m scripts.train_model
# or: python -m scripts.train_model --output waf/model/threat_model.joblib
```

### 3. Run the WAF

```bash
# Forward to an upstream service on port 8080
WAF_UPSTREAM_URL=http://localhost:8080 uvicorn waf.api:create_app --factory --port 8000
```

### 4. Test a request

```bash
# Clean request — forwarded to upstream
curl http://localhost:8000/api/users?page=1

# SQL injection — blocked with 403
curl "http://localhost:8000/search?q=' OR '1'='1 UNION SELECT null--"
# {"error":"Forbidden","message":"Request blocked by AI-WAF","request_id":"..."}
```

---

## Management API

```bash
# Health check
GET /waf/health

# Request statistics
GET /waf/stats

# Manual evaluation (does not proxy)
POST /waf/evaluate
Content-Type: application/json
{
  "method": "GET",
  "path": "/search",
  "query_string": "q=<script>alert(1)</script>",
  "client_ip": "1.2.3.4"
}
```

---

## Configuration

All settings are loaded from environment variables (prefix `WAF_`) or a `.env` file.

| Variable | Default | Description |
|---|---|---|
| `WAF_UPSTREAM_URL` | `http://localhost:8080` | Backend URL |
| `WAF_LISTEN_PORT` | `8000` | WAF listen port |
| `WAF_MODE` | `block` | `block` or `monitor` |
| `WAF_ENABLE_ML` | `true` | Enable ML detector |
| `WAF_ENABLE_RULES` | `true` | Enable rule engine |
| `WAF_ML_CONFIDENCE_THRESHOLD` | `0.70` | Min ML confidence to flag a threat |
| `WAF_RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `WAF_RATE_LIMIT_REQUESTS` | `100` | Max requests per window |
| `WAF_RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate-limit window (seconds) |
| `WAF_MODEL_PATH` | `waf/model/threat_model.joblib` | Path to trained model |
| `WAF_LOG_LEVEL` | `INFO` | Logging level |
| `WAF_LOG_FILE` | _(none)_ | Optional JSON log file |

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest
```

---

## Detected Threat Categories

- **SQL Injection** (tautologies, UNION SELECT, stacked queries, time-based blind, …)
- **Cross-Site Scripting** (script tags, event handlers, javascript: URIs, DOM sinks, …)
- **Command Injection** (shell pipes, backtick execution, command substitution, …)
- **Path Traversal** (../, URL-encoded, double-encoded variants)
- **LDAP Injection**
- **XML External Entity (XXE)**
- **Server-Side Request Forgery (SSRF)**
- **Automated Scanners** (sqlmap, nikto, nmap, acunetix, …)
