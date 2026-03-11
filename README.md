# AI-WAF — AI-Powered Web Application Firewall

An intelligent Web Application Firewall that combines **machine-learning models** with **OWASP-inspired rule-based detection** to identify and block web-layer attacks in real time.

---

## Features

| Capability | Details |
|---|---|
| **ML threat detection** | Character-level TF-IDF + Random Forest classifier trained on labelled attack samples |
| **Rule engine** | 30+ regex rules covering SQLi, XSS, CMDi, Path Traversal, LDAP, XXE, SSRF, scanner detection |
| **Dual proxy mode** | Flask reverse proxy and FastAPI transparent proxy options |
| **Dual action mode** | `block` (return 403) or `monitor` / `detect` (log & pass) |
| **Rate limiting** | Sliding-window per-IP rate limiter |
| **Anomaly detection** | Isolation Forest unsupervised model flags request deviations |
| **Threat intelligence** | IP reputation scoring and CTI feed integration |
| **Explainable AI** | Every detection decision includes feature-importance explanations |
| **Management API** | REST endpoints for stats, rules, config, and retraining |
| **Prometheus metrics** | Built-in `/metrics` endpoint for monitoring and alerting |

---

## Architecture

```
Client → [AI-WAF Proxy]
                │
         ┌──────┴──────┐
         │  WAFEngine  │
         ├─────────────┤
         │ RateLimit   │  ← per-IP sliding window
         │ Features    │  ← URL decode, char stats, entropy
         │ RuleEngine  │  ← 30+ OWASP regex rules
         │ MLDetector  │  ← TF-IDF + RandomForest
         │ AnomalyDet  │  ← Isolation Forest
         └──────┬──────┘
                │ allow / block
         [Upstream Server]
```

---

## Quick Start

### Option 1: FastAPI-based WAF

```bash
# Install
pip install -e .

# Train the ML model
python -m scripts.train_model

# Run the WAF
WAF_UPSTREAM_URL=http://localhost:8080 uvicorn waf.api:create_app --factory --port 8000
```

### Option 2: Flask-based WAF

```bash
# Install dependencies
pip install -r requirements.txt

# Copy and edit the environment file
cp .env.example .env

# Run the WAF
make run
```

### Test a request

```bash
# Clean request — forwarded to upstream
curl http://localhost:8000/api/users?page=1

# SQL injection — blocked with 403
curl "http://localhost:8000/search?q=' OR '1'='1 UNION SELECT null--"
```

---

## Project Structure

```
ai-waf/
├── waf/                     # Main application package
│   ├── core.py              # FastAPI WAF engine
│   ├── api.py               # FastAPI endpoints
│   ├── config.py            # FastAPI config (pydantic-settings)
│   ├── detector.py          # ML threat detector
│   ├── features.py          # Feature extraction
│   ├── rules.py             # Rule engine (30+ rules)
│   ├── logger.py            # Structured logging
│   ├── model/               # ML model training & artifacts
│   ├── ai/                  # Extended ML detection engine
│   │   └── models/          # Model definitions & loaders
│   ├── api/                 # Flask REST API endpoints
│   ├── config/              # YAML configuration & defaults
│   ├── core/                # Flask reverse-proxy & request handling
│   ├── logging/             # Structured logging (Flask)
│   ├── rules/               # Signature / rule-based detection (Flask)
│   ├── threat_intel/        # Threat-feed integration
│   └── utils/               # Shared helpers
├── scripts/                 # FastAPI training scripts
├── tests/                   # Test suite
├── training/                # Flask model training scripts & data
├── docker/                  # Docker & Compose files
├── docs/                    # Documentation
├── models/                  # Serialised ML models
├── requirements.txt
├── requirements-dev.txt
├── setup.py
├── Makefile
└── .env.example
```

---

## Configuration

All settings are loaded from environment variables (prefix `WAF_`) or a `.env` file.

| Variable | Default | Description |
|---|---|---|
| `WAF_UPSTREAM_URL` / `WAF_BACKEND_URL` | `http://localhost:8080` | Backend URL |
| `WAF_LISTEN_PORT` | `8000` / `5000` | WAF listen port |
| `WAF_MODE` | `block` | `block` / `monitor` / `detect` / `prevent` |
| `WAF_ENABLE_ML` | `true` | Enable ML detector |
| `WAF_ENABLE_RULES` | `true` | Enable rule engine |
| `WAF_ML_CONFIDENCE_THRESHOLD` | `0.70` | Min ML confidence to flag a threat |
| `WAF_RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `WAF_RATE_LIMIT_REQUESTS` | `100` | Max requests per window |
| `WAF_MODEL_PATH` | `waf/model/threat_model.joblib` | Path to trained model |
| `WAF_LOG_LEVEL` | `INFO` | Logging level |
| `WAF_MODEL_DIR` | `models/` | Directory for Flask WAF models |

---

## Management API

### FastAPI endpoints
```
GET  /waf/health       # Health check
GET  /waf/stats        # Request statistics
POST /waf/evaluate     # Manual threat evaluation
```

### Flask API endpoints
```
GET  /api/status       # WAF status
GET  /api/metrics      # Metrics data
GET  /api/rules        # List rules
POST /api/rules        # Add rule
GET  /api/threats      # Recent detections
POST /api/config       # Update config
GET  /api/ip/blocklist # IP blocklist
```

---

## Detected Threat Categories

- **SQL Injection** (tautologies, UNION SELECT, stacked queries, time-based blind)
- **Cross-Site Scripting** (script tags, event handlers, javascript: URIs, DOM sinks)
- **Command Injection** (shell pipes, backtick execution, command substitution)
- **Path Traversal** (../, URL-encoded, double-encoded variants)
- **LDAP Injection**
- **XML External Entity (XXE)**
- **Server-Side Request Forgery (SSRF)**
- **Automated Scanners** (sqlmap, nikto, nmap, acunetix)

---

## Testing & Verification

### 1. Install dependencies

```bash
pip install -e ".[dev]"
```

### 2. Run the full test suite (204 tests)

```bash
# Quick run
pytest

# Verbose with coverage
make test
# or equivalently:
pytest tests/ -v --cov=waf --cov-report=term-missing
```

**What the tests cover:**

| Test file | What it validates |
|---|---|
| `test_core.py` | WAFEngine: SQLi, XSS, CMDi, path traversal, SSRF, XXE, scanner detection, monitor mode, rate limiting |
| `test_rules.py` | 30+ OWASP regex rules: pattern matching, severity, score calculation |
| `test_rule_engine.py` | YAML rule loading, rule evaluation with target filtering |
| `test_sqli_detector.py` | SQL injection detector: UNION, DROP, SLEEP, tautologies, payload file |
| `test_xss_detector.py` | XSS detector: script tags, event handlers, JS URIs, payload file |
| `test_detector.py` | ML ThreatDetector: model loading, predict, confidence scoring |
| `test_features.py` | Feature extraction: char ratios, encodings, null bytes, URL decoding |
| `test_feature_extractor.py` | 12-feature ML vector: entropy, SQL keywords, XSS patterns |
| `test_api.py` | Flask API: auth, status, metrics, rules CRUD, threats |
| `test_api_fastapi.py` | FastAPI: health, stats, evaluate, proxy blocking |
| `test_proxy.py` | Flask reverse-proxy: app factory, health check, error handling |

### 3. Run the smoke test (no network required)

The smoke test exercises the WAF engine directly against 17 attack and clean payloads:

```bash
# Default: block mode, rules only
python -m scripts.smoke_test

# With ML detector enabled (requires trained model)
python -m scripts.smoke_test --ml

# Monitor mode (detects threats but allows all traffic)
python -m scripts.smoke_test --mode monitor
```

**Expected output (block mode):**
```
======================================================================
 AI-WAF Smoke Test  —  mode=block  (17 test cases)
======================================================================

  [PASS] Clean GET request                             expect=ALLOW  got=ALLOWED  score=0.00
  [PASS] Clean POST with JSON body                     expect=ALLOW  got=ALLOWED  score=0.00
  [PASS] Clean search query                            expect=ALLOW  got=ALLOWED  score=0.00
  [PASS] SQLi — OR tautology                           expect=BLOCK  got=BLOCKED  score=1.00
  [PASS] SQLi — UNION SELECT                           expect=BLOCK  got=BLOCKED  score=0.95
  [PASS] SQLi — DROP TABLE                             expect=BLOCK  got=BLOCKED  score=1.00
  [PASS] SQLi — time-based blind (SLEEP)               expect=BLOCK  got=BLOCKED  score=0.85
  [PASS] XSS — script tag                              expect=BLOCK  got=BLOCKED  score=0.85
  [PASS] XSS — img onerror                             expect=BLOCK  got=BLOCKED  score=0.87
  [PASS] XSS — javascript: URI                         expect=BLOCK  got=BLOCKED  score=0.85
  [PASS] CMDi — semicolon chaining                     expect=BLOCK  got=BLOCKED  score=1.00
  [PASS] CMDi — backtick execution                     expect=BLOCK  got=BLOCKED  score=0.97
  [PASS] Path traversal — ../../etc/passwd             expect=BLOCK  got=BLOCKED  score=0.75
  [PASS] SSRF — localhost                              expect=BLOCK  got=BLOCKED  score=0.60
  [PASS] SSRF — cloud metadata                         expect=BLOCK  got=BLOCKED  score=0.72
  [PASS] XXE — DOCTYPE ENTITY                          expect=BLOCK  got=BLOCKED  score=1.00
  [PASS] Scanner — sqlmap User-Agent                   expect=BLOCK  got=BLOCKED  score=0.25

──────────────────────────────────────────────────────────────────────
 Result: 17/17 passed
──────────────────────────────────────────────────────────────────────
```

### 4. Test with curl (live server)

Start the FastAPI WAF (proxying to any upstream, e.g. `httpbin.org`):

```bash
WAF_UPSTREAM_URL=https://httpbin.org WAF_ENABLE_ML=false uvicorn waf.fastapi_app:create_app --factory --port 8000
```

Then in another terminal:

```bash
# ✅ Clean request — should be forwarded (200)
curl -s http://localhost:8000/get | head -5

# 🚫 SQL injection — should be blocked (403)
curl -s http://localhost:8000/get?q="' OR '1'='1 UNION SELECT null--"
# → {"error":"Forbidden","message":"Request blocked by AI-WAF","request_id":"..."}

# 🚫 XSS — should be blocked (403)
curl -s "http://localhost:8000/get?q=<script>alert(1)</script>"
# → {"error":"Forbidden",...}

# 🚫 Path traversal — should be blocked (403)
curl -s http://localhost:8000/../../etc/passwd
# → {"error":"Forbidden",...}

# ℹ️ Health check
curl -s http://localhost:8000/waf/health
# → {"status":"ok","uptime_seconds":...,"mode":"block",...}

# ℹ️ Stats
curl -s http://localhost:8000/waf/stats
# → {"total_requests":5,"threats_detected":3,"requests_blocked":3,...}
```

### 5. Run individual test files

```bash
# Test only SQL injection detection
pytest tests/test_sqli_detector.py -v

# Test only the WAF engine
pytest tests/test_core.py -v

# Test only the API endpoints
pytest tests/test_api_fastapi.py -v

# Test with a keyword filter
pytest -k "sqli or xss" -v
```

---

## Development

```bash
make lint        # Run linter
make format      # Auto-format code
make test        # Run tests with coverage
make docker-build # Build Docker image
```

---

## License

MIT
