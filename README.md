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

## Running Tests

```bash
pip install -e ".[dev]"
pytest
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
