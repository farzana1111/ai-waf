# AI-WAF — AI-Powered Web Application Firewall

An intelligent reverse-proxy Web Application Firewall that combines **machine-learning models** with a traditional **rules engine** to detect and block malicious HTTP traffic in real time.

## Features

- **ML-Based Attack Detection** — trained classifiers for SQL injection (SQLi), cross-site scripting (XSS), and DDoS patterns.
- **Anomaly Detection** — unsupervised model flags requests that deviate from learned baselines.
- **Hybrid Rules Engine** — signature-based rules run alongside ML models for defence-in-depth.
- **Real-Time Threat Intelligence** — integrates external threat feeds for IP reputation and IOC matching.
- **Explainable AI** — every detection decision includes feature-importance explanations.
- **REST Management API** — query stats, update rules, and retrain models without restarts.
- **Prometheus Metrics** — built-in `/metrics` endpoint for monitoring and alerting.

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/ai-waf/ai-waf.git
cd ai-waf

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate

# 3. Install dependencies
make install          # production deps
# or
make dev-install      # production + dev/test deps

# 4. Copy and edit the environment file
cp .env.example .env

# 5. Run the WAF
make run
```

## Project Structure

```
ai-waf/
├── waf/                     # Main application package
│   ├── ai/                  # ML detection engine
│   │   └── models/          # Model definitions & loaders
│   ├── api/                 # REST API endpoints
│   ├── config/              # Configuration & YAML defaults
│   ├── core/                # Reverse-proxy & request handling
│   ├── logging/             # Structured logging
│   ├── rules/               # Signature / rule-based detection
│   ├── threat_intel/        # Threat-feed integration
│   └── utils/               # Shared helpers
├── tests/                   # Test suite
├── training/                # Model training scripts & data
│   ├── datasets/
│   └── notebooks/
├── docker/                  # Docker & Compose files
├── docs/                    # Documentation
├── models/                  # Serialised ML models (*.pkl)
├── requirements.txt
├── requirements-dev.txt
├── setup.py
├── Makefile
└── .env.example
```

## Configuration

Configuration is resolved in the following order (highest priority first):

1. **Environment variables** — prefixed with `WAF_` (e.g. `WAF_BACKEND_URL`).
2. **Custom YAML** — set `WAF_CONFIG_PATH` to point at your own file.
3. **default_config.yaml** — sensible defaults shipped with the package.

Key settings live in `waf/config/default_config.yaml`. See `.env.example` for the most common overrides.

| Variable | Description | Default |
|---|---|---|
| `WAF_MODE` | `detect` (log only) or `prevent` (block) | `detect` |
| `WAF_BACKEND_URL` | Upstream server to proxy traffic to | `http://localhost:8080` |
| `WAF_LISTEN_PORT` | Port the WAF listens on | `5000` |
| `WAF_LOG_LEVEL` | Logging verbosity | `INFO` |
| `WAF_MODEL_DIR` | Directory containing serialised models | `models/` |

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `ANY` | `/*` | Reverse-proxy — all traffic is inspected then forwarded |
| `GET` | `/api/v1/health` | Health-check |
| `GET` | `/api/v1/stats` | Detection statistics & counters |
| `GET` | `/api/v1/config` | Current running configuration |
| `POST` | `/api/v1/rules` | Add or update detection rules |
| `GET` | `/api/v1/threats` | Recent threat detections |
| `POST` | `/api/v1/train` | Trigger model retraining |
| `GET` | `/metrics` | Prometheus metrics |

## Development

```bash
# Run linter & formatter check
make lint

# Auto-format code
make format

# Run tests with coverage
make test

# Build Docker image
make docker-build
```

## License

MIT