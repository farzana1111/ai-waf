# AI-WAF Architecture

## Overview

AI-WAF is an AI-powered Web Application Firewall that operates as a reverse proxy between clients and a backend web server. It intercepts every HTTP request, analyses it through a multi-layered detection pipeline, and either blocks malicious traffic or forwards legitimate requests to the backend.

## High-Level Components

```
┌──────────┐     ┌──────────────────────────────────────────┐     ┌─────────┐
│  Client  │────▶│                 AI-WAF                   │────▶│ Backend │
│          │◀────│                                          │◀────│ Server  │
└──────────┘     │  ┌────────┐  ┌───────────┐  ┌────────┐  │     └─────────┘
                 │  │ Parser │─▶│ Detection │─▶│Decision│  │
                 │  └────────┘  │  Pipeline  │  │ Engine │  │
                 │              └───────────┘  └────────┘  │
                 │  ┌─────────┐ ┌──────────┐  ┌────────┐  │
                 │  │ Logging │ │  Metrics  │  │  API   │  │
                 │  └─────────┘ └──────────┘  └────────┘  │
                 └──────────────────────────────────────────┘
```

## Component Details

### Core (`waf/core/`)

| Module             | Purpose                                            |
|--------------------|----------------------------------------------------|
| `proxy.py`         | Flask application factory and reverse-proxy logic  |
| `request_parser.py`| Parse and normalise incoming HTTP requests          |
| `response_handler.py` | Decision engine; create block/rate-limit responses |

**`create_app()`** builds the Flask application. A `before_request` hook intercepts every request, parses it into a `ParsedRequest`, runs the detection pipeline, and either blocks or forwards the request.

### AI / ML (`waf/ai/`)

| Module               | Purpose                                    |
|-----------------------|--------------------------------------------|
| `feature_extractor.py`| Extract 12 numerical features from requests|
| `model_manager.py`    | Load, cache, and reload `.joblib`/`.pkl` models |
| `explainability.py`   | Explain detection decisions                |
| `models/sqli_detector.py`  | SQL injection detection (regex + ML) |
| `models/xss_detector.py`   | XSS detection (regex + ML)           |
| `models/anomaly_detector.py`| Anomaly detection (stats + ML)      |
| `models/rate_limiter.py`    | Per-IP rate limiting                 |

### Rules (`waf/rules/`)

| Module           | Purpose                              |
|------------------|--------------------------------------|
| `rule_engine.py` | Regex-based rule evaluation engine   |
| `rule_loader.py` | Load rules from YAML files           |
| `default_rules.yaml` | Built-in detection rules         |

### Threat Intelligence (`waf/threat_intel/`)

| Module            | Purpose                              |
|-------------------|--------------------------------------|
| `feed_manager.py` | Fetch and cache external threat feeds|
| `ip_reputation.py`| IP allow/block list management       |

### Logging & Metrics (`waf/logging/`)

| Module            | Purpose                              |
|-------------------|--------------------------------------|
| `logger.py`       | JSON-structured logging              |
| `metrics.py`      | Prometheus-compatible WAF metrics    |
| `alert_manager.py`| Webhook-based alerting               |

### API (`waf/api/`)

| Module         | Purpose                              |
|----------------|--------------------------------------|
| `routes.py`    | REST API endpoints for management    |
| `middleware.py`| API key authentication decorator     |

### Configuration (`waf/config/`)

| Module              | Purpose                              |
|---------------------|--------------------------------------|
| `settings.py`       | Hierarchical config loader           |
| `default_config.yaml` | Default configuration values      |

## Data Flow

```
Client Request
      │
      ▼
┌─────────────────┐
│  Flask Proxy    │  (waf.core.proxy)
│  before_request │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Request Parser  │  Normalise URL-encoding, HTML entities, etc.
│ + decode_all()  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Feature         │  12 numerical features → dict
│ Extractor       │
└────────┬────────┘
         │
         ├──────────────────┬──────────────────┐
         ▼                  ▼                  ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
│ SQLi Detector│  │ XSS Detector │  │ Anomaly Detector │
│ (regex + ML) │  │ (regex + ML) │  │ (stats + ML)     │
└──────┬───────┘  └──────┬───────┘  └────────┬─────────┘
       │                 │                   │
       ├─────────────────┼───────────────────┤
       ▼                 ▼                   ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Rate Limiter │  │ Rule Engine  │  │ IP Reputation│
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │
       └─────────────────┼─────────────────┘
                         ▼
               ┌──────────────────┐
               │ make_decision()  │
               │ block / rate_limit│
               │      / pass      │
               └────────┬─────────┘
                        │
               ┌────────┴────────┐
               │                 │
          ┌────▼────┐     ┌─────▼──────┐
          │  Block  │     │  Forward   │
          │ 403/429 │     │ to Backend │
          └─────────┘     └────────────┘
```

## Detection Pipeline

1. **Input normalisation** — recursive URL, HTML-entity, and base64 decoding via `decode_all()`.
2. **Feature extraction** — 12 features including payload length, entropy, special-character count, SQL/XSS keyword flags, URL depth, parameter count.
3. **ML detection** — trained Random Forest (SQLi, XSS) and Isolation Forest (anomaly) models score the feature vector. Falls back to regex/statistical checks when models are unavailable.
4. **Rule evaluation** — YAML-defined regex rules are matched against the normalised payload.
5. **Rate limiting** — per-IP burst and sustained rate checks.
6. **IP reputation** — allow/block list lookup.
7. **Decision** — `make_decision()` picks the highest-severity action: **block** (≥ 0.7 confidence), **rate_limit**, or **pass**.

## Configuration Hierarchy

Settings are resolved in priority order:

1. **Environment variables** (`WAF_BACKEND_URL`, `WAF_API_KEY`, etc.)
2. **User config YAML** (path set via `WAF_CONFIG_PATH`)
3. **`default_config.yaml`** shipped with the package
