# Deployment Guide

## Prerequisites

- Python 3.10 or later
- pip
- (Optional) Docker and Docker Compose

---

## Standalone Deployment

### 1. Install Dependencies

```bash
pip install -r requirements.txt
pip install -e .
```

### 2. Configure

Create a custom configuration file or use environment variables:

```bash
# Minimal — point the WAF at your backend
export WAF_BACKEND_URL=http://your-backend:8080
export WAF_API_KEY=my-secret-key
export WAF_LOG_LEVEL=INFO
```

Or create a YAML config and set `WAF_CONFIG_PATH`:

```bash
export WAF_CONFIG_PATH=/etc/ai-waf/config.yaml
```

See `waf/config/default_config.yaml` for all available options.

### 3. Train Models (Optional)

```bash
python training/train_sqli_model.py
python training/train_xss_model.py
python training/train_anomaly_model.py
```

Models are saved to `models/` and loaded automatically at startup. The WAF falls back to regex/statistical detection when models are not present.

### 4. Run

```bash
python -m flask --app waf.core.proxy:create_app run --host 0.0.0.0 --port 5000
```

Or using the package entry point (after `pip install -e .`):

```bash
ai-waf
```

---

## Docker Deployment

### Build and Run with Docker Compose

```bash
cd docker
docker compose up --build -d
```

This starts:

| Service   | Port | Description                    |
|-----------|------|--------------------------------|
| `waf`     | 5000 | AI-WAF reverse proxy           |
| `waf`     | 9090 | Prometheus metrics endpoint    |
| `backend` | 8080 | Sample nginx backend           |

### Custom Backend

Update `docker-compose.yaml` to point to your real backend service:

```yaml
environment:
  - WAF_BACKEND_URL=http://your-service:8080
```

### Persistent Data

Models and logs are stored in Docker volumes:

```yaml
volumes:
  - ./models:/app/models
  - ./logs:/app/logs
```

### Build Image Only

```bash
docker build -f docker/Dockerfile -t ai-waf .
docker run -p 5000:5000 -e WAF_BACKEND_URL=http://host.docker.internal:8080 ai-waf
```

---

## Configuration Reference

### Environment Variables

| Variable            | Default                    | Description              |
|---------------------|----------------------------|--------------------------|
| `WAF_BACKEND_URL`   | `http://localhost:8080`    | Backend server URL       |
| `WAF_MODE`          | `detect`                   | `detect` or `prevent`   |
| `WAF_API_KEY`       | `change-me`                | API authentication key   |
| `WAF_SECRET_KEY`    | `change-me-in-production`  | Flask secret key         |
| `WAF_LOG_LEVEL`     | `INFO`                     | Logging level            |
| `WAF_LOG_FILE`      | `logs/waf.log`             | Log file path            |
| `WAF_MODEL_DIR`     | `models/`                  | ML model directory       |
| `WAF_METRICS_PORT`  | `9090`                     | Prometheus metrics port  |
| `WAF_CONFIG_PATH`   | —                          | Path to custom YAML config |

### Ports

| Port | Protocol | Purpose                    |
|------|----------|----------------------------|
| 5000 | HTTP     | WAF reverse proxy          |
| 9090 | HTTP     | Prometheus metrics         |

---

## Production Checklist

- [ ] Set `WAF_API_KEY` to a strong random value
- [ ] Set `WAF_SECRET_KEY` to a strong random value
- [ ] Train and deploy ML models
- [ ] Configure a proper log destination
- [ ] Place behind a load balancer / TLS terminator
- [ ] Monitor the `/health` endpoint
- [ ] Set up Prometheus scraping on port 9090
