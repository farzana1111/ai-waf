# API Reference

All management endpoints require the `X-API-Key` header. The key is configured via the `WAF_API_KEY` environment variable or the `security.api_key` field in the configuration file.

## Authentication

Every request must include:

```
X-API-Key: <your-api-key>
```

Unauthorized requests receive:

```json
HTTP/1.1 401 Unauthorized
{"error": "Unauthorized", "message": "Invalid or missing API key"}
```

---

## Endpoints

### `GET /api/status`

Returns the current WAF status.

**Response:**

```json
{
  "status": "running",
  "mode": "detect",
  "uptime_seconds": 3621.45,
  "version": "0.1.0"
}
```

---

### `GET /api/metrics`

Returns collected operational metrics.

**Response:**

```json
{
  "requests_total": 15230,
  "detections_total": 42,
  "requests_by_key": {"GET:/search:200": 12000},
  "detections_by_key": {"sqli:block": 30, "xss:block": 12},
  "average_latency_seconds": 0.002345,
  "latency_samples": 15230,
  "backend": "in_memory"
}
```

---

### `GET /api/rules`

List all loaded detection rules.

**Response:**

```json
{
  "rules": [
    {
      "id": "SQLI-001",
      "name": "SQL Injection - UNION SELECT",
      "severity": "critical",
      "target": "all",
      "action": "block"
    }
  ],
  "count": 20
}
```

---

### `POST /api/rules`

Add a new detection rule.

**Request body:**

```json
{
  "id": "CUSTOM-001",
  "name": "Block /admin access",
  "pattern": "/admin",
  "target": "url",
  "severity": "high",
  "action": "block"
}
```

**Response (201):**

```json
{"message": "Rule added", "rule_id": "CUSTOM-001"}
```

**Validation error (400):**

```json
{"error": "Missing fields: action, severity"}
```

---

### `GET /api/threats`

List recent threat detections. Accepts an optional `limit` query parameter (default 100).

**Example:** `GET /api/threats?limit=10`

**Response:**

```json
{
  "threats": [
    {
      "threat_type": "sqli",
      "confidence": 0.95,
      "client_ip": "192.168.1.100",
      "path": "/search",
      "timestamp": 1710000000.0
    }
  ],
  "count": 42
}
```

---

### `POST /api/config`

Update WAF configuration at runtime. The request body is deep-merged into the current configuration.

**Request body:**

```json
{
  "detection": {
    "sqli": {"threshold": 0.8}
  },
  "logging": {
    "level": "DEBUG"
  }
}
```

**Response:**

```json
{"message": "Configuration updated"}
```

---

### `GET /api/ip/blocklist`

Return the current IP blocklist.

**Response:**

```json
{
  "blocklist": {
    "10.0.0.5": {"reason": "brute-force", "added_at": 1710000000.0}
  },
  "count": 1
}
```

---

### `POST /api/ip/blocklist`

Add an IP address to the blocklist.

**Request body:**

```json
{"ip": "10.0.0.5", "reason": "brute-force"}
```

**Response (201):**

```json
{"message": "IP 10.0.0.5 added to blocklist"}
```

---

### `DELETE /api/ip/blocklist/<ip>`

Remove an IP address from the blocklist.

**Example:** `DELETE /api/ip/blocklist/10.0.0.5`

**Response:**

```json
{"message": "IP 10.0.0.5 removed from blocklist"}
```

**Not found (404):**

```json
{"error": "IP 10.0.0.5 not found in blocklist"}
```

---

## Health Check

The health check endpoint does **not** require authentication:

### `GET /health`

```json
{"status": "healthy"}
```
