"""REST API endpoints for WAF management."""

import logging
import time

from flask import Blueprint, jsonify, request

from waf.api.middleware import require_api_key
from waf.config.settings import Settings
from waf.logging.metrics import WAFMetrics
from waf.rules.rule_engine import RuleEngine
from waf.rules.rule_loader import load_default_rules
from waf.threat_intel.ip_reputation import IPReputationChecker

logger = logging.getLogger(__name__)

api = Blueprint("api", __name__)

_start_time = time.time()
_VERSION = "0.1.0"

# Module-level singletons initialised on first request via _ensure_components.
_metrics: WAFMetrics | None = None
_rule_engine: RuleEngine | None = None
_ip_checker: IPReputationChecker | None = None
_recent_detections: list[dict] = []


def _ensure_components() -> None:
    """Lazily create shared components so the blueprint works without
    the full application wiring being in place yet."""
    global _metrics, _rule_engine, _ip_checker  # noqa: PLW0603

    if _metrics is None:
        _metrics = WAFMetrics()
    if _rule_engine is None:
        _rule_engine = RuleEngine()
        _rule_engine.load_rules(load_default_rules())
    if _ip_checker is None:
        _ip_checker = IPReputationChecker()


# ------------------------------------------------------------------
# Status & Metrics
# ------------------------------------------------------------------

@api.route("/api/status")
@require_api_key
def get_status():
    """Return current WAF status."""
    from flask import current_app

    settings: Settings = current_app.config.get("WAF_SETTINGS", Settings())
    return jsonify({
        "status": "running",
        "mode": settings.mode,
        "uptime_seconds": round(time.time() - _start_time, 2),
        "version": _VERSION,
    })


@api.route("/api/metrics")
@require_api_key
def get_metrics():
    """Return collected metrics."""
    _ensure_components()
    return jsonify(_metrics.get_metrics())


# ------------------------------------------------------------------
# Rules
# ------------------------------------------------------------------

@api.route("/api/rules", methods=["GET"])
@require_api_key
def list_rules():
    """List all loaded detection rules."""
    _ensure_components()
    rules = [
        {
            "id": rule.get("id"),
            "name": rule.get("name"),
            "severity": rule.get("severity"),
            "target": rule.get("target"),
            "action": rule.get("action"),
        }
        for rule in _rule_engine._rules
    ]
    return jsonify({"rules": rules, "count": len(rules)})


@api.route("/api/rules", methods=["POST"])
@require_api_key
def add_rule():
    """Add a new detection rule (expects JSON body)."""
    _ensure_components()
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    required = {"id", "name", "pattern", "target", "severity", "action"}
    missing = required - set(data.keys())
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(sorted(missing))}"}), 400

    _rule_engine._rules.append(data)
    _rule_engine.load_rules(_rule_engine._rules)
    logger.info("Rule added via API: %s", data.get("id"))
    return jsonify({"message": "Rule added", "rule_id": data["id"]}), 201


# ------------------------------------------------------------------
# Threat detections
# ------------------------------------------------------------------

@api.route("/api/threats")
@require_api_key
def list_threats():
    """Return recent threat detections."""
    limit = request.args.get("limit", 100, type=int)
    return jsonify({"threats": _recent_detections[-limit:], "count": len(_recent_detections)})


def record_detection(detection: dict) -> None:
    """Append a detection dict to the in-memory recent-detections list.

    Called by the core proxy pipeline after a threat is detected.
    """
    _recent_detections.append({**detection, "timestamp": time.time()})
    # Keep the list bounded
    if len(_recent_detections) > 10_000:
        _recent_detections[:] = _recent_detections[-5_000:]


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

@api.route("/api/config", methods=["POST"])
@require_api_key
def update_config():
    """Update WAF configuration at runtime (partial merge)."""
    from flask import current_app

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    settings: Settings = current_app.config.get("WAF_SETTINGS", Settings())
    # Merge top-level keys into the live configuration
    for key, value in data.items():
        if isinstance(value, dict) and isinstance(settings._data.get(key), dict):
            settings._data[key].update(value)
        else:
            settings._data[key] = value

    logger.info("Configuration updated via API")
    return jsonify({"message": "Configuration updated"})


# ------------------------------------------------------------------
# IP Blocklist
# ------------------------------------------------------------------

@api.route("/api/ip/blocklist", methods=["GET"])
@require_api_key
def get_blocklist():
    """Return the current IP blocklist."""
    _ensure_components()
    blocklist = {
        ip: {"reason": entry.get("reason", ""), "added_at": entry.get("added_at")}
        for ip, entry in _ip_checker._blocklist.items()
    }
    return jsonify({"blocklist": blocklist, "count": len(blocklist)})


@api.route("/api/ip/blocklist", methods=["POST"])
@require_api_key
def add_to_blocklist():
    """Add an IP address to the blocklist."""
    _ensure_components()
    data = request.get_json(silent=True)
    if not data or "ip" not in data:
        return jsonify({"error": "Missing 'ip' field"}), 400

    ip = data["ip"]
    reason = data.get("reason", "manual")
    _ip_checker.add_to_blocklist(ip, reason)
    return jsonify({"message": f"IP {ip} added to blocklist"}), 201


@api.route("/api/ip/blocklist/<ip>", methods=["DELETE"])
@require_api_key
def remove_from_blocklist(ip: str):
    """Remove an IP address from the blocklist."""
    _ensure_components()
    if ip not in _ip_checker._blocklist:
        return jsonify({"error": f"IP {ip} not found in blocklist"}), 404

    _ip_checker.remove_from_blocklist(ip)
    return jsonify({"message": f"IP {ip} removed from blocklist"})
