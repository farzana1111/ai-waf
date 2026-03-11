"""Evaluate trained AI-WAF models against test payloads.

Loads the SQLi, XSS, and anomaly models from the ``models/``
directory, runs them against known payloads, and prints standard
classification metrics.
"""

import os
import sys

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
)

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from waf.ai.feature_extractor import FeatureExtractor
from waf.ai.model_manager import ModelManager
from waf.core.request_parser import ParsedRequest

# ------------------------------------------------------------------
# Test payloads
# ------------------------------------------------------------------

NORMAL_PAYLOADS = [
    "search=good+morning",
    "user=alice&page=3",
    "q=best+coffee+shops",
    "category=electronics&brand=acme",
    "id=100",
]

SQLI_PAYLOADS = [
    "id=1' OR '1'='1'--",
    "q=1 UNION SELECT username,password FROM users",
    "search='; DROP TABLE orders;--",
    "id=1 AND SLEEP(5)--",
    "q=' HAVING 1=1--",
]

XSS_PAYLOADS = [
    '<script>alert("xss")</script>',
    '<img src=x onerror=alert(1)>',
    "javascript:alert(document.cookie)",
    '<svg onload=alert(1)>',
    '<body onload=alert("x")>',
]


def _extract_features(payloads: list[str]) -> np.ndarray:
    extractor = FeatureExtractor()
    features_list: list[list[float]] = []
    for payload in payloads:
        parsed = ParsedRequest(
            method="GET",
            path="/test",
            query_params={"input": payload},
            headers={"User-Agent": "Mozilla/5.0"},
            body="",
            client_ip="127.0.0.1",
        )
        features = extractor.extract(parsed)
        features_list.append(list(features.values()))
    return np.array(features_list)


def _evaluate_binary_model(
    model,
    model_name: str,
    X_normal: np.ndarray,
    X_attack: np.ndarray,
) -> None:
    """Evaluate a binary classifier and print metrics."""
    X = np.vstack([X_normal, X_attack])
    y_true = np.array([0] * len(X_normal) + [1] * len(X_attack))

    y_prob = model.predict_proba(X)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    print(f"\n{'=' * 50}")
    print(f"  {model_name} Model Evaluation")
    print(f"{'=' * 50}")
    print(f"Accuracy : {accuracy_score(y_true, y_pred):.4f}")
    print(f"Precision: {precision_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"Recall   : {recall_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"\nConfusion Matrix:\n{confusion_matrix(y_true, y_pred)}")
    print(f"\nClassification Report:")
    print(classification_report(y_true, y_pred, target_names=["normal", model_name.lower()], zero_division=0))


def _evaluate_anomaly_model(model, X_normal: np.ndarray, X_attack: np.ndarray) -> None:
    """Evaluate the Isolation Forest anomaly model."""
    X = np.vstack([X_normal, X_attack])
    # IsolationForest: 1 = inlier, -1 = outlier
    y_true = np.array([0] * len(X_normal) + [1] * len(X_attack))
    raw_preds = model.predict(X)
    # Map: 1 (inlier) → 0 (normal), -1 (outlier) → 1 (anomaly)
    y_pred = (raw_preds == -1).astype(int)

    print(f"\n{'=' * 50}")
    print("  Anomaly Model Evaluation")
    print(f"{'=' * 50}")
    print(f"Accuracy : {accuracy_score(y_true, y_pred):.4f}")
    print(f"Precision: {precision_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"Recall   : {recall_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"\nConfusion Matrix:\n{confusion_matrix(y_true, y_pred)}")
    print(f"\nClassification Report:")
    print(classification_report(y_true, y_pred, target_names=["normal", "anomaly"], zero_division=0))


def evaluate() -> None:
    """Load models and run evaluation."""
    model_dir = os.path.join(_PROJECT_ROOT, "models")
    manager = ModelManager(model_dir)

    X_normal = _extract_features(NORMAL_PAYLOADS)
    X_sqli = _extract_features(SQLI_PAYLOADS)
    X_xss = _extract_features(XSS_PAYLOADS)

    # Combine attack payloads for anomaly detection evaluation
    X_attack = np.vstack([X_sqli, X_xss])

    sqli_model = manager.get_model("sqli_model")
    if sqli_model:
        _evaluate_binary_model(sqli_model, "SQLi", X_normal, X_sqli)
    else:
        print("\n⚠  SQLi model not found — skipping evaluation")

    xss_model = manager.get_model("xss_model")
    if xss_model:
        _evaluate_binary_model(xss_model, "XSS", X_normal, X_xss)
    else:
        print("\n⚠  XSS model not found — skipping evaluation")

    anomaly_model = manager.get_model("anomaly_model")
    if anomaly_model:
        _evaluate_anomaly_model(anomaly_model, X_normal, X_attack)
    else:
        print("\n⚠  Anomaly model not found — skipping evaluation")


if __name__ == "__main__":
    evaluate()
