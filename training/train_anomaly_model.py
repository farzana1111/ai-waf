"""Train an Isolation Forest model for anomaly detection.

Generates normal-traffic feature vectors, fits an
:class:`~sklearn.ensemble.IsolationForest`, and saves the trained
model to the ``models/`` directory.
"""

import os
import sys

import numpy as np

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from waf.ai.feature_extractor import FeatureExtractor
from waf.core.request_parser import ParsedRequest

# ------------------------------------------------------------------
# Synthetic normal-traffic data
# ------------------------------------------------------------------

NORMAL_REQUESTS = [
    {"method": "GET", "path": "/", "params": {}},
    {"method": "GET", "path": "/index.html", "params": {}},
    {"method": "GET", "path": "/about", "params": {}},
    {"method": "GET", "path": "/products", "params": {"page": "1", "limit": "20"}},
    {"method": "GET", "path": "/search", "params": {"q": "running shoes"}},
    {"method": "POST", "path": "/login", "params": {}, "body": "user=alice&pass=secret"},
    {"method": "GET", "path": "/api/items", "params": {"sort": "name", "order": "asc"}},
    {"method": "GET", "path": "/blog/2024/hello-world", "params": {}},
    {"method": "POST", "path": "/contact", "params": {}, "body": "name=Bob&message=Hi+there"},
    {"method": "GET", "path": "/images/logo.png", "params": {}},
    {"method": "GET", "path": "/css/style.css", "params": {}},
    {"method": "GET", "path": "/js/app.js", "params": {}},
    {"method": "GET", "path": "/users/profile", "params": {"id": "42"}},
    {"method": "GET", "path": "/docs", "params": {"section": "quickstart"}},
    {"method": "POST", "path": "/api/feedback", "params": {}, "body": "rating=5&comment=great"},
]


def _generate_normal_features(multiplier: int = 20) -> np.ndarray:
    """Generate feature vectors from synthetic normal traffic."""
    extractor = FeatureExtractor()
    rng = np.random.default_rng(42)
    all_features: list[list[float]] = []

    for _ in range(multiplier):
        for req in NORMAL_REQUESTS:
            parsed = ParsedRequest(
                method=req["method"],
                path=req["path"],
                query_params=req.get("params", {}),
                headers={"User-Agent": "Mozilla/5.0"},
                body=req.get("body", ""),
                client_ip="127.0.0.1",
            )
            features = extractor.extract(parsed)
            vec = list(features.values())
            # Small noise
            vec = [v + float(rng.normal(0, 0.1)) for v in vec]
            all_features.append(vec)

    return np.array(all_features)


def train() -> None:
    """Generate normal-traffic data, train Isolation Forest, and save the model."""
    from sklearn.ensemble import IsolationForest

    print("Generating normal-traffic feature vectors …")
    X = _generate_normal_features()
    print(f"Training samples: {X.shape[0]}  |  Features: {X.shape[1]}")

    print("Training Isolation Forest …")
    clf = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X)

    # Quick sanity check — most training samples should be inliers
    predictions = clf.predict(X)
    inlier_ratio = (predictions == 1).sum() / len(predictions)
    print(f"\nInlier ratio on training data: {inlier_ratio:.4f}")
    print(f"Outlier ratio on training data: {1 - inlier_ratio:.4f}")

    # Save model
    import joblib

    model_dir = os.path.join(_PROJECT_ROOT, "models")
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "anomaly_model.joblib")
    joblib.dump(clf, model_path)
    print(f"Model saved to {model_path}")


if __name__ == "__main__":
    train()
