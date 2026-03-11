"""Train a Random Forest classifier for SQL injection detection.

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

# Ensure the project root is on sys.path so ``waf`` is importable when
# the script is executed directly.
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

SQLI_PAYLOADS = [
    "id=1 UNION SELECT username,password FROM users--",
    "id=1' OR '1'='1",
    "search='; DROP TABLE users;--",
    "username=admin'--",
    "id=1 AND 1=1 UNION SELECT NULL,NULL,NULL--",
    "q=1' UNION SELECT table_name FROM information_schema.tables--",
    "id=1; EXEC xp_cmdshell('dir')--",
    "search=' OR 1=1#",
    "id=1 WAITFOR DELAY '0:0:5'--",
    "input=1' AND SLEEP(5)--",
    "id=1' UNION ALL SELECT 1,2,CONCAT(username,password) FROM users--",
    "q=admin' AND '1'='1",
    "search=1; INSERT INTO users VALUES('hacker','pass')--",
    "id=1' OR ''='",
    "q=' HAVING 1=1--",
    "id=1 ORDER BY 10--",
    "search=1' AND BENCHMARK(10000000,SHA1('test'))--",
    "id=1' UNION SELECT LOAD_FILE('/etc/passwd')--",
    "q=1'; DELETE FROM users WHERE '1'='1",
    "search=' UNION SELECT 1,GROUP_CONCAT(table_name) FROM information_schema.tables--",
]


def _generate_dataset(
    normal_payloads: list[str],
    sqli_payloads: list[str],
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
            path="/search",
            query_params={"q": payload},
            headers={"User-Agent": "Mozilla/5.0"},
            body="",
            client_ip="127.0.0.1",
        )
        features = extractor.extract(parsed)
        # Add small random noise for diversity
        features["payload_length"] += int(rng.integers(-2, 3))
        features_list.append(features)
        labels.append(0)

    for payload in sqli_payloads * multiplier:
        parsed = ParsedRequest(
            method="GET",
            path="/search",
            query_params={"q": payload},
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
    print("Generating synthetic training data …")
    features_list, labels = _generate_dataset(NORMAL_PAYLOADS, SQLI_PAYLOADS)

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
    print(classification_report(y_test, y_pred, target_names=["normal", "sqli"]))

    # Save model
    import joblib

    model_dir = os.path.join(_PROJECT_ROOT, "models")
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "sqli_model.joblib")
    joblib.dump(clf, model_path)
    print(f"Model saved to {model_path}")


if __name__ == "__main__":
    train()
