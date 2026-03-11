# Training Datasets

This directory stores datasets used to train the AI-WAF machine-learning models.

## Preparing Your Own Datasets

### Expected Format

Each dataset should be a **CSV** file with the following columns:

| Column    | Type   | Description                              |
|-----------|--------|------------------------------------------|
| `payload` | string | The raw HTTP parameter / body content    |
| `label`   | int    | `0` for benign, `1` for malicious        |

Optional columns (if available):

| Column        | Type   | Description                    |
|---------------|--------|--------------------------------|
| `attack_type` | string | e.g. `sqli`, `xss`, `normal`  |
| `source`      | string | Origin of the sample           |

### Example

```csv
payload,label,attack_type
hello world,0,normal
<script>alert(1)</script>,1,xss
1' OR '1'='1,1,sqli
page=2&sort=name,0,normal
```

### Public Data Sources

The following open datasets can be used for training (download manually and place here):

1. **CSIC 2010** — HTTP dataset with normal and anomalous web requests.
2. **SQLi payload lists** — available on GitHub (e.g. `payloadbox/sql-injection-payload-list`).
3. **XSS payload lists** — available on GitHub (e.g. `payloadbox/xss-payload-list`).

### Using Synthetic Data

If you do not have external datasets, the training scripts generate synthetic data automatically:

```bash
python training/train_sqli_model.py
python training/train_xss_model.py
python training/train_anomaly_model.py
```

### Using Custom Datasets

To train with your own CSV files, modify the relevant training script to load data from this directory instead of generating synthetic payloads. For example:

```python
import pandas as pd

df = pd.read_csv("training/datasets/sqli_dataset.csv")
payloads = df["payload"].tolist()
labels = df["label"].tolist()
```

### Tips

- Balance your dataset — aim for a roughly equal number of benign and malicious samples.
- Deduplicate payloads to avoid biased evaluation.
- Normalise payloads (URL-decode, lowercase) before feature extraction for consistency.
- Use `training/evaluate.py` to measure precision, recall, and accuracy after training.
