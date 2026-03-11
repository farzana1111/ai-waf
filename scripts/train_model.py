#!/usr/bin/env python3
"""CLI entry-point for training the WAF threat-detection model.

Usage
-----
    python -m scripts.train_model [--output PATH] [--boosting]
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train the AI-WAF ML threat-detection model."
    )
    parser.add_argument(
        "--output",
        default="waf/model/threat_model.joblib",
        help="Output path for the serialised model bundle (default: waf/model/threat_model.joblib)",
    )
    parser.add_argument(
        "--boosting",
        action="store_true",
        default=False,
        help="Use GradientBoostingClassifier instead of RandomForestClassifier.",
    )
    args = parser.parse_args()

    from waf.model.trainer import train_and_save  # noqa: PLC0415 (late import OK)

    train_and_save(Path(args.output), boosting=args.boosting)
    print(f"✓ Model saved to {args.output}")


if __name__ == "__main__":
    main()
