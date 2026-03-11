"""Load WAF rules from YAML configuration files."""

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_RULES_PATH = Path(__file__).parent / "default_rules.yaml"


def load_rules_from_file(filepath: str | Path) -> list[dict]:
    """Load rules from a YAML file and return them as a list of dicts.

    The YAML file must contain a top-level ``rules`` key whose value is
    a list of rule dictionaries.

    Args:
        filepath: Path to the YAML rules file.

    Returns:
        A list of rule dictionaries.  Returns an empty list if the file
        cannot be read or parsed.
    """
    filepath = Path(filepath)
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        logger.error("Rules file not found: %s", filepath)
        return []
    except yaml.YAMLError:
        logger.error("Failed to parse rules file: %s", filepath, exc_info=True)
        return []

    rules = data.get("rules", [])
    if not isinstance(rules, list):
        logger.warning("Expected 'rules' to be a list in %s", filepath)
        return []

    logger.info("Loaded %d rules from %s", len(rules), filepath)
    return rules


def load_default_rules() -> list[dict]:
    """Load the built-in default rules shipped with the package.

    Returns:
        A list of rule dictionaries from ``default_rules.yaml``.
    """
    return load_rules_from_file(_DEFAULT_RULES_PATH)
