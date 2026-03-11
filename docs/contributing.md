# Contributing Guide

Thank you for your interest in contributing to AI-WAF! This document explains how to set up a development environment, run tests, and submit changes.

## Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/ai-waf/ai-waf.git
cd ai-waf
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .
```

## Running Tests

```bash
pytest tests/ -v
```

Run a specific test file:

```bash
pytest tests/test_feature_extractor.py -v
```

## Code Style

- Follow **PEP 8** conventions.
- Use **Black** for formatting and **flake8** for linting:

```bash
black waf/ tests/ training/
flake8 waf/ tests/ training/
```

- Use type hints for function signatures.
- Write docstrings for public classes and functions.

## Project Structure

```
waf/
├── ai/          # ML feature extraction, models, explainability
├── api/         # REST management API
├── config/      # Settings and default configuration
├── core/        # Flask proxy, request parsing, response handling
├── logging/     # Structured logging, metrics, alerting
├── rules/       # Regex rule engine and rule loader
├── threat_intel/ # Threat feeds and IP reputation
└── utils/       # Encoding helpers and validators
training/        # Model training scripts
tests/           # Test suite
docker/          # Docker and Compose files
docs/            # Documentation
```

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`.
2. **Write tests** for any new functionality.
3. **Run the full test suite** — all tests must pass.
4. **Format your code** with Black and ensure flake8 reports no errors.
5. **Write a clear PR description** explaining the change and its motivation.
6. Submit the PR and address reviewer feedback.

## Adding Detection Rules

Custom rules go in `waf/rules/default_rules.yaml`. Each rule requires:

```yaml
- id: "CUSTOM-001"
  name: "Description of the rule"
  pattern: "regex-pattern"
  target: "all"        # all | url | body | headers
  severity: "high"     # critical | high | medium | low | info
  action: "block"      # block | log
```

## Training Models

See `training/datasets/README.md` for dataset preparation. To retrain:

```bash
python training/train_sqli_model.py
python training/train_xss_model.py
python training/train_anomaly_model.py
python training/evaluate.py
```

## Reporting Issues

Open an issue on GitHub with:

- Steps to reproduce
- Expected vs actual behaviour
- Python version and OS
- Relevant log output
