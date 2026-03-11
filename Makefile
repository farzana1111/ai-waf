.PHONY: install dev-install lint format test train docker-build docker-up clean run

install:
	pip install -r requirements.txt
	pip install -e .

dev-install:
	pip install -r requirements-dev.txt
	pip install -e .

lint:
	flake8 waf/ tests/
	black --check waf/ tests/

format:
	black waf/ tests/

test:
	pytest tests/ -v --cov=waf --cov-report=term-missing

train:
	python -m training.train_models

docker-build:
	docker compose -f docker/docker-compose.yaml build

docker-up:
	docker compose -f docker/docker-compose.yaml up -d

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info .pytest_cache htmlcov .coverage

run:
	python -m waf.app
