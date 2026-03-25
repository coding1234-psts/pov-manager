.PHONY: help test test-no-db test-setup coverage test-quick test-unit test-api test-models test-utils test-commands clean install lint format

help:
	@echo "VDR Test Suite Commands"
	@echo "======================="
	@echo "make install       - Install dependencies"
	@echo "make test-setup    - Run migrations on test database (run once)"
	@echo "make test          - Run all tests (requires database)"
	@echo "make test-no-db    - Run tests without database (API/utils only)"
	@echo "make coverage      - Run tests with coverage report"
	@echo "make test-quick    - Run tests with minimal output"
	@echo "make test-unit     - Run unit tests only"
	@echo "make test-api      - Run API tests"
	@echo "make test-models   - Run model tests"
	@echo "make test-utils    - Run utility tests"
	@echo "make test-commands - Run management command tests"
	@echo "make lint          - Run linting checks"
	@echo "make format        - Format code with black and isort"
	@echo "make clean         - Clean test artifacts"

test-setup:
	@echo "Running migrations on test database..."
	cd pov_manager && DJANGO_SETTINGS_MODULE=pov_manager.test_settings python manage.py migrate


test:
	PYTHONPATH=/app:/app/pov_manager pytest -v --reuse-db --import-mode=importlib -c pov_manager/pytest.ini pov_manager/vdr/tests/

test-no-db:
	@echo "Running tests that don't require database..."
	PYTHONPATH=/app:/app/pov_manager pytest -v --import-mode=importlib -c pov_manager/pytest.ini \
		pov_manager/vdr/tests/test_vdrapi.py \
		pov_manager/vdr/tests/test_ctuapi.py \
		pov_manager/vdr/tests/test_utils.py::TestIPConversion \
		pov_manager/vdr/tests/test_utils.py::TestIPRangeValidation

coverage:
	PYTHONPATH=/app:/app/pov_manager pytest --reuse-db --import-mode=importlib -c pov_manager/pytest.ini --cov=pov_manager/vdr --cov-report=html --cov-report=term-missing pov_manager/vdr/tests/
	@echo "Coverage report: htmlcov/index.html"

test-quick:
	PYTHONPATH=/app:/app/pov_manager pytest -x --reuse-db --tb=short --import-mode=importlib -c pov_manager/pytest.ini pov_manager/vdr/tests/

test-unit:
	PYTHONPATH=/app:/app/pov_manager pytest -v --reuse-db -m unit --import-mode=importlib -c pov_manager/pytest.ini pov_manager/vdr/tests/

test-api:
	PYTHONPATH=/app:/app/pov_manager pytest -v --import-mode=importlib -c pov_manager/pytest.ini pov_manager/vdr/tests/test_vdrapi.py pov_manager/vdr/tests/test_ctuapi.py

test-models:
	PYTHONPATH=/app:/app/pov_manager pytest -v --reuse-db --import-mode=importlib -c pov_manager/pytest.ini pov_manager/vdr/tests/test_models.py

test-utils:
	PYTHONPATH=/app:/app/pov_manager pytest -v --reuse-db --import-mode=importlib -c pov_manager/pytest.ini pov_manager/vdr/tests/test_utils.py

test-commands:
	PYTHONPATH=/app:/app/pov_manager pytest -v --reuse-db --import-mode=importlib -c pov_manager/pytest.ini pov_manager/vdr/tests/test_commands.py

lint:
	flake8 pov_manager/vdr --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 pov_manager/vdr --count --max-complexity=10 --max-line-length=120 --statistics

format:
	black pov_manager/vdr
	isort pov_manager/vdr

clean:
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .coverage
	rm -rf coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
