.PHONY: install lint format security test check clean

install:
	pip install -r requirements.txt
	pip install ruff bandit pytest pre-commit
	pre-commit install

lint:
	ruff check agent/ mcp_server/
	ruff format --check agent/ mcp_server/

format:
	ruff check --fix agent/ mcp_server/
	ruff format agent/ mcp_server/

security:
	bandit -r agent/ mcp_server/ -s B101

test:
	python -m pytest tests/ -v --tb=short

check: lint security test
	@echo "\n✓ All checks passed"

clean:
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov
	find . -type d -name __pycache__ -not -path "./.venv/*" -exec rm -rf {} + 2>/dev/null || true
