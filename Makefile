# Common tasks. `make help` lists them.
PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.DEFAULT_GOAL := help
.PHONY: help install test test-fast lint format typecheck check dashboard-install dashboard-build dashboard-dev \
	env up down logs ps seed demo wheel clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ------------------------------------------------------------------------ development
install: ## Create .venv and install llmscan with every extra plus the dev tools
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[all,dev]"

test: ## Run the whole test suite (set REDIS_URL / TEST_POSTGRES_URL to include the integration tests)
	$(BIN)/pytest

test-fast: ## Skip the slow integration tests
	$(BIN)/pytest -m "not integration" -q

lint: ## ruff check + format check
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

format: ## Apply ruff formatting and safe fixes
	$(BIN)/ruff check --fix .
	$(BIN)/ruff format .

typecheck: ## mypy over the Python packages
	$(BIN)/mypy scanner api targets

check: lint typecheck test ## Everything CI runs for the Python side

dashboard-install: ## npm ci in dashboard/
	cd dashboard && npm ci

dashboard-build: ## Type-check and build the dashboard
	cd dashboard && npm run typecheck && npm run build

dashboard-dev: ## Dashboard dev server on :3000 (needs the API on :8000, e.g. `llmscan serve`)
	cd dashboard && LLMSCAN_API_URL=$${LLMSCAN_API_URL:-http://localhost:8000} npm run dev

# --------------------------------------------------------------------------- docker
env: ## Create .env with freshly generated secrets (never overwrites)
	@sh scripts/init-env.sh

up: env ## Build and start the whole stack (dashboard on http://localhost:3000)
	docker compose up -d --build
	@echo "Dashboard: http://localhost:$${DASHBOARD_PORT:-3000}  |  API docs: http://localhost:$${API_PORT:-8000}/api/v1/docs"

down: ## Stop the stack (keeps the database volume)
	docker compose down

logs: ## Follow the logs
	docker compose logs -f --tail=100

ps: ## Show service status
	docker compose ps

seed: ## Fill a running stack with demo runs (uses the key from .env)
	@. ./.env && $(BIN)/python scripts/seed_demo.py --api http://localhost:$${API_PORT:-8000} --key "$$LLMSCAN_API_KEY"

# ------------------------------------------------------------------------------ misc
demo: ## Scan the built-in vulnerable demo app and write reports/ (no network, no Docker)
	$(BIN)/llmscan run demo:weak --seed 1 -o reports/demo.html -o reports/demo.json -o reports/demo.sarif

wheel: ## Build the wheel (ships the probe library and report template)
	$(BIN)/pip wheel . --no-deps -w dist

clean: ## Remove build and cache directories
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache dashboard/.next reports llmscan-reports
