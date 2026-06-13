# sentinel-as-code — Detection-as-Code Makefile
# Each target mirrors a `sentinel` CLI subcommand so contributors and CI share
# the exact same entrypoints.

# Use uv when available; fall back to a plain virtualenv otherwise.
UV := $(shell command -v uv 2> /dev/null)
ifeq ($(UV),)
RUN := python -m
SENTINEL := python -m sentinelcode.cli
else
RUN := uv run python -m
SENTINEL := uv run sentinel
endif

REPORT ?=
ENGINE ?= python

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## Create the environment and install dependencies (uv).
ifeq ($(UV),)
	python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
else
	uv sync --extra dev
endif

.PHONY: validate
validate: ## Validate every Sigma rule (pySigma validators + yamllint).
	$(SENTINEL) validate

.PHONY: test
test: ## Run the offline TP/FP detection test suite (no Elastic required).
	$(SENTINEL) test

.PHONY: coverage
coverage: ## Generate the ATT&CK Navigator layer and the Markdown coverage summary.
	$(SENTINEL) coverage

.PHONY: convert
convert: ## Convert every rule to Elastic Detection Engine NDJSON in build/elastic/.
	$(SENTINEL) convert

.PHONY: deploy
deploy: ## Idempotently publish rules to the local Kibana Detection Engine.
	$(SENTINEL) deploy

.PHONY: genrule
genrule: ## Generate a Sigma rule draft from a threat report (REPORT=<file>).
	$(SENTINEL) genrule --report "$(REPORT)"

.PHONY: up
up: ## Start Elasticsearch + Kibana (single node, memory-limited) via docker-compose.
	docker compose up -d

.PHONY: down
down: ## Stop the Elasticsearch + Kibana stack.
	docker compose down

.PHONY: lint
lint: ## Lint the codebase (ruff + yamllint).
	$(RUN) ruff check src tests
	$(RUN) yamllint detections config

.PHONY: fmt
fmt: ## Auto-format the codebase (ruff format + import fixes).
	$(RUN) ruff format src tests
	$(RUN) ruff check --fix src tests

.PHONY: typecheck
typecheck: ## Run mypy in permissive mode.
	$(RUN) mypy

.PHONY: clean
clean: ## Remove build artifacts and caches.
	rm -rf build/elastic build/zircolite
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .mypy_cache
