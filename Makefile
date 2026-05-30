# ─────────────────────────────────────────────────────────────────────────────
# Augur — Makefile task runner
#
# Python env is managed with uv (https://docs.astral.sh/uv/); the React console
# with pnpm. Targets are self-documenting: run `make` (or `make help`) to list
# them. Override any tunable on the CLI, e.g. `make demo PORT=9000`.
# ─────────────────────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

# ── Tunables ─────────────────────────────────────────────────────────────────
UV     ?= uv
PORT   ?= 8000
CORPUS ?= sample_data/corpus/enterprise_day.jsonl

PYTHON := $(UV) run python
PYTEST := $(UV) run pytest

# First-run admin so the console is loginable on a fresh DB. Scoped to the serve
# targets only (not exported into `make test`). Override the password in real use:
#   make demo AUGUR_ADMIN_PASSWORD=…
demo demo-min dev: export AUGUR_ADMIN_USER     ?= admin
demo demo-min dev: export AUGUR_ADMIN_PASSWORD ?= dev-password-123

##@ Setup
.PHONY: install
install: ## Install Python deps into a uv-managed venv
	$(UV) sync

# Incremental: pnpm install runs only when package.json / lockfile changes.
frontend/node_modules: frontend/package.json frontend/pnpm-lock.yaml
	cd frontend && pnpm install
	@touch $@

##@ Develop
.PHONY: dev
dev: ## Hot-reload dev: API (:8000, auto-reload) + Vite (:5173, HMR) — open http://localhost:5173, Ctrl-C stops both
	$(MAKE) -j2 dev-api ui-dev

.PHONY: dev-real
dev-real: ## Hot-reload dev on the REAL OTRF dataset: API (:8000, --real) + Vite (:5173) — auto-fetches+tags the capture
	$(MAKE) -j2 dev-api-real ui-dev

.PHONY: dev-api
dev-api: ## Start only the API with auto-reload on src/augur/*.py changes (:8000)
	$(PYTHON) -m augur.demo --logs $(CORPUS) --port $(PORT) --reload

.PHONY: dev-api-real
dev-api-real: ## Start only the API on the real OTRF dataset with auto-reload (:8000)
	$(PYTHON) -m augur.demo --real --port $(PORT) --reload

.PHONY: ui-dev
ui-dev: frontend/node_modules ## Start only the Vite dev server (:5173, HMR; proxies /api → :8000)
	cd frontend && pnpm dev

.PHONY: test
test: ## Run the full test suite (infra-free)
	$(PYTEST) -q

##@ Run the engine
.PHONY: engine
engine: ## Headless: run the engine on a planted-attack feed and print detections
	$(PYTHON) -m augur.demo --no-serve

.PHONY: demo
demo: ## Serve the SOC console on the ~9.6k-event enterprise-day corpus (http://127.0.0.1:8000)
	$(PYTHON) -m augur.demo --logs $(CORPUS) --port $(PORT)

.PHONY: demo-min
demo-min: ## Serve the console on the minimal 2-attack sample (crisp, easy to read)
	$(PYTHON) -m augur.demo --port $(PORT)

.PHONY: demo-real
demo-real: ## Serve the console on the REAL OTRF mimikatz capture — shows SCEN-REAL-WIN-T1003-001 (http://127.0.0.1:8000)
	$(PYTHON) -m augur.demo --real --port $(PORT)

.PHONY: demo-real-all
demo-real-all: ## Serve the console on the REAL Wave-1 SUITE — all 7 real detections at once (http://127.0.0.1:8000)
	$(PYTHON) -m augur.demo --real all --port $(PORT)

.PHONY: hunt
hunt: ## Run a hunt: corpus → engine → stdout + out/detections.jsonl
	@mkdir -p out
	$(PYTHON) -m augur.hunt \
	  --source jsonl --source-arg path=$(CORPUS) \
	  --sink stdout --sink jsonl --sink-arg jsonl:path=out/detections.jsonl \
	  --min-proximity 0.9

##@ Frontend build
.PHONY: ui-build
ui-build: frontend/node_modules ## Compile the React console into frontend/dist
	cd frontend && pnpm build

##@ Docker stack
.PHONY: up
up: ui-build ## Build the UI, then run the full stack (FastAPI + Neo4j) detached
	docker compose up -d --build

.PHONY: down
down: ## Stop the Docker stack (named volumes persist)
	docker compose down

.PHONY: logs
logs: ## Tail the app container logs
	docker compose logs -f app

.PHONY: neo4j-local
neo4j-local: ## Run only Neo4j in Docker; serve the demo locally against it
	docker compose up -d neo4j
	AUGUR_BACKEND=neo4j NEO4J_URI=bolt://localhost:7687 $(UV) run --extra neo4j python -m augur.demo

##@ Misc
.PHONY: grpc-demo
grpc-demo: ## Polyglot slice: Go collector → gRPC → Python engine
	bash services/run-grpc-demo.sh

.PHONY: clean
clean: ## Remove caches and build artifacts
	rm -rf .pytest_cache src/*.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

##@ Help
.PHONY: help
help: ## Show this help
	@awk 'BEGIN { FS = ":.*##"; printf "\nAugur — make targets\n" } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5); next } \
		/^[a-zA-Z0-9_\/-]+:.*##/ { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' \
		$(MAKEFILE_LIST)
	@printf "\n"
