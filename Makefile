.PHONY: install run test lint format check benchmark clean up down logs compose-version rebuild ps dogfood dogfood-smoke docker-smoke mcp-docker-smoke bench-static bench-fetch bench-corpus bench-agent bench-all

# === Python / Local Development ===
install:
	uv pip install -e ".[dev]" || pip install -e ".[dev]"

run:
	uvicorn src.terminus.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest tests/ -v

lint:
	ruff check src/ tests/
	mypy src/terminus
	black --check src/ tests/
	isort --check-only src/ tests/

format:
	black src/ tests/
	isort src/ tests/
	ruff check --fix src/ tests/

check: lint test

benchmark:
	pytest tests/ --benchmark-only -v

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache .ruff_cache dist build *.egg-info

# === Docker Compose v2 (Modern) ===
compose-version:
	docker compose version

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f terminus

rebuild:
	docker compose down
	docker compose build --no-cache
	docker compose up -d

ps:
	docker compose ps

# === Dogfood Harness ===
dogfood: ## Live write dogfood: real agent -> Terminus MCP PEP -> Postgres (needs Docker + ANTHROPIC_API_KEY)
	docker compose -f dogfood/compose.yml up -d --wait
	PYTHONPATH=src uv run --extra dogfood python dogfood/run.py; \
	status=$$?; docker compose -f dogfood/compose.yml down -v; exit $$status

dogfood-smoke: ## Dogfood wiring check without an LLM or API key
	docker compose -f dogfood/compose.yml up -d --wait
	PYTHONPATH=src uv run --extra dogfood python dogfood/run.py --smoke; \
	status=$$?; docker compose -f dogfood/compose.yml down -v; exit $$status

docker-smoke: ## Build the hardened image; assert non-root and a healthy /health
	docker build -t terminus-smoke .
	@test "$$(docker run --rm terminus-smoke id -u)" != "0" || (echo "FAIL: container runs as root" && exit 1)
	docker run -d --rm --name terminus-smoke-run -p 18000:8000 \
		-e TERMINUS_ENVIRONMENT=development \
		terminus-smoke \
		python -m uvicorn terminus.main:app --host 0.0.0.0 --port 8000 --no-access-log
	@sleep 3; curl -fsS http://localhost:18000/health \
		|| (docker logs terminus-smoke-run; docker stop terminus-smoke-run; exit 1)
	@docker stop terminus-smoke-run
	@echo "docker-smoke: OK (non-root, /health 200)"

mcp-docker-smoke: ## Containerized MCP PEP over stdio: initialize + tools/list against dogfood Postgres
	docker build -t terminus-smoke .
	docker compose -f dogfood/compose.yml up -d --wait
	PYTHONPATH=src uv run --extra dogfood python scripts/mcp_container_smoke.py; \
	status=$$?; docker compose -f dogfood/compose.yml down -v; exit $$status

bench-static: ## Security-efficacy static scorecard (benign FPR + Youden J); no API key
	PYTHONPATH=src:. uv run python -m bench.run_static

bench-fetch: ## Fetch third-party corpora (libinjection) at a pinned commit into a gitignored cache
	PYTHONPATH=src:. uv run python -m bench.fetch

bench-corpus: bench-fetch ## SQLi executed-rate appendix ("SQL parser-abuse coverage"); no API key
	PYTHONPATH=src:. uv run python -m bench.run_corpus

bench-agent: ## Agent A/B attack-success-rate benchmark (needs Docker + ANTHROPIC_API_KEY; ~$$15/run)
	docker compose -f dogfood/compose.yml up -d --wait
	PYTHONPATH=src:. uv run --extra dogfood python -m bench.run_agent; \
	status=$$?; docker compose -f dogfood/compose.yml down -v; exit $$status

bench-all: bench-static bench-corpus bench-agent ## Run the full security-efficacy benchmark suite
