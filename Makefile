.PHONY: setup up down logs test lint eval

setup:  ## first run: build, download the model, index the documents, create the users
	test -f .env || (cp .env.example .env && echo "Created .env, edit the secrets then run make setup again" && exit 1)
	mkdir -p index config logs && chmod 777 index config logs
	docker compose build
	docker compose --profile setup run --rm ollama-pull
	docker compose --profile setup run --rm ingest
	docker compose --profile setup run --rm users

up:
	docker compose up -d api ui
	@echo "Web interface: http://localhost:8501   API docs: http://localhost:8000/docs"

down:
	docker compose down

logs:
	docker compose logs -f api

test:
	pytest

lint:
	ruff check . && ruff format --check .

eval:
	python eval/run_eval.py --gate
