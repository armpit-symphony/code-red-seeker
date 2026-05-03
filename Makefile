.PHONY: help py-compile test-scanner smoke-review frontend-install frontend-build

help:
	@echo "Code Red Seeker developer tasks"
	@echo "  make py-compile        Compile touched Python entrypoints"
	@echo "  make test-scanner      Run scanner bridge and dedupe tests"
	@echo "  make smoke-review      Run a passive scanner smoke test"
	@echo "  make frontend-install  Install frontend dependencies"
	@echo "  make frontend-build    Build the platform frontend"

py-compile:
	python -m py_compile code_red_seeker.py platform/backend/models.py platform/backend/finding_dedupe.py platform/backend/scanner_jobs.py platform/backend/server.py engines/swarm-review/agents/secrets_detector.py engines/swarm-review/core/report.py

test-scanner:
	python -m pytest platform/backend/tests/test_scanner_jobs.py platform/backend/tests/test_finding_dedupe.py --basetemp pytest-work -o cache_dir=pytest-cache

smoke-review:
	python code_red_seeker.py review --repo platform/backend/tests --profile review-passive --out artifacts/smoke-code-review

frontend-install:
	npm --prefix platform/frontend install

frontend-build:
	npm --prefix platform/frontend run build
