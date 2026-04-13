PYTHON ?= python3

.PHONY: install test serve

install:
	$(PYTHON) -m venv .venv
	. .venv/bin/activate && python -m pip install -e ".[dev]"

test:
	. .venv/bin/activate && pytest

serve:
	. .venv/bin/activate && glasswall serve --host 127.0.0.1 --port 8080
