.PHONY: install run-sample run-live test clean

VENV?=.venv
PYTHON?=python3

install:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip || true
	$(VENV)/bin/pip install -e .

run-sample: ensure-venv
	$(VENV)/bin/security-dashboard --sample-data

run-live: ensure-venv
	$(VENV)/bin/security-dashboard --include-github \
		--include-code-scanning \
		--include-secret-scanning \
		--include-dependabot

ensure-venv:
	@[ -d $(VENV) ] || (echo "Virtualenv not found. Run 'make install' first." && exit 1)

clean:
	rm -rf $(VENV)

pytest := $(VENV)/bin/pytest

test: ensure-venv
	$(pytest)
