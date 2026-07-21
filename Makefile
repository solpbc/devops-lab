PYTHON ?= python3

.PHONY: install check test ci clean

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	./test/build-check.sh selftest

check:
	$(PYTHON) -m compileall -q fetch-report.py verifier.py test/python-verifier-selftest.py
	bash -n demo.sh demo-aci.sh run.sh verify.sh test/build-check.sh test/freshness-selftest.sh test/verifier-selftest.sh

ci: check test

clean:
	rm -rf __pycache__ test/__pycache__ .pytest_cache
