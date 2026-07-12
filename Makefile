PYTHON ?= python3

.PHONY: install check test ci clean

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	./test/build-check.sh selftest

check:
	$(PYTHON) -m compileall -q verifier.py ratls_contract.py ratls_collector.py ratls_gateway.py asr_shim.py strict_wav.py test/python-verifier-selftest.py test/ratls-gateway-selftest.py test/asr-shim-selftest.py
	$(PYTHON) ratls_contract.py check

ci: check test

clean:
	rm -rf __pycache__ test/__pycache__ .pytest_cache

.PHONY: ratls-contract
ratls-contract:
	$(PYTHON) ratls_contract.py generate
