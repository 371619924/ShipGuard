PYTHON ?= python3
.PHONY: test evaluate check reproduce
test:
	$(PYTHON) -m unittest discover -s tests -v
	$(PYTHON) integration.py
evaluate:
	$(PYTHON) evaluate.py
check: test evaluate
	$(PYTHON) run.py --repo repository --out evidence/repository
reproduce:
	$(PYTHON) reproduce.py
