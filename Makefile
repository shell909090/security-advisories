.DEFAULT_GOAL := check
UV ?= uv

.PHONY: sync test complexity mi quality check
sync:
	$(UV) sync --group dev

test:
	$(UV) run --group dev python -m unittest discover -s tests -t . -v

complexity:
	$(UV) run --group dev python scripts/check_quality.py complexity

mi:
	$(UV) run --group dev python scripts/check_quality.py mi

quality:
	$(UV) run --group dev python scripts/check_quality.py all

check: test quality
