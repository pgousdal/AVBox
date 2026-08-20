.PHONY: test lint typecheck build check registry doctor ansible-syntax

test:
	python -m pytest

lint:
	python -m ruff check src tests

typecheck:
	python -m mypy src/avbox

build:
	python -m build

registry:
	avbox registry validate

doctor:
	avbox doctor

ansible-syntax:
	mkdir -p .state/ansible-tmp
	ANSIBLE_LOCAL_TEMP=$(CURDIR)/.state/ansible-tmp ansible-playbook --syntax-check -i ansible/inventory.example ansible/site.yml

check: test lint typecheck build registry doctor ansible-syntax
