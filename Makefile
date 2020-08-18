MYPYPATH = $(shell pwd)/.travis/mypy-stubs

PYTHON ?= python3

install-python-requirements:
	$(PYTHON) -m ensurepip
	$(PYTHON) -m pip install -U pip
	$(PYTHON) -m pip install -Ur requirements.txt

install-python-requirements-dev: install-python-requirements
	$(PYTHON) -m pip install -Ur requirements-dev.txt

check:
	flake8 --version
	mypy --version
	flake8 --exclude=".travis,.eggs,__init__.py,docs,tests" --ignore=E203,E252,W391,D107,A001,A002,A003,A004,D412,D413,T499
	bandit --skip B404,B110 --exclude tests/ *.py jail/*.py
test:
	pytest tests --zpool $(ZPOOL)

.PHONY: docs
docs:
	$(PYTHON) setup.py build_sphinx

help:
	@echo "    install"
	@echo "        Installs libioc"
	@echo "    uninstall"
	@echo "        Removes libioc"
	@echo "    test"
	@echo "        Run unit tests with pytest"
	@echo "    check"
	@echo "        Run static linters & other static analysis tests"
	@echo "    install-dev"
	@echo "        Install dependencies needed to run `check`"
