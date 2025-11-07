.PHONY: clean-pyc clean-build docs help
.DEFAULT_GOAL := help

help:
	@perl -nle'print $& if m{^[a-zA-Z_-]+:.*?## .*$$}' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

clean: clean-build clean-pyc

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr *.egg-info

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -rf {} +

lint: ## check style with flake8
	flake8 mozilla_django_oidc tests

test: ## run tests quickly with the default Python
	DJANGO_SETTINGS_MODULE=tests.settings python -m django test

test-all: ## run tests on every Python version with tox
	tox

coverage: ## check code coverage quickly with the default Python
	coverage run --source mozilla_django_oidc -m django test --settings=tests.settings
	coverage report -m
	coverage html
	open htmlcov/index.html

docs: ## generate Sphinx HTML documentation, including API docs
	rm -rf docs/source
	sphinx-apidoc -o docs/source/ mozilla_django_oidc
	$(MAKE) -C docs clean
	$(MAKE) -C docs html

build: clean ## build the sdist and wheel
	python -m build . --sdist --wheel
	ls -l dist

release: build ##package and upload a release
	twine upload dist/*

sdist: clean ## package
	python -m build . --sdist
	ls -l dist
