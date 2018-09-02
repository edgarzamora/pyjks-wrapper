python := $(PWD)/venv/bin/python
sed := sed -i.bak

SOURCES=src utils services scripts

# Check that the virtual env is active and error if not.
check-venv:
ifndef VIRTUAL_ENV
	$(error Not in a virtual environment. Activate your venv and try again)
endif

lint: check-venv
	@./lint

# Create a virtual environment using virtualenv.
venv:
	python3.6 -m venv venv
	@echo 'export PYTHONPATH=$(PWD)/pyjks_wrapper:$$PYTHONPATH' >> venv/bin/activate
	@echo 'export KEYSTORE_CONFIG=$(PWD)/default_config.yaml' >> venv/bin/activate
	$(sed) '/^VIRTUAL_ENV=/ a VIRTUAL_ENV_NAME="pyjkswrapper"' venv/bin/activate
	$(sed) 's/`basename \\"$$VIRTUAL_ENV\\"`/$$VIRTUAL_ENV_NAME/' venv/bin/activate

# Install all the dependencies.
install-dependencies: check-venv
	pip install pip --upgrade
	pip install -r requirements/dev.txt


# Run tests.
test: check-venv
	nosetests

# Format those files that changed in the current patch (and which
# haven't been staged for commit).
format-changed: check-venv
	git diff --name-only | grep '\.py' | xargs utils/format-imports

build-docs: check-venv
	sphinx-apidoc -o docs/api pyjks_wrapper
	sphinx-build docs/ site/
