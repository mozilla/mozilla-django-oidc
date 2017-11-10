#!/bin/bash

set -e

# Build a new package of mozilla-django-oidc lib
cd ..
make clean
make sdist
rm -rf integration_tests/vendor/
mkdir integration_tests/vendor
mv dist/*.tar.gz integration_tests/vendor/mozilla-django-oidc-latest.tar.gz

# Build and run docker images for `testrp` and `testprovider`
cd integration_tests
docker-compose build
docker-compose up -d
sleep 10

# Run integration tests
python integration_tests.py

# Cleanup env
docker-compose stop
docker-compose rm -f
