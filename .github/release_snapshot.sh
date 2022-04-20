#!/bin/bash

set -ex

TAG="$(date +%y.%m)"
mkdir -p ailib/version
git rev-parse --short HEAD > ailib/version/git
docker build -t quay.io/karmab/aicli:$TAG -f Dockerfile .
docker login -u $QUAY_USERNAME -p $QUAY_PASSWORD quay.io
docker push quay.io/karmab/aicli:$TAG

# export VERSION=$(date "+%Y%m%d%H%M")
# sed -i "s/99.0/99.0.$VERSION/" setup.py
# python setup.py bdist_wheel
# pip3 install twine
# twine upload --repository-url https://upload.pypi.org/legacy/ -u $PYPI_USERNAME -p $PYPI_PASSWORD --skip-existing dist/*
