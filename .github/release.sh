#!/bin/bash

set -ex
. venv/bin/activate

podman login -u $QUAY_USERNAME -p $QUAY_PASSWORD quay.io
podman push quay.io/karmab/aicli:latest

export VERSION=$(date "+%Y%m%d%H%M")
sed -i "s/99.0/99.0.$VERSION/" setup.py
python3 setup.py bdist_wheel
twine upload --repository-url https://upload.pypi.org/legacy/ -u $PYPI_USERNAME -p $PYPI_PASSWORD --skip-existing dist/*
