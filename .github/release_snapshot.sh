#!/bin/bash

set -ex

TAG="$(date +%y.%m)"
mkdir -p src/ailib/version
git rev-parse --short HEAD > src/ailib/version/git
podman build -t quay.io/karmab/aicli:$TAG -f Dockerfile .
podman login -u $QUAY_USERNAME -p $QUAY_PASSWORD quay.io
podman push quay.io/karmab/aicli:$TAG
