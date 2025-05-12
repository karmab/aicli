#!/bin/bash

set -ex

mkdir -p src/ailib/version
git rev-parse --short HEAD > src/ailib/version/git
podman build -t quay.io/karmab/aicli -f Dockerfile .
