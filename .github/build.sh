#!/bin/bash

set -ex

mkdir -p ailib/version
git rev-parse --short HEAD > ailib/version/git
docker build -t quay.io/karmab/aicli -f Dockerfile .
