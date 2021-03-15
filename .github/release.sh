#!/bin/bash

set -ex

docker login -u ${{ secrets.QUAY_USERNAME }} -p ${{ secrets.QUAY_PASSWORD }} quay.io
docker push quay.io:karmab/aicli:latest
"../pypi.sh"
