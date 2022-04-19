#!/usr/bin/env bash

set -euo pipefail

IMAGE=trackunit/aws-es-proxy:$(date -u +"%Y-%m-%d-%H%M")

docker build . --no-cache -f Dockerfile  --pull -t "${IMAGE}"
docker push "${IMAGE}"
echo "Pushed ${IMAGE}..."
