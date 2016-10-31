#!/bin/bash

mkdir -p dist
for GOOS in darwin linux windows; do
  for GOARCH in 386 amd64; do
    echo "Building $GOOS-$GOARCH"
    env GOOS=$GOOS GOARCH=$GOARCH go build -o dist/aws-es-proxy-$GOOS-$GOARCH
  done
done
