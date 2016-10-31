#!/bin/bash

rm -rf dist; mkdir -p dist
for GOOS in darwin linux windows; do
  for GOARCH in 386 amd64; do
    echo "Building $GOOS-$GOARCH"
    if [[ $GOOS == "windows" ]]; then
       env GOOS=$GOOS GOARCH=$GOARCH go build -o dist/aws-es-proxy-${GOOS}-${GOARCH}.exe
    else
      env GOOS=$GOOS GOARCH=$GOARCH go build -o dist/aws-es-proxy-${GOOS}-${GOARCH}
    fi
  done
done
