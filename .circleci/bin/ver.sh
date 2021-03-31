#!/usr/bin/env bash

NEWVERSION="$(date +%F)-$(git rev-parse --short HEAD)"

# only non snapshots from master
if [ "$(git rev-parse --abbrev-ref HEAD)" == 'master' ]; then
  echo "$NEWVERSION"
else
  echo "$NEWVERSION-SNAPSHOT"
fi
