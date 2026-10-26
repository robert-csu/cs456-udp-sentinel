#!/usr/bin/env bash
set -e
for p in sentinel monitor client; do
    [ -x "bin/$p" ] || { echo "Error: $p not found or not executable"; exit 1; }
    "bin/$p" > /dev/null
done