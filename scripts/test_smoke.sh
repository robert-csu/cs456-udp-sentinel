#!/usr/bin/env bash
set -e
for p in sentinel monitor client; do
    [ -x "bin/$p" ] || { echo "Error: $p not found or not executable"; exit 1; }
done
# the sentinel runs until signalled or its injected crash, so only check that it starts and parses options
bin/sentinel --help > /dev/null
bin/monitor > /dev/null
bin/client > /dev/null
