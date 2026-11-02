#!/usr/bin/env bash
set -e
for p in sentinel monitor client; do
    [ -x "bin/$p" ] || { echo "Error: $p not found or not executable"; exit 1; }
done
# the sentinel runs until signalled or its injected crash, so only check that it starts and parses options
bin/sentinel --help > /dev/null
# the monitor runs until killed, so it passes if it is still running when the timeout fires (exit 124);
# any other exit code means it failed to start (for example, the bind failed)
status=0
timeout 2 bin/monitor > /dev/null || status=$?
if [ "$status" -ne 124 ]; then
    echo "Error: monitor exited with status $status instead of running until the timeout"
    exit 1
fi
bin/client > /dev/null
