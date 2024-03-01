#!/bin/sh

set -e

log_level="$(snapctl get log-level)"
if [ -n "$log_level" ]; then
    export AZIOT_LOG="$log_level"
fi

export LD_LIBRARY_PATH="$SNAP/lib/aziot-identity-service${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

exec "$@"
