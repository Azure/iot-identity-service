#!/bin/sh

set -e

log_level="$(snapctl get log-level)"
if [ -n "$log_level" ]; then
    export AZIOT_LOG="$log_level"
fi

exec "$@"
