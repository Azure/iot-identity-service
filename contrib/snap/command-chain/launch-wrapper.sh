#!/bin/sh

set -e

echo "Making /run/aziot if it does not exist"
mkdir -p /run/aziot
echo "Successfully made /run/aziot if it did not exist"

log_level="$(snapctl get log-level)"
if [ -n "$log_level" ]; then
    export AZIOT_LOG="$log_level"
fi

exec "$@"
