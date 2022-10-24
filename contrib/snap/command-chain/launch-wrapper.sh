#!/bin/sh

set -e

echo "Making /run/aziot if it does not exist"
mkdir -p /run/aziot
echo "Successfully made /run/aziot if it did not exist"

exec "$@"
