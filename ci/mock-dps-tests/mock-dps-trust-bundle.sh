#!/bin/bash

cd /src
. ./ci/install-runtime-deps.sh
. ./ci/mock-dps-tests/mock-dps-setup.sh

set -euo pipefail
