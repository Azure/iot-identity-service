#!/bin/bash

set -euo pipefail

cd /src

. ./ci/install-build-deps.sh

make V=1 test-release
