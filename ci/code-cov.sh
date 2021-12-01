#!/bin/bash

set -euo pipefail

cd /src

. ./ci/install-build-deps.sh

make codecov
