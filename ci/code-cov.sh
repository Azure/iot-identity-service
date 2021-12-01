#!/bin/bash

set -euo pipefail


. ./ci/install-build-deps.sh

make codecov
