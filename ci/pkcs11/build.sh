#!/bin/bash

set -euxo pipefail

cd /src


. ./ci/install-build-deps.sh


# Build

make V=1 pkcs11-test
