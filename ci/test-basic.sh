#!/bin/bash

set -euxo pipefail

cd /src

. ./ci/install-test-deps.sh

if [ "$SKIP_TSS_MINIMAL" = 0 ]; then
    libpath=/usr/local/lib
    if [ "$USE_SWTPM_PKG" = 1 ]; then
        libpath=
    fi

    TPM_STATE="$(mktemp -d)"
    LD_LIBRARY_PATH=$libpath swtpm socket \
        --tpm2 \
        --tpmstate dir="$TPM_STATE" \
        --port 2321 \
        --ctrl type=tcp,port=2322 \
        --flags not-need-init,startup-clear &
    SWTPM_PID=$!
    trap "kill '$SWTPM_PID'; rm -rf '$TPM_STATE';" EXIT
fi

make SKIP_TSS_MINIMAL="$SKIP_TSS_MINIMAL" VENDOR_LIBTSS="${VENDOR_LIBTSS:-0}" V=1 test-release
