#!/bin/bash

set -euo pipefail

cd /src

. ./ci/install-test-deps.sh

if [ "$SKIP_TSS_MINIMAL" = 0 ]; then
    TPM_STATE="$(mktemp -d)"
    LD_LIBRARY_PATH=/usr/local/lib swtpm socket \
        --tpm2 \
        --tpmstate dir="$TPM_STATE" \
        --port 2321 \
        --ctrl type=tcp,port=2322 \
        --flags not-need-init,startup-clear &
    SWTPM_PID=$!
    trap "kill '$SWTPM_PID'; rm -rf '$TPM_STATE';" EXIT
fi

make SKIP_TSS_MINIMAL="$SKIP_TSS_MINIMAL" V=1 test-release
