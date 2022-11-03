#!/bin/bash

set -euxo pipefail

cd /src

. ./ci/install-runtime-deps.sh

case "$OS" in
    'centos:7')
        cp \
            ./target/debug/libaziot_key_openssl_engine_shared.so \
            /usr/lib64/openssl/engines/libaziot_keys.so
        ;;

    'debian:10'|'debian:11'|'platform:el8'|'platform:el9'|'ubuntu:18.04'|'ubuntu:20.04'|'ubuntu:22.04')
        cp \
            ./target/debug/libaziot_key_openssl_engine_shared.so \
            "$(openssl version -e | sed -E 's/^ENGINESDIR: "(.*)"$/\1/')/aziot_keys.so"
        ;;

    *)
        echo "Unsupported OS $OS." >&2
        exit 1
        ;;
esac

chmod +x ./target/debug/aziotd
chmod +x ./target/debug/aziot-key-openssl-engine-shared-test

case "${PKCS11_BACKEND:-}" in
    'softhsm')
        TOKEN='Key pairs'
        USER_PIN='1234'
        softhsm2-util --init-token --free --label "$TOKEN" --so-pin "so$USER_PIN" --pin "$USER_PIN"
        export PKCS11_BASE_SLOT="pkcs11:token=$TOKEN?pin-value=$USER_PIN"
        ;;

    '')
        ;;

    *)
        echo "Unsupported PKCS#11 backend $PKCS11_BACKEND" >&2
        exit 1
        ;;
esac

./key/test-aziot-key-openssl-engine-shared.sh
