#!/bin/bash

set -euxo pipefail

cd /src


. ./ci/install-runtime-deps.sh


# softhsm tests

case "$ARCH" in
    'amd64')
        PKCS11_TEST_PATH="$PWD/target/x86_64-unknown-linux-gnu/debug/pkcs11-test"
        ;;
    'arm32v7')
        PKCS11_TEST_PATH="$PWD/target/armv7-unknown-linux-gnueabihf/debug/pkcs11-test"
        ;;
    'aarch64')
        PKCS11_TEST_PATH="$PWD/target/aarch64-unknown-linux-gnu/debug/pkcs11-test"
        ;;
esac

chmod +x "$PKCS11_TEST_PATH"

TOKEN='Key pairs'
USER_PIN='1234'

LABEL_1='CA'
# shellcheck disable=SC2153
KEY_1_TYPE="$KEY_TYPE"

LABEL_2='Server'
KEY_2_TYPE="$KEY_TYPE"

LABEL_3='Client'
KEY_3_TYPE="$KEY_TYPE"

SO_PIN="so$USER_PIN"

softhsm2-util --init-token --free --label "$TOKEN" --so-pin "$SO_PIN" --pin "$USER_PIN"

"$PKCS11_TEST_PATH" generate-key-pair \
    --key "pkcs11:token=$TOKEN;object=$LABEL_1?pin-value=$USER_PIN" --type "$KEY_1_TYPE"
"$PKCS11_TEST_PATH" generate-key-pair \
    --key "pkcs11:token=$TOKEN;object=$LABEL_2?pin-value=$USER_PIN" --type "$KEY_2_TYPE"
"$PKCS11_TEST_PATH" generate-key-pair \
    --key "pkcs11:token=$TOKEN;object=$LABEL_3?pin-value=$USER_PIN" --type "$KEY_3_TYPE"

"$PKCS11_TEST_PATH" load \
    --keys "pkcs11:token=$TOKEN;object=$LABEL_1" "pkcs11:token=$TOKEN;object=$LABEL_2" "pkcs11:token=$TOKEN;object=$LABEL_3"

"$PKCS11_TEST_PATH" generate-ca-cert \
    --key "pkcs11:token=$TOKEN;object=$LABEL_1?pin-value=$USER_PIN" \
    --subject 'CA Inc' \
    --out-file "$PWD/ca.pem"
[ -f "$PWD/ca.pem" ]

"$PKCS11_TEST_PATH" generate-server-cert \
    --key "pkcs11:token=$TOKEN;object=$LABEL_2?pin-value=$USER_PIN" \
    --subject 'Server LLC' \
    --ca-cert "$PWD/ca.pem" --ca-key "pkcs11:token=$TOKEN;object=$LABEL_1?pin-value=$USER_PIN" \
    --out-file "$PWD/server.pem"
[ -f "$PWD/server.pem" ]

"$PKCS11_TEST_PATH" generate-client-cert \
    --key "pkcs11:token=$TOKEN;object=$LABEL_3?pin-value=$USER_PIN" \
    --subject 'Client GmbH' \
    --ca-cert "$PWD/ca.pem" --ca-key "pkcs11:token=$TOKEN;object=$LABEL_1?pin-value=$USER_PIN" \
    --out-file "$PWD/client.pem"
[ -f "$PWD/client.pem" ]
