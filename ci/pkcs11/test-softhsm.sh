#!/bin/bash

set -euxo pipefail

cd /src


. ./ci/install-runtime-deps.sh


# softhsm tests

chmod +x "$PWD/target/debug/pkcs11-test"

TOKEN='Key pairs'
USER_PIN='1234'

LABEL_1='CA'
KEY_1_TYPE="$KEY_TYPE"

LABEL_2='Server'
KEY_2_TYPE="$KEY_TYPE"

LABEL_3='Client'
KEY_3_TYPE="$KEY_TYPE"

SO_PIN="so$USER_PIN"

softhsm2-util --init-token --free --label "$TOKEN" --so-pin "$SO_PIN" --pin "$USER_PIN"

"$PWD/target/debug/pkcs11-test" generate-key-pair \
    --key "pkcs11:token=$TOKEN;object=$LABEL_1?pin-value=$USER_PIN" --type "$KEY_1_TYPE"
"$PWD/target/debug/pkcs11-test" generate-key-pair \
    --key "pkcs11:token=$TOKEN;object=$LABEL_2?pin-value=$USER_PIN" --type "$KEY_2_TYPE"
"$PWD/target/debug/pkcs11-test" generate-key-pair \
    --key "pkcs11:token=$TOKEN;object=$LABEL_3?pin-value=$USER_PIN" --type "$KEY_3_TYPE"

"$PWD/target/debug/pkcs11-test" load \
    --keys "pkcs11:token=$TOKEN;object=$LABEL_1" "pkcs11:token=$TOKEN;object=$LABEL_2" "pkcs11:token=$TOKEN;object=$LABEL_3"

"$PWD/target/debug/pkcs11-test" generate-ca-cert \
    --key "pkcs11:token=$TOKEN;object=$LABEL_1?pin-value=$USER_PIN" \
    --subject 'CA Inc' \
    --out-file "$PWD/ca.pem"
[ -f "$PWD/ca.pem" ]

"$PWD/target/debug/pkcs11-test" generate-server-cert \
    --key "pkcs11:token=$TOKEN;object=$LABEL_2?pin-value=$USER_PIN" \
    --subject 'Server LLC' \
    --ca-cert "$PWD/ca.pem" --ca-key "pkcs11:token=$TOKEN;object=$LABEL_1?pin-value=$USER_PIN" \
    --out-file "$PWD/server.pem"
[ -f "$PWD/server.pem" ]

"$PWD/target/debug/pkcs11-test" generate-client-cert \
    --key "pkcs11:token=$TOKEN;object=$LABEL_3?pin-value=$USER_PIN" \
    --subject 'Client GmbH' \
    --ca-cert "$PWD/ca.pem" --ca-key "pkcs11:token=$TOKEN;object=$LABEL_1?pin-value=$USER_PIN" \
    --out-file "$PWD/client.pem"
[ -f "$PWD/client.pem" ]
