#!/bin/bash

set -euxo pipefail


# Install deps

case "$CONTAINER_OS" in
    'centos:7')
        case "$OPENSSL_VERSION" in
            '1.0')
                OPENSSL_PACKAGE_NAME='openssl-libs'
                ;;
            *)
                exit 1
                ;;
        esac

        yum install -y softhsm "$OPENSSL_PACKAGE_NAME"

        export PKCS11_LIB_PATH='/usr/lib64/libsofthsm2.so'

        mkdir -p /var/lib/softhsm/tokens
        ;;

    'debian:9-slim')
        case "$OPENSSL_VERSION" in
            '1.0')
                OPENSSL_PACKAGE_NAME='libssl1.0.2'
                ;;
            '1.1.0')
                OPENSSL_PACKAGE_NAME='libssl1.1'
                ;;
            *)
                exit 1
                ;;
        esac

        apt-get update
        apt-get install -y softhsm "$OPENSSL_PACKAGE_NAME"

        export PKCS11_LIB_PATH='/usr/lib/softhsm/libsofthsm2.so'

        mkdir -p /var/lib/softhsm/tokens
        ;;

    'debian:10-slim')
        case "$OPENSSL_VERSION" in
            '1.1.1')
                OPENSSL_PACKAGE_NAME='libssl1.1'
                ;;
            *)
                exit 1
                ;;
        esac

        apt-get update
        apt-get install -y softhsm "$OPENSSL_PACKAGE_NAME"

        export PKCS11_LIB_PATH='/usr/lib/softhsm/libsofthsm2.so'

        mkdir -p /var/lib/softhsm/tokens
        ;;

    *)
        exit 1
esac


cd /src


chmod +x "$PWD/target/debug/pkcs11-test"


# softhsm tests

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
