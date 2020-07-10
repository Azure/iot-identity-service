#!/bin/bash

# This script is meant to be sourced.

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
