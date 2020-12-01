#!/bin/bash

# This script is meant to be sourced.


OS="$(. /etc/os-release; echo "$ID:$VERSION_ID")"


case "$OS" in
    'centos:7')
        # openssl 1.0

        yum install -y epel-release
        yum install -y curl jq openssl

        case "${PKCS11_BACKEND:-}" in
            'softhsm')
                yum install -y softhsm

                export PKCS11_LIB_PATH='/usr/lib64/libsofthsm2.so'

                mkdir -p /var/lib/softhsm/tokens
                ;;

            '')
                ;;

            *)
                echo "Unsupported PKCS#11 backend $PKCS11_BACKEND" >&2
                exit 1
                ;;
        esac
        ;;

    'debian:9'|'debian:10'|'ubuntu:18.04'|'ubuntu:20.04')
        # openssl 1.1.0 for Debian 9, 1.1.1 for the others

        apt-get update -y
        DEBIAN_FRONTEND=noninteractive TZ=UTC apt-get install -y curl jq openssl

        case "${PKCS11_BACKEND:-}" in
            'softhsm')
                DEBIAN_FRONTEND=noninteractive TZ=UTC apt-get install -y softhsm

                export PKCS11_LIB_PATH='/usr/lib/softhsm/libsofthsm2.so'

                mkdir -p /var/lib/softhsm/tokens
                ;;

            '')
                ;;

            *)
                echo "Unsupported PKCS#11 backend $PKCS11_BACKEND" >&2
                exit 1
                ;;
        esac
        ;;

    *)
        echo "Unsupported OS $OS" >&2
        exit 1
        ;;
esac
