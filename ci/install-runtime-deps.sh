#!/bin/bash

# This script is meant to be sourced.


OS="$(. /etc/os-release; echo "${PLATFORM_ID:-$ID:$VERSION_ID}")"

case "$OS" in
    'centos:7'|'platform:el8')
        # openssl 1.0

        if [ "$OS" = 'platform:el8' ] && [ "$(. /etc/os-release; echo "$ID")" = 'rhel' ]; then
            # If using RHEL 8 UBI images without a subscription then they only have access to a
            # subset of packages. Workaround to enable EPEL.
            yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
        else
            yum install -y epel-release
        fi

        yum install -y curl jq openssl ca-certificates

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

    'debian:10'|'debian:11'|'ubuntu:18.04'|'ubuntu:20.04'|'ubuntu:22.04')
        # openssl 1.1.1 for Debian 10/11 and Ubuntu 18.04/20.04
	# openssl 3.0 for Ubuntu 22.04

        apt-get update -y
        DEBIAN_FRONTEND=noninteractive TZ=UTC apt-get install -y curl jq openssl ca-certificates

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
