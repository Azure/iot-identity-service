#!/bin/bash

# This script is meant to be sourced.


OS="$(. /etc/os-release; echo "${PLATFORM_ID:-$ID:$VERSION_ID}")"

case "$OS" in
    'platform:el8'|'platform:el9')
        # If using RHEL 8/9 UBI images without a subscription then they only have access to a
        # subset of packages. Workaround to enable EPEL.
        if [ "$OS" = 'platform:el8' ] && [ "$(. /etc/os-release; echo "$ID")" = 'rhel' ]; then
            yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
            yum install -y curl jq openssl ca-certificates
        elif [ "$OS" = 'platform:el9' ] && [ "$(. /etc/os-release; echo "$ID")" = 'rhel' ]; then
            yum config-manager --add-repo http://repo.almalinux.org/almalinux/9/AppStream/x86_64/os/
            rpm --import http://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-9

            # curl is already installed on el9
            yum install -y jq openssl ca-certificates
        else
            yum install -y epel-release
            yum install -y curl jq openssl ca-certificates
        fi

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

    'debian:11'|'ubuntu:20.04'|'ubuntu:22.04')
        # openssl 1.1.1 for Debian 11, Ubuntu 20.04, RHEL 8
        # openssl 3.0 for Ubuntu 22.04, RHEL 9

        apt-get update -y
        DEBIAN_FRONTEND=noninteractive TZ=UTC apt-get install -y curl jq openssl ca-certificates libtss2-dev

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
