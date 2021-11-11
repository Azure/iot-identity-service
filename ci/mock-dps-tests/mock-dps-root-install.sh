#!/bin/bash

set -e

# Don't modify trusted certificates if not running on a CI container OS.
if [ -n "$CONTAINER_OS" ]; then
    case "$CONTAINER_OS" in
        'ubuntu:18.04' | 'debian:10-slim')
            cp root_cert.pem /usr/local/share/ca-certificates/dps_root_cert.crt
            update-ca-certificates
            ;;
        'centos:7' | 'redhat/ubi8:latest')
            cp root_cert.pem /etc/pki/ca-trust/source/anchors/dps_root_cert.crt
            update-ca-trust
        ;;
    esac
    echo "Added mock DPS root certificate to system root store"
else
    echo "CONTAINER_OS env var empty. Skipping install of test DPS root server."
fi
