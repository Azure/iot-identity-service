#!/bin/bash

set -eu

# Don't modify trusted certificates if not running on a CI container OS.
case "$CONTAINER_OS" in
    'ubuntu:18.04' | 'debian:10-slim')
        mkdir -p /usr/local/share/ca-certificates
        cp "$ROOT_CERT" /usr/local/share/ca-certificates/dps_root_cert.crt
        update-ca-certificates
        ;;
    'centos:7' | 'redhat/ubi8:latest')
        mkdir -p /etc/pki/ca-trust/source/anchors
        cp "$ROOT_CERT" /etc/pki/ca-trust/source/anchors/dps_root_cert.crt
        update-ca-trust
    ;;
esac
echo "Added mock DPS root certificate to system root store."
