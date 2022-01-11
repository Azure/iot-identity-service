#!/bin/bash

set -eu

# Install mock-iot-server's root CA certificate.
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

# Find the build output directory / the directory where CI extracted the artifact.
#
# For a local build, this would be target/x86_64-unknown-linux-gnu/debug.
# For CI, this would be target/debug.
cd "$(find target -type f -name mock-iot-server | head -n 1 | xargs dirname)"
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}:$PWD"

chmod +x ./aziotd
chmod +x ./mock-iot-server

# Create directories needed for the tests.
mkdir -p /run/aziot
mkdir -p /etc/aziot/keyd/
mkdir -p /var/lib/aziot/keyd
mkdir -p /etc/aziot/certd
mkdir -p /var/lib/aziot/certd
mkdir -p /etc/aziot/identityd
mkdir -p /var/lib/aziot/identityd

# Generate test credentials.
# mock-iot-server does not authenticate, so tests can use any arbitrary credentials.
echo 'mock-iot-provision' | base64 > device_id_symkey

touch ~/.rnd
>device_id_cert.conf cat <<-EOF
[ device_id_cert ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
EOF

openssl genrsa -out device_id_certkey.pem
openssl req -new -key device_id_certkey.pem -subj "/CN=mock-iot-provision" -out device_id_certreq.pem

openssl x509 -req \
    -in device_id_certreq.pem \
    -extfile device_id_cert.conf -extensions device_id_cert \
    -signkey device_id_certkey.pem -sha256 \
    -out device_id_cert.pem

>/etc/aziot/keyd/config.toml cat <<-EOF
[aziot_keys]
homedir_path = "/var/lib/aziot/keyd"

[preloaded_keys]
device-id-symkey = "file://$PWD/device_id_symkey"
device-id-certkey = "file://$PWD/device_id_certkey.pem"

[[principal]]
uid = $UID
keys = ["*"]
EOF

>/etc/aziot/certd/config.toml cat<<-EOF
homedir_path = "/var/lib/aziot/certd"

[preloaded_certs]
device-id-cert = "file://$PWD/device_id_cert.pem"

[[principal]]
uid = $UID
certs = ["*"]
EOF
