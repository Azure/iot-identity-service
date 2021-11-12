#!/bin/bash

cd /src
. ./ci/install-runtime-deps.sh
. ./ci/mock-dps-tests/mock-dps-root-install.sh

set -euo pipefail

# Find the build output directory / the directory where CI extracted the artifact.
#
# For a local build, this would be target/x86_64-unknown-linux-gnu/debug.
# For CI, this would be target/debug.
cd "$(find target -type f -name mock-dps-server | head -n 1 | xargs dirname)"
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}:$PWD"

chmod +x ./aziotd
chmod +x ./mock-dps-server

# Create directories needed for the tests.
mkdir -p /run/aziot
mkdir -p /etc/aziot/keyd/
mkdir -p /var/lib/aziot/keyd
mkdir -p /etc/aziot/certd
mkdir -p /var/lib/aziot/certd
mkdir -p /etc/aziot/identityd
mkdir -p /var/lib/aziot/identityd

uid=$(id -u)

# Start mock-dps-server and wait for it to come up.
./mock-dps-server --port 8443 --server-cert-chain "$SERVER_CERT_CHAIN" --server-key "$SERVER_KEY" &
server_pid="$!"
sleep 1

# mock-dps-server does not authenticate, so tests can use any arbitrary credentials.
echo 'mock-dps-provision' | base64 > device_id_symkey

touch ~/.rnd
>device_id_cert.conf cat <<-EOF
[ device_id_cert ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection
EOF

openssl genrsa -out device_id_certkey.pem
openssl req -new -key device_id_certkey.pem -subj "/CN=mock-dps-provision" -out device_id_certreq.pem

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
uid = $uid
keys = ["*"]
EOF

>/etc/aziot/certd/config.toml cat<<-EOF
homedir_path = "/var/lib/aziot/certd"

[preloaded_certs]
device-id-cert = "file://$PWD/device_id_cert.pem"

[[principal]]
uid = $uid
certs = ["*"]
EOF

# Set up for DPS provisioning with symmetric key.
>/etc/aziot/identityd/config.toml cat<<-EOF
hostname = "$(hostname)"
homedir = "/var/lib/aziot/identityd"

[provisioning]
source = "dps"
global_endpoint = "https://localhost:8443/"
scope_id = "scope123"

[provisioning.attestation]
method = "symmetric_key"
registration_id = "mock-dps-provision"
symmetric_key = "device-id-symkey"

[[principal]]
uid = $uid
name = "aziot-edged"
EOF

# Start services and wait for them to come up.
./aziotd aziot-keyd &
keyd_pid="$!"
sleep 1

./aziotd aziot-certd &
certd_pid="$!"
sleep 1

./aziotd aziot-identityd &
identityd_pid="$!"
sleep 5

# Check provisioning info.
result=$(curl -s \
    --unix-socket /run/aziot/identityd.sock \
    "http://localhost/identities/provisioning?api-version=2021-12-01" \
    --fail \
    | jq .)
expected=$(jq . <<< '{"source":"dps","auth":"symmetric_key","endpoint":"https://localhost:8443/","scope_id":"scope123","registration_id":"mock-dps-provision"}')

if [ "$result" != "$expected" ]; then
    echo ""
    echo "SYMMETRIC KEY PROVISIONING WITH MOCK DPS: FAIL"
    echo ""
    echo "Symmetric key provisioning information does not match."
    echo ""
    echo "Expected: $expected"
    echo ""
    echo "Got: $result"
    echo ""
    exit 1
fi

# Get device identity.
symkey_device_id=$(curl -s \
    --unix-socket /run/aziot/identityd.sock \
    "http://localhost/identities/device?api-version=2021-12-01" \
    --data '{"type": "aziot"}' \
    -H "content-type: application/json" \
    --fail \
    | jq .)

echo ""
echo "SYMMETRIC KEY PROVISIONING WITH MOCK DPS: PASS"
echo ""

# Change to DPS provisioning with X.509 credential.
kill -TERM "$identityd_pid"
wait "$identityd_pid" || :

>/etc/aziot/identityd/config.toml cat<<-EOF
hostname = "$(hostname)"
homedir = "/var/lib/aziot/identityd"

[provisioning]
source = "dps"
global_endpoint = "https://localhost:8443/"
scope_id = "scope123"

[provisioning.attestation]
method = "x509"
registration_id = "mock-dps-provision"
identity_cert = "device-id-cert"
identity_pk = "device-id-certkey"

[[principal]]
uid = $uid
name = "aziot-edged"
EOF

./aziotd aziot-identityd &
identityd_pid="$!"
sleep 5

# Check provisioning info.
result=$(curl -s --unix-socket /run/aziot/identityd.sock "http://localhost/identities/provisioning?api-version=2021-12-01" | jq .)
expected=$(jq . <<< '{"source":"dps","auth":"x509","endpoint":"https://localhost:8443/","scope_id":"scope123","registration_id":"mock-dps-provision"}')

if [ "$result" != "$expected" ]; then
    echo ""
    echo "X.509 PROVISIONING WITH MOCK DPS: FAIL"
    echo ""
    echo "X.509 provisioning information does not match."
    echo ""
    echo "Expected: $expected"
    echo ""
    echo "Got: $result"
    echo ""
    exit 1
fi

# Get device identity. Check that it changed with the reprovision.
x509_device_id=$(curl -s \
    --unix-socket /run/aziot/identityd.sock \
    "http://localhost/identities/device?api-version=2021-12-01" \
    --data '{"type": "aziot"}' \
    -H "content-type: application/json" \
    --fail \
    | jq .)

if [ "$symkey_device_id" = "$x509_device_id" ]; then
    echo ""
    echo "MOCK DPS REPROVISION: FAIL"
    echo "Device identity did not change."
    echo ""
    exit 1
fi

echo ""
echo "X.509 PROVISIONING WITH MOCK DPS: PASS"
echo ""

# Clean up.
kill -TERM "$identityd_pid"
wait "$identityd_pid" || :

kill -TERM "$certd_pid"
wait "$certd_pid" || :

kill -TERM "$keyd_pid"
wait "$keyd_pid" || :

kill -TERM "$server_pid"
wait "$server_pid" || :
