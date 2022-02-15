#!/bin/bash

set -euo pipefail

cd /src
. ./ci/install-runtime-deps.sh
. ./ci/mock-iot-tests/mock-iot-setup.sh

# Start mock-iot-server with server certificates and wait for it to come up.
./mock-iot-server --port 8443 \
    --server-cert-chain "$SERVER_CERT_CHAIN" --server-key "$SERVER_KEY" \
    --enable-identity-certs \
    --enable-server-certs &
server_pid="$!"
sleep 1

# Set up for DPS provisioning with symmetric key.
>/etc/aziot/identityd/config.toml cat<<-EOF
hostname = "$HOSTNAME"
homedir = "/var/lib/aziot/identityd"

[provisioning]
source = "dps"
global_endpoint = "https://localhost:8443/"
scope_id = "scope123"

[provisioning.attestation]
method = "symmetric_key"
registration_id = "mock-iot-provision"
symmetric_key = "device-id-symkey"

[[principal]]
uid = $UID
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
sleep 20

# Query for server certificate issuance policy.
cert_type=$(curl -s \
    --unix-socket /run/aziot/identityd.sock \
    "http://localhost/identities/provisioning?api-version=2021-12-01" \
    --fail \
    | jq -r .cert_policy.certificateType)

if [ "$cert_type" != "serverCertificate" ]; then
    echo ""
    echo "SERVER CERTIFICATE ISSUANCE TYPE: FAIL"
    echo "Certificate issuance type is $cert_type, not 'serverCertificate'"
    exit 1
fi

# Ensure that certificate issuance policies are retained across restarts.
kill -TERM "$identityd_pid"
wait "$identityd_pid" || :

./aziotd aziot-identityd &
identityd_pid="$!"
sleep 5

cert_type=$(curl -s \
    --unix-socket /run/aziot/identityd.sock \
    "http://localhost/identities/provisioning?api-version=2021-12-01" \
    --fail \
    | jq -r .cert_policy.certificateType)

if [ "$cert_type" != "serverCertificate" ]; then
    echo ""
    echo "SERVER CERTIFICATE ISSUANCE TYPE: FAIL"
    echo "Certificate issuance type changed to $cert_type when restarted"
    exit 1
fi

echo ""
echo "SERVER CERTIFICATE ISSUANCE TYPE: PASS"
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
