#!/bin/bash

set -euo pipefail

cd /src
. ./ci/install-runtime-deps.sh
. ./ci/mock-iot-tests/mock-iot-setup.sh

# Create an example custom DPS payload file
payload_file="/etc/aziot/identityd/payload.json"
cp /src/identity/aziot-identityd-config/test/complex_payload.json $payload_file

# Start mock-iot-server and wait for it to come up.
./mock-iot-server --port 8443 --server-cert-chain "$SERVER_CERT_CHAIN" --server-key "$SERVER_KEY" &
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
payload_uri = "file://$payload_file"

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
sleep 10

# Check provisioning info.
result=$(curl -s \
    --unix-socket /run/aziot/identityd.sock \
    "http://localhost/identities/provisioning?api-version=2022-08-01" \
    --fail \
    | jq --sort-keys .)
expected=$(echo '{"source":"dps","auth":"symmetric_key","endpoint":"https://localhost:8443/","scope_id":"scope123","registration_id":"mock-iot-provision","payload":'\
    $(cat $payload_file) '}' | jq --sort-keys .)

if [ "$result" != "$expected" ]; then
    echo ""
    echo "SYMMETRIC KEY PROVISIONING WITH MOCK IoT: FAIL"
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
device_id_response=$(curl -s \
    --unix-socket /run/aziot/identityd.sock \
    "http://localhost/identities/device?api-version=2022-08-01" \
    --data '{"type": "aziot"}' \
    -H "content-type: application/json" \
    --fail \
    | jq .)

auth_type=$(jq .spec.auth.type <<< "$device_id_response")
symkey_device_id=$(jq .spec.deviceId <<< "$device_id_response")

if [ "$auth_type" != '"sas"' ]; then
    echo ""
    echo "SYMMETRIC KEY PROVISIONING WITH MOCK IoT: FAIL"
    echo "Auth type is $auth_type, not 'sas'"
    exit 1
fi

echo ""
echo "SYMMETRIC KEY PROVISIONING WITH MOCK IoT: PASS"
echo ""

# Change to DPS provisioning with X.509 credential.
kill -TERM "$identityd_pid"
wait "$identityd_pid" || :

>/etc/aziot/identityd/config.toml cat<<-EOF
hostname = "$HOSTNAME"
homedir = "/var/lib/aziot/identityd"

[provisioning]
source = "dps"
global_endpoint = "https://localhost:8443/"
scope_id = "scope123"
payload_uri = "file://$payload_file"

[provisioning.attestation]
method = "x509"
registration_id = "mock-iot-provision"
identity_cert = "device-id-cert"
identity_pk = "device-id-certkey"

[[principal]]
uid = $UID
name = "aziot-edged"
EOF

./aziotd aziot-identityd &
identityd_pid="$!"
sleep 5

# Provisioning info has changed, so reprovision.
curl -s --unix-socket /run/aziot/identityd.sock "http://localhost/identities/device/reprovision?api-version=2022-08-01" \
    -H "content-type: application/json" --data '{"type": "aziot"}' &> /dev/null

# Check provisioning info.
result=$(curl -s --unix-socket /run/aziot/identityd.sock "http://localhost/identities/provisioning?api-version=2022-08-01" | jq --sort-keys .)
expected=$(echo '{"source":"dps","auth":"x509","endpoint":"https://localhost:8443/","scope_id":"scope123","registration_id":"mock-iot-provision","payload":'\
    $(cat $payload_file) '}' | jq --sort-keys .)

if [ "$result" != "$expected" ]; then
    echo ""
    echo "X.509 PROVISIONING WITH MOCK IoT: FAIL"
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
device_id_response=$(curl -s \
    --unix-socket /run/aziot/identityd.sock \
    "http://localhost/identities/device?api-version=2022-08-01" \
    --data '{"type": "aziot"}' \
    -H "content-type: application/json" \
    --fail \
    | jq .)

auth_type=$(jq .spec.auth.type <<< "$device_id_response")
x509_device_id=$(jq .spec.deviceId <<< "$device_id_response")

if [ "$auth_type" != '"x509"' ]; then
    echo ""
    echo "X.509 PROVISIONING WITH MOCK IoT: FAIL"
    echo "Auth type is $auth_type, not 'x509'"
    exit 1
fi

if [ "$symkey_device_id" = "$x509_device_id" ]; then
    echo ""
    echo "MOCK IoT REPROVISION: FAIL"
    echo "Device identity did not change."
    echo ""
    exit 1
fi

echo ""
echo "X.509 PROVISIONING WITH MOCK IoT: PASS"
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
