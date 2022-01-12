#!/bin/bash

set -euo pipefail

cd /src
. ./ci/install-runtime-deps.sh
. ./ci/mock-iot-tests/mock-iot-setup.sh

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

# Start mock-iot-server with identity certificates and wait for it to come up.
./mock-iot-server --port 8443 \
    --server-cert-chain "$SERVER_CERT_CHAIN" --server-key "$SERVER_KEY" \
    --enable-identity-certs &
server_pid="$!"
sleep 1

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

# Query and parse identity certificate.
curl -s \
    --unix-socket /run/aziot/certd.sock \
    "http://localhost/certificates/aziot-dps-identity-cert?api-version=2020-09-01" \
    --fail \
    | jq -r .pem > identity_cert.pem
openssl x509 -in identity_cert.pem -noout

# Query device provisioning information. The DPS-provided identity certificate should
# override the SAS key specified in the config.
device_id_response=$(curl -s \
    --unix-socket /run/aziot/identityd.sock \
    "http://localhost/identities/device?api-version=2021-12-01" \
    --data '{"type": "aziot"}' \
    -H "content-type: application/json" \
    --fail \
    | jq .)
auth_type=$(jq .spec.auth.type <<< "$device_id_response")

if [ "$auth_type" != '"x509"' ]; then
    echo ""
    echo "MOCK DPS PROVISION WITH DPS IDENTITY CERT: FAIL"
    echo "Auth type is $auth_type, not 'x509'"
    exit 1
fi

echo ""
echo "MOCK DPS PROVISION WITH DPS IDENTITY CERT: PASS"
echo ""

# Restart mock-iot-server without identity certificates.
kill -TERM "$server_pid"
wait "$server_pid" || :

./mock-iot-server --port 8443 \
    --server-cert-chain "$SERVER_CERT_CHAIN" --server-key "$SERVER_KEY" &
server_pid="$!"
sleep 1

# Reprovision and check that the identity certificate was deleted.
curl -s --unix-socket /run/aziot/identityd.sock "http://localhost/identities/device/reprovision?api-version=2021-12-01" \
    -H "content-type: application/json" --data '{"type": "aziot"}' &> /dev/null

message=$(curl -s --unix-socket /run/aziot/certd.sock "http://localhost/certificates/aziot-dps-identity-cert?api-version=2020-09-01" | jq -r .message)

# Use 'echo' to normalize whitespace before string compare.
# shellcheck disable=2086,2116
if [ "$(echo $message)" != 'parameter "id" has an invalid value caused by: not found' ]; then
    echo ""
    echo "MOCK DPS REPROVISION WITH DPS IDENTITY CERT: FAIL"
    echo "Out-of-date identity certificate was not deleted."
    echo ""
    exit 1
fi

# Check that the device identity has changed back to SAS.
device_id_response=$(curl -s \
    --unix-socket /run/aziot/identityd.sock \
    "http://localhost/identities/device?api-version=2021-12-01" \
    --data '{"type": "aziot"}' \
    -H "content-type: application/json" \
    --fail \
    | jq .)
auth_type=$(jq .spec.auth.type <<< "$device_id_response")

if [ "$auth_type" != '"sas"' ]; then
    echo ""
    echo "MOCK DPS REPROVISION WITH DPS IDENTITY CERT: FAIL"
    echo "Reprovisioning did not reset device identity type."
    exit 1
fi

echo ""
echo "MOCK DPS REPROVISION WITH DPS IDENTITY CERT: PASS"
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
