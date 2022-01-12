#!/bin/bash

set -euo pipefail

cd /src
. ./ci/install-runtime-deps.sh
. ./ci/mock-iot-tests/mock-iot-setup.sh

# Generate 2 certificates for trust bundle.
mkdir -p trust_bundle

>trust_bundle_cert.conf cat <<-EOF
[ trust_bundle_cert ]
basicConstraints = critical, CA:TRUE
keyUsage = keyCertSign
EOF

openssl genrsa -out trustbundle1_key.pem &> /dev/null
openssl req -new -key trustbundle1_key.pem -subj "/CN=Trust_Bundle_Cert_1" -out trustbundle1_req.pem

openssl x509 -req \
    -in trustbundle1_req.pem \
    -extfile trust_bundle_cert.conf -extensions trust_bundle_cert \
    -signkey trustbundle1_key.pem -sha256 \
    -out trust_bundle/cert1.pem &> /dev/null

openssl genrsa -out trustbundle2_key.pem &> /dev/null
openssl req -new -key trustbundle2_key.pem -subj "/CN=Trust_Bundle_Cert_2" -out trustbundle2_req.pem

openssl x509 -req \
    -in trustbundle2_req.pem \
    -extfile trust_bundle_cert.conf -extensions trust_bundle_cert \
    -signkey trustbundle2_key.pem -sha256 \
    -out trust_bundle/cert2.pem &> /dev/null

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

# Start mock-iot-server with the specified trust bundle and wait for it to come up.
./mock-iot-server --port 8443 \
    --server-cert-chain "$SERVER_CERT_CHAIN" --server-key "$SERVER_KEY" \
    --trust-bundle-certs-dir trust_bundle &
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

# Query and parse trust bundle.
curl -s \
    --unix-socket /run/aziot/certd.sock \
    "http://localhost/certificates/aziot-dps-trust-bundle?api-version=2020-09-01" \
    --fail \
    | jq -r .pem > certs.pem
openssl crl2pkcs7 -nocrl -certfile certs.pem | openssl pkcs7 -print_certs -noout

echo ""
echo "GET TRUST BUNDLE WITH MOCK DPS: PASS"
echo ""

# Restart mock-iot-server without a trust bundle.
kill -TERM "$server_pid"
wait "$server_pid" || :

./mock-iot-server --port 8443 \
    --server-cert-chain "$SERVER_CERT_CHAIN" --server-key "$SERVER_KEY" &
server_pid="$!"
sleep 1

# Reprovision and check that the trust bundle was deleted.
curl -s --unix-socket /run/aziot/identityd.sock "http://localhost/identities/device/reprovision?api-version=2021-12-01" \
    -H "content-type: application/json" --data '{"type": "aziot"}' &> /dev/null

message=$(curl -s --unix-socket /run/aziot/certd.sock "http://localhost/certificates/aziot-dps-trust-bundle?api-version=2020-09-01" | jq -r .message)

# Use 'echo' to normalize whitespace before string compare.
# shellcheck disable=2086,2116
if [ "$(echo $message)" != 'parameter "id" has an invalid value caused by: not found' ]; then
    echo ""
    echo "TRUST BUNDLE REPROVISION WITH MOCK DPS: FAIL"
    echo "Out-of-date trust bundle was not deleted."
    echo ""
    exit 1
fi

echo ""
echo "TRUST BUNDLE REPROVISION WITH MOCK DPS: PASS"
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
