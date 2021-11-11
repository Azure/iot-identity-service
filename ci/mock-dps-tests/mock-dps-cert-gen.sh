#!/bin/bash

set -euxo pipefail

>mock_dps_certs.conf cat <<-EOF
[ root_cert ]
basicConstraints = critical, CA:TRUE
keyUsage = keyCertSign

[ server_cert ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

# Generate test root CA certificate.
openssl genrsa -out root_cert_key.pem &> /dev/null
openssl req -new -key root_cert_key.pem -subj "/CN=Mock_DPS_Test_Root" -out root_req.pem

openssl x509 -req \
    -in root_req.pem \
    -extfile mock_dps_certs.conf -extensions root_cert \
    -signkey root_cert_key.pem -sha256 \
    -out root_cert.pem &> /dev/null

# Generate test server certificate.
openssl genrsa -out server_cert_key.pem &> /dev/null

# mock-dps-server always uses hostname localhost, so its server certificate must always have CN or SAN localhost.
openssl req -new -key server_cert_key.pem -subj "/CN=localhost" -out server_req.pem

openssl x509 -req \
    -in server_req.pem \
    -extfile mock_dps_certs.conf -extensions server_cert \
    -CAcreateserial -sha256 \
    -CA root_cert.pem -CAkey root_cert_key.pem \
    -out server_cert.pem &> /dev/null

cat server_cert.pem root_cert.pem > server_cert_chain.pem

echo "Generated test root CA certificate:"
echo " - $(pwd)/root_cert.pem"
echo ""
echo "Generated test server certificate:"
echo " - cert chain: $(pwd)/server_cert_chain.pem"
echo " - key: $(pwd)/server_cert_key.pem"
