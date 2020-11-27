#!/bin/bash

# This script runs some basic tests against aziot-keyd, optionally with a PKCS#11 library as the backend.
#
# First, ensure the test binary has been built, with `make aziot-key-openssl-engine-shared-test`.
#
# Specify the PKCS#11 library path via the PKCS11_LIB_PATH env var, and the base slot used for dynamic keys
# via the PKCS11_BASE_SLOT env var. If PKCS11_LIB_PATH is not set, aziot-keyd will be configured to use the filesystem backend.
#
# Also set the KEY_TYPE env var to one of "ec-p256", "rsa-2048" and "rsa-4096" to evaluate that kind of asymmetric key pair.
#
# Lastly, ensure that libaziot_key_openssl_engine_shared.so has been installed in the openssl engines directory
# as printed by `openssl version -e` (`/usr/lib64/openssl/engines` for CentOS 7),
# with the name "aziot_keys.so" ("libaziot_keys.so" for CentOS 7).
#
# The web server test requires an open TCP port to bind to. The default is 8443. Set the PORT env var to override it.
#
# Note: Ensure the /run/aziot directory exists and is writable by your user.
# The openssl engine expects aziot-keyd's socket to be in this directory.
#
#
# Example (softhsm):
#
#    rm -rf ~/softhsm; mkdir -p ~/softhsm   # assuming ~/softhsm is the directories.tokendir configured in softhsm2.conf
#
#    TOKEN='Key pairs'
#    USER_PIN='1234'
#    softhsm2-util --init-token --free --label "$TOKEN" --so-pin "so$USER_PIN" --pin "$USER_PIN"
#
#    export PKCS11_LIB_PATH='/usr/lib64/softhsm/libsofthsm.so'
#    export PKCS11_BASE_SLOT="pkcs11:token=$TOKEN?pin-value=$USER_PIN"
#    export KEY_TYPE='ec-p256'
#    ./key/test-aziot-key-openssl-engine-shared.sh


set -euxo pipefail


# Find the build output directory / the directory where CI extracted the artifact
#
# For a local build, this would be target/x86_64-unknown-linux-gnu/debug.
# For CI, this would be target/debug
cd "$(find target -type f -name aziot-key-openssl-engine-shared-test | head -n 1 | xargs dirname)"


# Set constants and LD_LIBRARY_PATH (to be able to load libaziot_keys.so from the same directory)

export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}:$PWD"


# Configure aziot-keyd and spawn it in the background

# Assert /run/aziot exists and is writable
mkdir -p /run/aziot
touch /run/aziot/keyd.sock
rm -f /run/aziot/keyd.sock

>./keyd.toml printf "\
[aziot_keys]
homedir_path = \"%s\"
" "$PWD"

if [ -n "${PKCS11_LIB_PATH:-}" ]; then
>>./keyd.toml printf "\
pkcs11_lib_path = \"%s\"
pkcs11_base_slot = \"%s\"
" "$PKCS11_LIB_PATH" "$PKCS11_BASE_SLOT"
fi

rm -rf keys
AZIOT_KEYD_CONFIG="$PWD/keyd.toml" ./aziotd aziot-keyd &
keyd_pid="$!"


# Wait for aziot-keyd to come up.
sleep 1


# Create CA key and cert.

ca_key_handle="$(
    curl --unix-socket /run/aziot/keyd.sock \
        -X POST -H 'content-type: application/json' --data-binary "{ \"keyId\": \"ca\", \"preferredAlgorithms\": \"$KEY_TYPE\" }" \
        'http://foo/keypair?api-version=2020-09-01' |
    jq -er '.keyHandle'
)"
echo "CA key: $ca_key_handle"

./aziot-key-openssl-engine-shared-test generate-ca-cert \
    --key-handle "$ca_key_handle" \
    --subject 'CA Inc' \
    --out-file "$PWD/ca.pem"
[ -f "$PWD/ca.pem" ]


# Create server key and cert.

server_key_handle="$(
    curl --unix-socket /run/aziot/keyd.sock \
        -X POST -H 'content-type: application/json' --data-binary "{ \"keyId\": \"server\", \"preferredAlgorithms\": \"$KEY_TYPE\" }" \
        'http://foo/keypair?api-version=2020-09-01' |
    jq -er '.keyHandle'
)"
echo "Server key: $server_key_handle"

./aziot-key-openssl-engine-shared-test generate-server-cert \
    --key-handle "$server_key_handle" \
    --subject 'Server LLC' \
    --ca-cert "$PWD/ca.pem" --ca-key-handle "$ca_key_handle" \
    --out-file "$PWD/server.pem"
[ -f "$PWD/server.pem" ]


# Create client key and cert.

client_key_handle="$(
    curl --unix-socket /run/aziot/keyd.sock \
        -X POST -H 'content-type: application/json' --data-binary "{ \"keyId\": \"client\", \"preferredAlgorithms\": \"$KEY_TYPE\" }" \
        'http://foo/keypair?api-version=2020-09-01' |
    jq -er '.keyHandle'
)"
echo "Client key: $client_key_handle"

./aziot-key-openssl-engine-shared-test generate-client-cert \
    --key-handle "$client_key_handle" \
    --subject 'Client GmbH' \
    --ca-cert "$PWD/ca.pem" --ca-key-handle "$ca_key_handle" \
    --out-file "$PWD/client.pem"
[ -f "$PWD/client.pem" ]


# Verify keys were created using PKCS#11 or not, depending on whether PKCS11_LIB_PATH is set or not.
num_keys="$(find keys/ -type f | wc -l)"
if [ -n "${PKCS11_LIB_PATH:-}" ]; then
    # Only master encryption key should have been created.
    if (( num_keys != 1 )); then
        echo "Expected to find 1 key under keys/ but found $num_keys" >&2
        ls -l keys/
        exit 1
    fi
else
    # Master encryption key and the three keys above should have been created.
    if (( num_keys != 4 )); then
        echo "Expected to find 4 keys under keys/ but found $num_keys" >&2
        ls -l keys/
        exit 1
    fi
fi


# Start the webserver

./aziot-key-openssl-engine-shared-test web-server \
    --cert "$PWD/server.pem" \
    --key-handle "$server_key_handle" \
    --port "${PORT:-8443}" &
server_pid="$!"
# Wait for the server to come up.
sleep 1


# Connect with `openssl s_client` and print the server cert.
</dev/null openssl s_client \
    -connect "127.0.0.1:${PORT:-8443}" \
    -CAfile "$PWD/ca.pem" \
    -showcerts


# Connect with `curl` and print the response.
OS="$(. /etc/os-release; echo "$ID:$VERSION_ID")"
case "$OS" in
    'centos:7'|'debian:9')
        # CentOS 7's curl doesn't support openssl engines.
        #
        # Debian 9 has openssl 1.1, so that is what the openssl engine compiles gainst.
        # But its curl links to openssl 1.0.2, so it can't use the engine.
        #
        # For these distros, skip the curl check.
        ;;

    *)
        curl \
            -D /dev/stderr \
            --cacert "$PWD/ca.pem" \
            --cert "$PWD/client.pem" \
            --engine 'aziot_keys' --key-type 'ENG' --key "$client_key_handle" \
            "https://127.0.0.1:${PORT:-8443}"
        ;;
esac


# Clean up

kill -TERM "$server_pid"
wait "$server_pid" || :

kill -TERM "$keyd_pid"
wait "$keyd_pid" || :
