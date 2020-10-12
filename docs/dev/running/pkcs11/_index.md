# Setting up your PKCS#11 library

Follow the column corresponding to your hardware:

- `softhsm2`: A software-emulated HSM. Requires no hardware.
- `cryptoauthlib`: A library for Microchip devices like the ATECC608A.
- `tpm2-pkcs11`: A library for all TPM 2.0 devices.

<table>
<thead>
<tr>
<th><code>softhsm2</code></th>
<th><code>cryptoauthlib</code></th>
<th><code>tpm2-pkcs11</code></th>
</tr>
</thead>
<tbody>
<tr>
<td><a href="softhsm2.md">Install and configure</a></td>
<td><a href="cryptoauthlib.md">Install and configure</a></td>
<td><a href="tpm2-pkcs11/_index.md">Install and configure</a></td>
</tr>
<tr>
<td>

```sh
# Path of the PKCS#11 library
export PKCS11_LIB_PATH='/usr/lib64/pkcs11/libsofthsm2.so'
# export PKCS11_LIB_PATH='/usr/lib/arm-linux-gnueabihf/softhsm/libsofthsm2.so'

# Variables to identify and log in to the PKCS#11 token
TOKEN='Key pairs'
TOKEN_PARAM="token=$TOKEN"
PIN='1234'
PIN_SUFFIX="?pin-value=$PIN"

```
</td>
<td>

```sh
# Path of the PKCS#11 library
export PKCS11_LIB_PATH='/usr/lib/libcryptoauth.so'

# Variables to identify and log in to the PKCS#11 token
TOKEN_PARAM='slot-id=0'
PIN_SUFFIX=''
```
</td>
<td>

```sh
# Path of the PKCS#11 library
export PKCS11_LIB_PATH='/usr/local/lib/libtpm2_pkcs11.so'

# Variables to identify and log in to the PKCS#11 token
TOKEN='Key pairs'
TOKEN_PARAM="token=$TOKEN"
PIN='1234'
PIN_SUFFIX="?pin-value=$PIN"
```
</td>
</tr>
<tr>
<td colspan="3">Clear existing keys</td>
</tr>
<tr>
<td>

```sh
# This is the `directories.tokendir` in `softhsm2.conf`
rm -rf /var/lib/softhsm/tokens/* &&
softhsm2-util --init-token --free --label "$TOKEN" --so-pin "so$PIN" --pin "$PIN"
```
</td>
<td>

```sh
# This is the directory specified by `filestore` in `cryptoauthlib.conf`,
# plus the metadata files for objects in PKCS#11 slot 0.
rm -f /var/lib/cryptoauthlib/0.*.conf
```
</td>
<td>

```sh
sudo tpm2_clear

# This is the directory tpm2-pkcs11 was configured to use.
export TPM2_PKCS11_STORE='/opt/tpm2-pkcs11'

# tpm2_ptool requires Python 3 >= 3.7 and expects `python3` to be
# that version by default.
#
# If your distro has python3.7 or higher at a different path,
# like how Ubuntu 18.04 has `python3.7`, then set
# the `PYTHON_INTERPRETER` env var.
#
# export PYTHON_INTERPRETER=python3.7

rm -f "$TPM2_PKCS11_STORE/tpm2_pkcs11.sqlite3"
(
    cd ~/src/tpm2-pkcs11/tools &&
    ./tpm2_ptool init --primary-auth '1234' &&
    ./tpm2_ptool addtoken \
        --sopin "so$PIN" --userpin "$PIN" \
        --label "$TOKEN" --pid '1'
)
```
</td>
</tr>
</tbody>
</table>

The hardware and PKCS#11 library has now been configured.

To test with `pkcs11-tool`, run `pkcs11-tool --module "$PKCS11_LIB_PATH" ...`. For example, `pkcs11-tool --module "$PKCS11_LIB_PATH" -T` will show information about the "Key pairs" token that was created above.

To test it with `p11tool`, run `p11tool --provider "$PKCS11_LIB_PATH" ...`. For example, `p11tool --provider="$PKCS11_LIB_PATH" --list-token-urls` will show the token URL for the "Key pairs" token that was created above.

Another alternative for `p11tool` is to create a `.module` file so that you don't need to pass in `--provider` for every invocation:

```sh
sudo mkdir -p /etc/pkcs11/modules
<<< "module: $PKCS11_LIB_PATH" sudo tee /etc/pkcs11/modules/tpm2-pkcs11.module
```

However, `--provider` is still useful to filter out tokens from other PKCS#11 libraries.

---


## `pkcs11-test`

To verify the hardware and PKCS#11 library, there is a standalone `pkcs11-test` binary in this repository that can be used to run some PKCS#11-focused tests.

<table>
<thead>
<tr>
<th><code>softhsm2</code></th>
<th><code>cryptoauthlib</code></th>
<th><code>tpm2-pkcs11</code></th>
</tr>
</thead>
<tbody>
<tr>
<td colspan="3">

```sh
make pkcs11-test
```
</td>
</tr>
<tr>
<td colspan="3">

```sh
# Define three variables for the labels of the three certs that will be generated as part of the test.
LABEL_1='CA' # A CA cert
LABEL_2='Server' # A server cert signed by the CA cert
LABEL_3='Client' # A client cert signed by the CA cert

# Define three variables for the algorithms of the private keys of the certs. Valid values are `rsa-2048`, `rsa-4096` and `ec-p256`.
```
</td>
</tr>
<tr>
<td>

```sh
KEY_1_TYPE='rsa-4096'
KEY_2_TYPE='rsa-2048'
KEY_3_TYPE='rsa-2048'

# KEY_1_TYPE='rsa-2048'
# KEY_2_TYPE='rsa-2048'
# KEY_3_TYPE='rsa-2048'

# KEY_1_TYPE='ec-p256'
# KEY_2_TYPE='ec-p256'
# KEY_3_TYPE='ec-p256'
```
</td>
<td>

```sh
KEY_1_TYPE='ec-p256'
KEY_2_TYPE='ec-p256'
KEY_3_TYPE='ec-p256'
```

`cryptoauthlib` only supports `ec-p256` keys.
</td>
<td>

```sh
KEY_1_TYPE='rsa-2048'
KEY_2_TYPE='rsa-2048'
KEY_3_TYPE='rsa-2048'

# KEY_1_TYPE='ec-p256'
# KEY_2_TYPE='ec-p256'
# KEY_3_TYPE='ec-p256'
```

`tpm2-pkcs11` only supports `rsa-2048` and `ec-p256` keys.
</td>
</tr>
<tr>
<td colspan="3">

```sh
# The `PKCS11_SPY_PATH` env var can be defined to intercept all PKCS#11 API calls
# to the PKCS#11 library and print their inputs and outputs.
#
# export PKCS11_SPY_PATH='/usr/lib64/pkcs11/pkcs11-spy.so'
# export PKCS11_SPY_PATH='/usr/lib/arm-linux-gnueabihf/pkcs11/pkcs11-spy.so'

PKCS11_TEST_PATH="$PWD/target/x86_64-unknown-linux-gnu/debug/pkcs11-test"
# PKCS11_TEST_PATH="$PWD/target/armv7-unknown-linux-gnueabhif/debug/pkcs11-test"

# Generate three asymmetric keys to be used as the private keys for the three certs
"$PKCS11_TEST_PATH" generate-key-pair --key "pkcs11:$TOKEN_PARAM;object=$LABEL_1$PIN_SUFFIX" --type "$KEY_1_TYPE" &&
"$PKCS11_TEST_PATH" generate-key-pair --key "pkcs11:$TOKEN_PARAM;object=$LABEL_2$PIN_SUFFIX" --type "$KEY_2_TYPE" &&
"$PKCS11_TEST_PATH" generate-key-pair --key "pkcs11:$TOKEN_PARAM;object=$LABEL_3$PIN_SUFFIX" --type "$KEY_3_TYPE" &&

# Load them and print them
"$PKCS11_TEST_PATH" load --keys "pkcs11:$TOKEN_PARAM;object=$LABEL_1" "pkcs11:$TOKEN_PARAM;object=$LABEL_2" "pkcs11:$TOKEN_PARAM;object=$LABEL_3" &&

# Generate the CA cert
"$PKCS11_TEST_PATH" generate-ca-cert \
    --key "pkcs11:$TOKEN_PARAM;object=$LABEL_1$PIN_SUFFIX" --subject 'CA Inc' \
    --out-file "$PWD/ca.pem" &&

# Generate the server cert
"$PKCS11_TEST_PATH" generate-server-cert \
    --key "pkcs11:$TOKEN_PARAM;object=$LABEL_2$PIN_SUFFIX" --subject 'Server LLC' \
    --ca-cert "$PWD/ca.pem" --ca-key "pkcs11:$TOKEN_PARAM;object=$LABEL_1$PIN_SUFFIX" \
    --out-file "$PWD/server.pem" &&

# Generate the client cert
"$PKCS11_TEST_PATH" generate-client-cert \
    --key "pkcs11:$TOKEN_PARAM;object=$LABEL_3$PIN_SUFFIX" --subject 'Client GmbH' \
    --ca-cert "$PWD/ca.pem" --ca-key "pkcs11:$TOKEN_PARAM;object=$LABEL_1$PIN_SUFFIX" \
    --out-file "$PWD/client.pem" &&

# Start a hello-world web server that serves HTTPS on port 8443 using the server cert.
# The server will remain running.
"$PKCS11_TEST_PATH" web-server --cert "$PWD/server.pem" --key "pkcs11:$TOKEN_PARAM;object=$LABEL_2$PIN_SUFFIX"

# In another shell, connect to the server in various ways to verify that TLS works.
#
# 1. `openssl s_client`
< /dev/null openssl s_client -connect 127.0.0.1:8443 &&

# 2. `curl` (`-k` is needed since the CA cert is not in the OS trusted roots.) This should receive an HTTP 200 response with the body "Hello, world!"
curl -kD - https://127.0.0.1:8443 &&

# 3. `pkcs11-test web-client`. This uses the client cert for TLS client authentication. It should receive an HTTP 200 response with the body "Hello, world!"
#
# Both the client and the server will also print the cert chain of the other, and assert that the other's cert is signed by the CA cert.
"$PKCS11_TEST_PATH" web-client \
    --cert "$PWD/client.pem" --key "pkcs11:$TOKEN_PARAM;object=$LABEL_3$PIN_SUFFIX"
```
</td>
</tr>
</tbody>
</table>

If the three client tests pass successfully, ie `openssl s_client` completes the handshake successfully and prints the server cert details, and `curl` and `pkcs11-test web-client` print the hello-world response from the server, then the hardware and PKCS#11 library ought to be suitable for `aziot-keyd` to use. If there are errors such as crashes or signature verification failures, then it might be a problem with the hardware configuration, a bug in the PKCS#11 library, or a bug in the PKCS#11-related code in this repository.
