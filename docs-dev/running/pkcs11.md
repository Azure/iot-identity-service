# Setting up your PKCS#11 library

Follow the user steps at <https://azure.github.io/iot-identity-service/pkcs11/>

If you want to use tpm2-pkcs11 with the TPM simulator, see [`swtpm`](swtpm.md)

To verify your HSM and its PKCS#11 library with aziot-keyd, see [Testing the openssl engine.](aziot-keyd.md#testing-the-openssl-engine)

If the script mentioned there completes successfully, then the hardware and PKCS#11 library ought to be suitable for `aziot-keyd` to use. If there are errors such as crashes or signature verification failures, then it might be a problem with the hardware configuration, a bug in the PKCS#11 library, or a bug in the PKCS#11-related code in this repository.
