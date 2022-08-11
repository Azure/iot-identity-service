# `swtpm`

[The `swtpm` project](https://github.com/stefanberger/swtpm) is a TPM simulator. `tpm2-abrmd` can be configured to use it as a backend instead of a real TPM at `/dev/tpm0`. 

Note: It's expected you've already followed the steps in [the parent document](index.md) to compile `tpm2-abrmd`.

1. Compile and start `/usr/local/bin/swtpm` (adapted from ci/install-test-deps.sh)

    ```sh
    sudo apt-get install \
        autoconf automake expect gawk \
        gcc libjson-glib-dev libssl-dev \
        libtasn1-6-dev libtool make \
        net-tools pkg-config python3 socat

    # Build and install libtpms (required by swtpm)
    (
        cd third-party/libtpms || exit 1;
        ./autogen.sh \
            --disable-dependency-tracking \
            --with-openssl \
            --with-tpm2;
        make -j;
        make install;
    )

    # Build and install swtpm
    (
        cd third-party/swtpm || exit 1;
        ./autogen.sh \
            --disable-dependency-tracking \
            --without-seccomp;
        make -j;
        make install;
    )

    # Start swtpm
    PORT=2321 # TCTI default
    CONTROL=$(("${PORT}" + 1))
    TPM_STATE=$(mktemp -d)
    swtpm socket \
        --tpm2 \
        --tpmstate dir="${TPM_STATE}" \
        --port "${PORT}" \
        --ctrl type=tcp,port="${CONTROL}" \
        --flags not-need-init,startup-clear
    ```


1. Configure `tpm2-abrmd` to use the `swtpm` TCTI and start it.

    ```sh
    # Change "--tcti=swtpm" to "--tcti=swtpm:port=${PORT}" if PORT changed above.
    sudo mkdir -p /etc/systemd/system/tpm2-abrmd.service.d/
    sudo tee /etc/systemd/system/tpm2-abrmd.service.d/swtpm.conf <<-EOF
    [Unit]
    ConditionPathExistsGlob=

    [Service]
    ExecStart=
    ExecStart=/usr/local/sbin/tpm2-abrmd --tcti=swtpm
    EOF

    sudo systemctl daemon-reload
    sudo systemctl restart tpm2-abrmd
    ```

1. Verify that everything is working.

    ```sh
    # Should be active (running), and its log should say
    #
    #     tcti_conf after: "swtpm"
    #
    # or "swtpm:port=${PORT}" if using a different port configuration.
    sudo systemctl status tpm2-abrmd

    # Should print a large array of bytes,
    # instead of an error like
    #
    #     ERROR: Esys_GetCapability(0xA000A) - tcti:IO failure"
    tpm2_pcrread sha256
    ```
