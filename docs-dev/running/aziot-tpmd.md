# Configuring and running `aziot-tpmd`

Configuration consists of the main config file (default `/etc/aziot/tpmd/config.toml`) and any number of principal files in the config directory (`/etc/aziot/tpmd/config.d`).

The main config file and all files in the config directory must be readable by the user you will run the service as. The default main config file and config directory can be overridden with the environment variables `AZIOT_TPMD_CONFIG` and `AZIOT_TPMD_CONFIG_DIR`, respectively.

Example main config file:

```toml
tcti = "swtpm:port=8181"
auth_key_index = 0x10_10_10

[hierarchy_authorization]
endorsement = "hello"
owner = "world"

[endpoints]
aziot_tpmd = "unix:///run/aziot/tpmd.sock"
```

- `tcti` - This value specifies the TCTI loader string that should be used to connect to the host TPM. By default, this value is "device".

- `auth_key_index` - This value controls the index within the owner hierarchy persistent key range (`[0x81_00_00_00, 0x81_7F_FF_FF]`) at which to store the DPS attestation key.

- `[hierarchy_authorization]` - This section defines the authorization values to be used with the endorsement and owner hierarchies of the TPM. Setting the "endorsement" and "owner" properties controls the authorization values provided to the corresponding TPM hierarchies. By default, the authorization values are empty.

- `[endpoints]` - This section defines endpoints for the services. For this service, there is only one endpoint:

    - The `aziot_tpmd` value denotes the endpoint that this service will accept connections on.

    Endpoints can be `unix` URIs where the URI contains a path of a UDS socket, `http` URIs with a host (and optional port).

    Note that the `[endpoints]` section is only parsed in debug builds, since it's only meant to be overridden for testing and development. For production, the section is ignored and the hard-coded defaults (same as the example above) are used.

    The configured value (or the default) will only take effect if the service hasn't been started via systemd socket activation. If it has been started via systemd socket activation, the service will use that socket fd instead.
