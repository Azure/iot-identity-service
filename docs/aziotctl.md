# Managing the Azure Iot Identity Service

The `aziotctl` CLI tool is used to manage and interact with the services.

See `aziotctl --help` for the full help. A few notable commands are listed below.

Note that most `aziotctl` commands need to be run as root.


## Applying changes in the super-config to the services

```sh
sudo aziotctl config apply
```

By default, this command expects the super-config to be at `/etc/aziot/config.toml`. To use a different path, specify the `-c / --config` parameter.


## Stop all services

```sh
sudo aziotctl system stop
```


## Restart all services

```sh
sudo aziotctl system restart
```

Note: Since the services use systemd socket activation, this command starts all the socket units but does not start any service except the Identity Service (`aziot-identityd.service`). The other services (`aziot-keyd.service`, `aziot-certd.service`, etc) will automatically start if they need to.
