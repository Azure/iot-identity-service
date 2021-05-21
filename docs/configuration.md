# Configuring the Azure IoT Identity Service

The Azure IoT Identity Service package installs four different services - the Identity Service, Keys Service, Certificates Service, and TPM Service. All of these services can be configured from a single configuration file, called the "super-config".

A template of this file is installed at `/etc/aziot/config.toml.template`. Copy it to a new file `/etc/aziot/config.toml`, and edit the file with the details of your device, IoT Hub, etc, based on the comments in the file. Then, run the command `sudo aziotctl config apply` to apply the configuration to the services.

```sh
# Copy the template to a new file
sudo cp /etc/aziot/config.toml.template /etc/aziot/config.toml

# Edit the new empty config and fill in your provisioning information,
# plus anything else you want to customize. See the comments in the file for details.
sudo $EDITOR /etc/aziot/config.toml

# Apply the configuration to the services
sudo aziotctl config apply
```

If you need to make any changes to the `/etc/aziot/config.toml` file, do so, then re-run `sudo aziotctl config apply` to re-apply those changes to the services.
