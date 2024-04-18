# Installing the Azure IoT Identity Service

The Azure IoT Identity Service can be installed on your device by installing the appropriate `aziot-identity-service` package. Packages are provided for several distributions and architectures on the [GitHub releases page](https://github.com/Azure/azure-iotedge/releases) for Azure IoT Edge, as of v1.2. Packages for a subset of these distributions and architectures are also available on packages.microsoft.com. See the Azure IoT Edge's list of [Tier 1 supported platforms](https://learn.microsoft.com/en-us/azure/iot-edge/support#tier-1) for more details.

## Install from packages.microsoft.com


```bash
sudo apt install aziot-identity-service
```

You may need to first add the `packages.microsoft.com` to your repo sources. Instructions can be found [here](https://learn.microsoft.com/en-us/azure/iot-edge/how-to-provision-single-device-linux-symmetric#install-iot-edge).

## Install for an alternative distro / architecture

Download and install the `aziot-identity-service` pre-built package for your respective distro / architecture from [the IoT Edge releases page](https://github.com/Azure/azure-iotedge/releases).

Using Ubuntu 22.04 amd64 as an example:

```bash
# query GitHub for the latest versions of IoT Edge and IoT Identity Service
wget -qO- https://raw.githubusercontent.com/Azure/azure-iotedge/main/product-versions.json | jq -r '
  .channels[]
  | select(.name == "stable").products[]
  | select(.id == "aziot-edge").components[]
  | select(.name == "aziot-edge").version
'
# example output: 1.4.20
wget -qO- https://raw.githubusercontent.com/Azure/azure-iotedge/main/product-versions.json | jq -r '
  .channels[]
  | select(.name == "stable").products[]
  | select(.id == "aziot-edge").components[]
  | select(.name == "aziot-identity-service").version
'
# example output: 1.4.6

# download and install
wget https://github.com/Azure/azure-iotedge/releases/download/1.4.20/aziot-identity-service_1.4.6-1_ubuntu22.04_amd64.deb -O aziot-identity-service.deb
sudo apt install ./aziot-identity-service.deb
```

> **Note**
>
> By design the package conflicts with the `iotedge` and `libiothsm-std` packages of IoT Edge v1.1 and earlier. If you're using `apt` to install the package it will prompt to remove the conflicting packages.  Otherwise, be sure to manually remove them before installing the Identity Service.
