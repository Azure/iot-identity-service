# Installing the Azure IoT Identity Service

The Azure IoT Identity Service can be installed on your device by installing the appropriate `aziot-identity-service`. Packages are provided for the following distributions and architectures with each [release of Azure IoT Edge as of v1.2](https://github.com/Azure/azure-iotedge/releases):

<table>
<thead>
<tr>
<th>OS</th>
<th>Architectures</th>
</tr>
</thead>
<tbody>
<tr>
<td>Debian 9, Raspbian 9</td>
<td>amd64, arm32v7, aarch64</td>
</tr>
<tr>
<td>Debian 10, Raspbian 10</td>
<td>amd64, arm32v7, aarch64</td>
</tr>
<tr>
<td>Ubuntu 18.04</td>
<td>amd64, arm32v7, aarch64</td>
</tr>
<tr>
<td>Ubuntu 20.04</td>
<td>amd64, arm32v7, aarch64</td>
</tr>
<tr>
<td>CentOS 7</td>
<td>amd64</td>
</tr>
</tbody>
</table>

Packages for some of these distros are available on packages.microsoft.com. 

## Install from packages.microsoft.com
**Applies to:** Ubuntu 18.04, Raspberry Pi OS Stretch

```bash
sudo apt install aziot-identity-service
```

You may need to first add the `packages.microsoft.com` to your repo sources.

1. Install the Microsoft GPG public key

    ```bash
    curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.gpg
    sudo cp ./microsoft.gpg /etc/apt/trusted.gpg.d/
    ```

2. On Ubuntu 18.04

    ```bash
    curl https://packages.microsoft.com/config/ubuntu/18.04/multiarch/prod.list > ./microsoft-prod.list
    sudo cp ./microsoft-prod.list /etc/apt/sources.list.d/
    ```

3. On Raspberry Pi OS Stretch

    ```bash
    curl https://packages.microsoft.com/config/debian/stretch/multiarch/prod.list > ./microsoft-prod.list
    sudo cp ./microsoft-prod.list /etc/apt/sources.list.d/
    ```

## Install for an alternative distro / architecture

Download and install the `aziot-identity-service` pre-built package for your respective distro / architecture from [the IoT Edge release collateral for v1.2 or later](https://github.com/Azure/azure-iotedge/releases/tag/1.2.0).

Using Ubuntu 20.04 amd64 as an example:

```bash
wget https://github.com/Azure/azure-iotedge/releases/download/1.2.0/aziot-identity-service_1.2.0-1_ubuntu20.04_amd64.deb -o aziot-identity-service.deb

sudo apt install ./aziot-identity-service.deb
```

> **Note**
>
> By design the package conflicts with the `iotedge` and `libiothsm-std` packages of IoT Edge v1.1 and earlier. If you're using `apt` to install the package it will prompt to remove the conflicting packages.  Otherwise, be sure to manually remove them before installing the Identity Service.
