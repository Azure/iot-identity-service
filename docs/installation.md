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
<td>Debian 10, Raspberry Pi OS 10</td>
<td>amd64, arm32v7, aarch64</td>
</tr>
<tr>
<td>Debian 11, Raspberry Pi OS 11</td>
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
<tr>
<td>RHEL 8</td>
<td>amd64</td>
</tr>
</tbody>
</table>

Packages for some of these distros are available on packages.microsoft.com. 

## Install from packages.microsoft.com
**Applies to:** Ubuntu 18.04, 20.04, Raspberry Pi OS Bullseye

```bash
sudo apt install aziot-identity-service
```

You may need to first add the `packages.microsoft.com` to your repo sources.

1. On Ubuntu 18.04

    ```bash
    wget https://packages.microsoft.com/config/ubuntu/18.04/multiarch/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
    sudo dpkg -i packages-microsoft-prod.deb
    rm packages-microsoft-prod.deb
    ```


2. On Ubuntu 20.04

    ```bash
    wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
    sudo dpkg -i packages-microsoft-prod.deb
    rm packages-microsoft-prod.deb
    ```

3. On Raspberry Pi OS Bullseye

    ```bash
    wget https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
    sudo dpkg -i packages-microsoft-prod.deb
    rm packages-microsoft-prod.deb
    ```

4. On RedHat Enterprise Linux 8

    ```bash
    wget https://packages.microsoft.com/config/rhel/8/packages-microsoft-prod.rpm -O packages-microsoft-prod.rpm
    sudo yum localinstall packages-microsoft-prod.rpm
    rm packages-microsoft-prod.rpm
    ```

## Install for an alternative distro / architecture

Download and install the `aziot-identity-service` pre-built package for your respective distro / architecture from [the IoT Edge release collateral for v1.4 or later](https://github.com/Azure/azure-iotedge/releases/tag/1.4.0).

Using Ubuntu 20.04 amd64 as an example:

```bash
wget https://github.com/Azure/azure-iotedge/releases/download/1.4.0/aziot-identity-service_1.4.0-1_ubuntu20.04_amd64.deb -o aziot-identity-service.deb

sudo apt install ./aziot-identity-service.deb
```

> **Note**
>
> By design the package conflicts with the `iotedge` and `libiothsm-std` packages of IoT Edge v1.1 and earlier. If you're using `apt` to install the package it will prompt to remove the conflicting packages.  Otherwise, be sure to manually remove them before installing the Identity Service.
