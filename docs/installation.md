# Installing the Azure IoT Identity Service

The Azure IoT Identity Service can be installed on your device by installing the appropriate `aziot-identity-service`. Packages are provided for the following distributions and architectures:

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

Packages for some of these distros are available on packages.microsoft.com. Alternatively, packages can be downloaded from [IoT Edge's GitHub releases.](https://github.com/Azure/azure-iotedge/releases)

For Debian and Ubuntu, install the package with `apt install` as usual. For CentOS, install the package with `yum install` as usual.
