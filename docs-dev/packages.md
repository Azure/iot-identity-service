# Building the packages

This repository contains three services - `aziot-certd`, `aziot-identityd` and `aziot-keyd` - as well as the `libaziot_keys.so` library. These four components ship in a single distro package named `aziot-identity-service`. The package can be built for a particular distro and a particular architecture by running the `/ci/package.sh` script in a Docker container of that distro, with an environment variable set to identify the architecture to build the packages for.


<table>
<thead>
<tr>
<th>Distro</th>
<th>Docker image</th>
</tr>
</thead>
<tbody>
<tr>
<td>CentOS 7</td>
<td><code>centos:7</code></td>
</tr>
<tr>
<td>Debian 9 / Raspbian 9</td>
<td><code>debian:9-slim</code></td>
</tr>
<tr>
<td>Debian 10 / Raspbian 10</td>
<td><code>debian:10-slim</code></td>
</tr>
<tr>
<td>Ubuntu 18.04</td>
<td><code>ubuntu:18.04</code></td>
</tr>
<tr>
<td>Ubuntu 20.04</td>
<td><code>ubuntu:20.04</code></td>
</tr>
</tbody>
</table>


<table>
<thead>
<tr>
<th>Architecture</th>
<th><code>ARCH</code> env var</th>
</tr>
</thead>
<tbody>
<tr>
<td>x86_64 / amd64</td>
<td><code>amd64</code></td>
</tr>
<tr>
<td>ARM32 v7 / armv7-gnueabihf</td>
<td><code>arm32v7</code></td>
</tr>
<tr>
<td>ARM64 v8 / AARCH64 / aarch64-gnu</td>
<td><code>aarch64</code></td>
</tr>
</tbody>
</table>

In addition, the script also needs the `PACKAGE_VERSION` and `PACKAGE_RELEASE` environment variables to be set, which control the version and release (for RPM packages) / revision (for Debian packages) number of the generated package.

Finally, the script expects the source directory to be at `/src`, and will create the packages under `/src/packages`.

For an example to put it all together, let's say you want to build the CentOS 7 package for `x86_64`, with version 1.2.0 and release 0, ie the package version is `1.2.0-0`. Let's say your clone of this repository is at `~/src/iot-identity-service`. You would run:

```sh
docker run -it --rm \
    -v "$(realpath ~/src/iot-identity-service):/src" \
    -e 'ARCH=amd64' \
    -e 'PACKAGE_VERSION=1.2.0' \
    -e 'PACKAGE_RELEASE=0' \
    centos:7 \
    '/src/ci/package.sh'
```

and at the end you would have these files under `~/src/iot-identity-service/packages`:

```
centos7/amd64/aziot-identity-service-1.2.0-0.src.rpm
centos7/amd64/aziot-identity-service-1.2.0-0.x86_64.rpm
centos7/amd64/aziot-identity-service-devel-1.2.0-0.x86_64.rpm
```

These files in order are:

1. The source package. This contains the contents of this repository but pre-processed for CentOS 7-specific customizations. The other packages were built from this package.
1. The binary package. This is the package a user would install on their device.
1. A devel package containing the `aziot-keys.h` C header, which contains the API definitions of `libaziot_keys.so`. A user would install this package if they wanted to make their own implementation of `libaziot_keys.so`. It's not needed for a production device.


For another example, let's say you want to build the Debian 10 package for ARM32, with version `1.2.0` and revision 0, ie the package version is `1.2.0-0`. You would run:

```sh
docker run -it --rm \
    -v "$(realpath ~/src/iot-identity-service):/src" \
    -e 'ARCH=arm32v7' \
    -e 'PACKAGE_VERSION=1.2.0' \
    -e 'PACKAGE_RELEASE=0' \
    debian:10-slim \
    '/src/ci/package.sh'
```

and at the end you would have these files under `~/src/iot-identity-service/packages`:

```
aziot-identity-service_1.2.0-0_armhf.deb
aziot-identity-service_1.2.0-0.debian.tar.xz
aziot-identity-service_1.2.0-0.dsc
aziot-identity-service_1.2.0.orig.tar.gz
aziot-identity-service-dbgsym_1.2.0-0_armhf.deb
```

The first file is the binary package, the second through fourth file together constitute the source package, and the fifth is the debug symbols package. The meanings are the same as the CentOS example. Note that there is no `-dev` package equivalent of the CentOS `-devel` package; the C header is included in the binary package.


## Miscellaneous

1. Make sure to run the script in a Docker container instead of directly on your machine, even if your machine happens to be the same distro as the one you want to build the package for. The script installs dependencies and modifies system files like `/etc/apt`, so you don't want these to be done to your host machine.

1. The script must be run on an `x86_64` host, even for building ARM32 and ARM64 packages. The ARM32 and ARM64 packages are built via cross-compilation.

1. Building ARM32 and ARM64 packages for CentOS 7 is currently not supported, because CentOS 7 does not have functional cross compilers for those architectures. (It has the `gcc` cross compiler itself but not a cross `glibc` for the compiled binary to link to, because the cross compiler is only intended for cross-compiling the kernel.)

1. The packages script is also run in our CI, via the `.github/workflows/packages.yaml` file.
