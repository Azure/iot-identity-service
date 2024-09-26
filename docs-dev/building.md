# Building the services

1. Clone this repo.

    ```sh
    git clone --recursive https://github.com/Azure/iot-identity-service
    cd iot-identity-service/
    ```

1. Install build dependencies.

    - `gcc`
    - `libclang1`
    - `llvm-config`
    - `make`
    - `openssl` headers and libraries
    - `pkg-config`

    Check [`/ci/install-build-deps.sh`](../ci/install-build-deps.sh) for the exact names of the packages for your distro that contain these components.

1. Install [`rustup`](https://rustup.rs). Ensure that `~/.cargo/bin` is in `$PATH`. The exact toolchain used to build this repository will automatically be downloaded later if necessary.

1. Install `bindgen` and `cbindgen`. Again, check [`/ci/install-build-deps.sh`](../ci/install-build-deps.sh) for the exact command and versions.

1. Build the services.

    ```sh
    make
    ```

    If the build fails with an error like:

    ```
    /usr/include/limits.h:124:16: fatal error: 'limits.h' file not found
    ```

    ... this is because `bindgen` got confused by the default `limits.h` that ships with `gcc`. Instead, you need to point it to an alternative one that doesn't use `include_next`. Find it with:

    ```sh
    find /usr/lib*/gcc/ -name limits.h | grep include-fixed
    ```

    This will print something like `/usr/lib/gcc/x86_64-linux-gnu/7/include-fixed/limits.h`

    Then export an env var to tell `bindgen` (and in turn, libclang) about this directory.

    ```sh
    export BINDGEN_EXTRA_CLANG_ARGS='-isystem /usr/lib/gcc/x86_64-linux-gnu/7/include-fixed'
    ```

    Then invoke `make` again.

# Updating a dependency

If you update a dependency in one of the Rust projects, e.g., by updating a Cargo.toml file or calling `cargo update`, you may get an error when you build the project, e.g.:

```sh
$ cargo build -p aziotd
error: failed to download from `https://pkgs.dev.azure.com/iotedge/39b8807f-aa0b-43ed-b4c9-58b83c0a23a7/_packaging/0581b6d1-911e-44b2-88d9-b384271aaf3a/cargo/api/v1/crates/http-body/1.0.1/download`

Caused by:
  failed to get successful HTTP response from `https://pkgs.dev.azure.com/iotedge/39b8807f-aa0b-43ed-b4c9-58b83c0a23a7/_packaging/0581b6d1-911e-44b2-88d9-b384271aaf3a/cargo/api/v1/crates/http-body/1.0.1/download` (13.107.42.20), got 401
  debug headers:
  x-cache: CONFIG_NOCACHE
  body:
  {"$id":"1","innerException":null,"message":"No local versions of package 'http-body'; please provide authentication to access versions from upstream that have not yet been saved to your feed.","typeName":"Microsoft.TeamFoundation.Framework.Server.UnauthorizedRequestException, Microsoft.TeamFoundation.Framework.Server","typeKey":"UnauthorizedRequestException","errorCode":0,"eventId":3000}
```

To add/upgrade a package in the feed, you must authenticate with write credentials. Ideally, a simple `cargo login` before `cargo build` would allow you to seamlessly update the feed, but cargo does not currently support optional authentication with fallback to anonymous. In other words, because we allow anonymous access to the feed, cargo will not authenticate. Instead, you can use the feed's REST API directly, e.g.,

```bash
package='<package name goes here>'
version='<package version goes here>'

# the user needs to have "Feed and Upstream Reader (Collaborator)" permissions on the feed
az login
auth_header=$(az account get-access-token --query "join(' ', ['Authorization: Bearer', accessToken])" --output tsv)

url="$(curl -sSL 'https://pkgs.dev.azure.com/iotedge/iotedge/_packaging/iotedge_PublicPackages/Cargo/index/config.json' | jq -r '.dl')"
url="${url/\{crate\}/$package}"
url="${url/\{version\}/$v}"

# curl with --max-time of 5 seconds because we don't actually have to download the package, we just need to nudge
# the feed to acquire the package from upstream
curl -sSL --max-time 5 --header "$auth_header" --write-out '%{http_code}\n' "$url"
```

Once you've added/updated the package in the feed, the build should proceed normally.

Outside contributors who need to add/update packages can temporarily comment out the changes in .cargo/config.toml during development, then open a PR (with config.toml restored to its original state) for review. Someone with access to the feed will need to update the feed before the PR can be tested and merged.