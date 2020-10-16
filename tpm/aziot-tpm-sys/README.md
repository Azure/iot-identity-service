# aziot-tpm-sys crate

This crate is the unsafe C to Rust interface for the TPM API library.

This crate represents the functions that the TPM API implements. This crate is
used by the `aziot-tpm-rs` crate to provide more Rust-friendly interfaces.

## TPM functionality

You may need additional setup for a TPM device see the in-tree dev docs for
more details.

## Memory allocation

The current TPM API functions expect the calling function to allocate memory for
the the caller to use. The caller (in this case, the Rust crate) is expected to
free this memory.

## Build dependencies

This crate is dependent on CMake being installed. On Debian based linux systems,
this can be installed with

```
sudo apt-get install build-essential cmake libcurl4-openssl-dev uuid-dev valgrind
```

### Valgrind

Valgrind was added to the linux build dependencies. We are using Valgrind for
detecting memory leaks, unassigned variables, and overruns in the dev mode
iothsm library.

Valgrind slows down the tests considerably, so the iothsm library in hsm-sys
runs tests with valgrind turned off by default. If you wish to run valgrind, set
the environment variable "RUN_VALGRIND".
