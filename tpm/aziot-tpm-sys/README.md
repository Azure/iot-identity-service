# aziot-tpm-sys crate

This crate is the unsafe C-to-Rust interface for the TPM API library. It is
consumed by the `aziot-tpm-rs` crate, which re-exports a more Rust-friendly
interface to the C library.

## TPM functionality

You may need additional setup for a TPM device see the in-tree dev docs for
more details.

## Memory allocation

The current TPM API functions expect the calling function to allocate memory for
the the caller to use. The caller (in this case, the Rust crate) is expected to
free this memory.

### Valgrind

We use Valgrind for detecting memory leaks, unassigned variables, and overruns 
in the dev mode libaziottpm library.

Valgrind slows down the tests considerably, so the libaziottpm library runs 
tests with valgrind turned off by default. If you wish to run valgrind, set
the environment variable "RUN_VALGRIND".
