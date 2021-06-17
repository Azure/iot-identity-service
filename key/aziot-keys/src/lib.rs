// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![deny(missing_docs)]
#![allow(
    non_camel_case_types,
    clippy::default_trait_access,
    clippy::doc_markdown, // clippy wants "IoT" in a code fence
    clippy::let_and_return,
    clippy::let_unit_value,
    clippy::missing_safety_doc,
    clippy::shadow_unrelated,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::type_complexity,
)]

//! This library is used to create and load keys for the Azure IoT Keys Service.
//!
//! While it is written in Rust, its interaction with the Azure IoT Keys Services is via a C API. This is because this library can be swapped
//! with another implementation of your choice that exposes the same C API. The documentation of this library is aimed at both
//! readers looking to understand this particular implementation, as well as readers looking to implement their own libaziot-keys library.
//!
//!
//! # API conventions
//!
//! All functions return an `unsigned int` to indicate success or failure. See the [`AZIOT_KEYS_RC`] type's docs for details about these constants.
//!
//! Unless specified otherwise, all C strings in the API are NUL-terminated UTF-8-encoded strings.
//!
//! The only function exported by this library is [`aziot_keys_get_function_list`]. Call this function to get the version of the API
//! that this library exports, as well as the function pointers to the key operations. See its docs for more details.
//!
//! All calls to [`aziot_keys_get_function_list`] or any function in [`function_list::AZIOT_KEYS_FUNCTION_LIST`] are serialized, ie a function will not be called
//! while another function is running. However, it is not guaranteed that all function calls will be made from the same operating system thread.
//! Thus, implementations do not need to worry about locking to prevent concurrent access, but must also not store data in thread-local storage
//! in one function invocation and expect it to be accessible in another function invocation.

// DEVNOTE:
//
// Keep the above doc header in sync with cbindgen.prelude.h

// DEVNOTE:
//
// Transparent newtypes around integers must be specified as non-tuple structs.
// Eg `struct AZIOT_KEYS_RC { inner: c_uint }`, not `struct AZIOT_KEYS_RC(c_uint)`.
// This is because cbindgen requires constants to be assigned with struct expressions like `AZIOT_KEYS_RC { inner: 0 }`,
// whereas `AZIOT_KEYS_RC(0)` is a call expression that makes cbindgen ignore the constant.

// DEVNOTE:
//
// Some structs have a corresponding fn item like
//
//    #[cfg(any())]
//    #[no_mangle]
//    pub extern "C" fn cbindgen_unused_STRUCT() -> STRUCT { unimplemented!(); }
//
// These functions are required so that cbindgen emits the corresponding structs in the C header file. This is because cbindgen doesn't emit
// all pub structs that it finds, but only the ones that are referenced by pub fns. So for structs that are not referenced directly by any pub fns,
// we need these fake functions to reference them.
//
// Since cbindgen doesn't expand macros by default, we need to write these functions manually, as opposed to using a macro to generate them.
//
// The functions aren't actually part of the API of course, so the Makefile runs a post-processing step to strip these functions from the C header file
// and leave the structs. Specifically, it strips all functions whose names start with `cbindgen_unused_`, so ensure that all such functions follow
// this convention.
//
// The `#[cfg(any())]` on the functions is a cfg that always evaluates to false, so the functions don't actually get compiled into the final cdylib.
// cbindgen doesn't notice this.
//
// (Incidentally, this would backfire if we did use a macro to generate the fns and enabled expansion in the cbindgen config. This is because
// cbindgen does expansion via `rustc --pretty=expanded`, which also resolves `cfg()`s, so these fns would end up getting ignored by cbindgen too.

pub mod function_list;

mod implementation;
mod key;
mod key_pair;

/// Return code of a function. This is a transparent wrapper around a `std::os::raw::c_uint` (`unsigned int`).
///
/// One of the `AZIOT_KEYS_RC_ERR_*` constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AZIOT_KEYS_RC {
    inner: std::os::raw::c_uint,
}

/// The operation succeeded.
pub const AZIOT_KEYS_RC_OK: AZIOT_KEYS_RC = AZIOT_KEYS_RC { inner: 0 };

/// The operation failed because a parameter has an invalid value.
pub const AZIOT_KEYS_RC_ERR_INVALID_PARAMETER: AZIOT_KEYS_RC = AZIOT_KEYS_RC { inner: 1 };

/// The library encountered an error with an external resource, such as an I/O error or RPC error.
pub const AZIOT_KEYS_RC_ERR_EXTERNAL: AZIOT_KEYS_RC = AZIOT_KEYS_RC { inner: 2 };

/// Represents the version of the API exported by this library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AZIOT_KEYS_VERSION {
    inner: std::os::raw::c_uint,
}

/// Get the list of functions for operations corresponding to the specified version.
///
/// Implementations can use this function for initialization, since it is guaranteed to be called before any operations.
/// However it is not an error to call this function multiple times, for the same or different version,
/// so implementations must ensure they only run their initialization once.
///
/// The pointer returned from this function must not be freed by the caller, and its contents must not be mutated.
///
/// # Errors
///
/// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
///   - `version` is not recognized by this implementation.
///   - `pfunction_list` is `NULL`.
#[no_mangle]
pub unsafe extern "C" fn aziot_keys_get_function_list(
    version: AZIOT_KEYS_VERSION,
    pfunction_list: *mut *const function_list::AZIOT_KEYS_FUNCTION_LIST,
) -> AZIOT_KEYS_RC {
    implementation::get_function_list(version, pfunction_list)
}

/// Used as the parameter type with `get_key_pair_parameter`.
///
/// One of the `AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_*` constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE {
    inner: std::os::raw::c_uint,
}

/// Used as the parameter type with `get_key_pair_parameter` to get the key algorithm.
///
/// The value returned by `get_key_pair_parameter` will be one of the `AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM_*` constants.
pub const AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_ALGORITHM: AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE =
    AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE { inner: 1 };

/// Used as the parameter type with `get_key_pair_parameter` to get the curve OID of an EC key.
///
/// The value returned by `get_key_pair_parameter` will be a byte buffer containing a DER-encoded OID.
pub const AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_EC_CURVE_OID: AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE =
    AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE { inner: 2 };

/// Used as the parameter type with `get_key_pair_parameter` to get the point of an EC key.
///
/// The value returned by `get_key_pair_parameter` will be a byte buffer containing a DER-encoded octet string in RFC 5490 format.
pub const AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_EC_POINT: AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE =
    AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE { inner: 3 };

/// Used as the parameter type with `get_key_pair_parameter` to get the modulus of an RSA key.
///
/// The value returned by `get_key_pair_parameter` will be a byte buffer holding a big-endian bignum.
pub const AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_RSA_MODULUS: AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE =
    AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE { inner: 4 };

/// Used as the parameter type with `get_key_pair_parameter` to get the exponent of an RSA key.
///
/// The value returned by `get_key_pair_parameter` will be a byte buffer holding a big-endian bignum.
pub const AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_RSA_EXPONENT: AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE =
    AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE { inner: 5 };

/// The algorithm of a key pair, as returned by `get_key_pair_parameter`.
///
/// One of the `AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM_*` constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM {
    inner: std::os::raw::c_uint,
}

/// The key pair is an EC key.
pub const AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM_EC: AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM =
    AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM { inner: 1 };

/// The key pair is an RSA key.
pub const AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM_RSA: AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM =
    AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM { inner: 2 };

/// The usage of key being created with `create_key_if_not_exists` or
/// being imported with `import_key`.
///
/// This is a bitflag type, so its values can be combined. But note that not all combinations of flags
/// are valid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AZIOT_KEYS_KEY_USAGE {
    inner: std::os::raw::c_uint,
}

/// The key can be used for deriving other keys.
///
/// Cannot be combined with [`AZIOT_KEYS_KEY_USAGE_ENCRYPT`]
pub const AZIOT_KEYS_KEY_USAGE_DERIVE: AZIOT_KEYS_KEY_USAGE =
    AZIOT_KEYS_KEY_USAGE { inner: 0x0001 };

/// The key can be used for encryption.
///
/// Cannot be combined with [`AZIOT_KEYS_KEY_USAGE_DERIVE`] or [`AZIOT_KEYS_KEY_USAGE_SIGN`]
pub const AZIOT_KEYS_KEY_USAGE_ENCRYPT: AZIOT_KEYS_KEY_USAGE =
    AZIOT_KEYS_KEY_USAGE { inner: 0x0010 };

/// The key can be used for signing.
///
/// Cannot be combined with [`AZIOT_KEYS_KEY_USAGE_ENCRYPT`]
pub const AZIOT_KEYS_KEY_USAGE_SIGN: AZIOT_KEYS_KEY_USAGE = AZIOT_KEYS_KEY_USAGE_DERIVE;

/// The mechanism used with `sign` / `verify`.
///
/// One of the `AZIOT_KEYS_SIGN_MECHANISM_*` constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AZIOT_KEYS_SIGN_MECHANISM {
    inner: std::os::raw::c_uint,
}

/// Used with `sign` / `verify` to sign / verify using ECDSA.
///
/// The `parameters` parameter of `sign` / `verify` is unused and ignored.
pub const AZIOT_KEYS_SIGN_MECHANISM_ECDSA: AZIOT_KEYS_SIGN_MECHANISM =
    AZIOT_KEYS_SIGN_MECHANISM { inner: 1 };

/// Used with `sign` / `verify` to sign / verify using HMAC-SHA256.
///
/// The `parameters` parameter of `sign` / `verify` is unused and ignored.
pub const AZIOT_KEYS_SIGN_MECHANISM_HMAC_SHA256: AZIOT_KEYS_SIGN_MECHANISM =
    AZIOT_KEYS_SIGN_MECHANISM { inner: 2 };

/// Used with `sign` / `verify` to sign / verify using a derived key.
///
/// The `id` parameter of `sign` / `verify` is set to the ID of the base key.
/// The `parameters` parameter of `sign` / `verify` must be set to an `AZIOT_KEYS_SIGN_DERIVED_PARAMETERS` value.
pub const AZIOT_KEYS_SIGN_MECHANISM_DERIVED: AZIOT_KEYS_SIGN_MECHANISM =
    AZIOT_KEYS_SIGN_MECHANISM { inner: 3 };

/// Used with `sign` / `verify` with the [`AZIOT_KEYS_SIGN_MECHANISM_DERIVED`] mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct AZIOT_KEYS_SIGN_DERIVED_PARAMETERS {
    /// The data used to derive the new key.
    pub derivation_data: *const std::os::raw::c_uchar,

    /// The length of the `derivation_data` buffer.
    pub derivation_data_len: usize,

    /// The signature mechanism to use with the derived key.
    ///
    /// One of the `AZIOT_KEYS_SIGN_MECHANISM_*` constants.
    pub mechanism: AZIOT_KEYS_SIGN_MECHANISM,

    /// The parameters of the signature mechanism specified by `mechanism`.
    pub parameters: *const std::ffi::c_void,
}

#[cfg(any())]
#[no_mangle]
pub extern "C" fn cbindgen_unused_AZIOT_KEYS_SIGN_DERIVED_PARAMETERS(
) -> AZIOT_KEYS_SIGN_DERIVED_PARAMETERS {
    unimplemented!();
}

/// The mechanism used with `encrypt` / `decrypt`.
///
/// One of the `AZIOT_KEYS_ENCRYPT_MECHANISM_*` constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AZIOT_KEYS_ENCRYPT_MECHANISM {
    inner: std::os::raw::c_uint,
}

/// Used with `encrypt` / `decrypt` to encrypt / decrypt using an AEAD mechanism, like AES-GCM.
///
/// The exact AEAD algorithm used is left to the implementation and need not always be the same.
/// The caller must not make any assumptions about the format of the ciphertext.
///
/// The `parameters` parameter of `encrypt` / `decrypt` must be set to an `AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS` value.
pub const AZIOT_KEYS_ENCRYPT_MECHANISM_AEAD: AZIOT_KEYS_ENCRYPT_MECHANISM =
    AZIOT_KEYS_ENCRYPT_MECHANISM { inner: 1 };

/// Used with `encrypt` / `decrypt` to encrypt / decrypt using RSA with PKCS1 padding.
///
/// The `parameters` parameter of `encrypt` / `decrypt` is unused and ignored.
pub const AZIOT_KEYS_ENCRYPT_MECHANISM_RSA_PKCS1: AZIOT_KEYS_ENCRYPT_MECHANISM =
    AZIOT_KEYS_ENCRYPT_MECHANISM { inner: 2 };

/// Used with `encrypt` / `decrypt` to encrypt / decrypt using RSA with no padding. Padding will have been performed by the caller.
///
/// The `parameters` parameter of `encrypt` / `decrypt` is unused and ignored.
pub const AZIOT_KEYS_ENCRYPT_MECHANISM_RSA_NO_PADDING: AZIOT_KEYS_ENCRYPT_MECHANISM =
    AZIOT_KEYS_ENCRYPT_MECHANISM { inner: 3 };

/// Used with `encrypt` / `decrypt` to encrypt / decrypt using a derived key.
///
/// The `id` parameter of `encrypt` / `decrypt` is set to the ID of the base key.
/// The `parameters` parameter of `encrypt` / `decrypt` must be set to an `AZIOT_KEYS_ENCRYPT_DERIVED_PARAMETERS` value.
pub const AZIOT_KEYS_ENCRYPT_MECHANISM_DERIVED: AZIOT_KEYS_ENCRYPT_MECHANISM =
    AZIOT_KEYS_ENCRYPT_MECHANISM { inner: 4 };

/// Used with `encrypt` / `decrypt` with the [`AZIOT_KEYS_ENCRYPT_MECHANISM_AEAD`] mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS {
    /// The IV.
    pub iv: *const std::os::raw::c_uchar,

    /// The length of the `iv` buffer.
    pub iv_len: usize,

    /// The AAD.
    pub aad: *const std::os::raw::c_uchar,

    /// The length of the `aad` buffer.
    pub aad_len: usize,
}

#[cfg(any())]
#[no_mangle]
pub extern "C" fn cbindgen_unused_AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS(
) -> AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS {
    unimplemented!();
}

/// Used with `encrypt` / `decrypt` with the [`AZIOT_KEYS_ENCRYPT_MECHANISM_DERIVED`] mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct AZIOT_KEYS_ENCRYPT_DERIVED_PARAMETERS {
    /// The data used to derive the new key.
    pub derivation_data: *const std::os::raw::c_uchar,

    /// The length of the `derivation_data` buffer.
    pub derivation_data_len: usize,

    /// The encryption mechanism to use with the derived key.
    ///
    /// One of the `AZIOT_KEYS_ENCRYPT_MECHANISM_*` constants.
    pub mechanism: AZIOT_KEYS_ENCRYPT_MECHANISM,

    /// The parameters of the encryption mechanism specified by `mechanism`.
    pub parameters: *const std::ffi::c_void,
}

#[cfg(any())]
#[no_mangle]
pub extern "C" fn cbindgen_unused_AZIOT_KEYS_ENCRYPT_DERIVED_PARAMETERS(
) -> AZIOT_KEYS_ENCRYPT_DERIVED_PARAMETERS {
    unimplemented!();
}

/// Catches the error, if any, and returns it. Otherwise returns [`AZIOT_KEYS_RC_OK`].
fn r#catch(f: impl FnOnce() -> Result<(), AZIOT_KEYS_RC>) -> AZIOT_KEYS_RC {
    match f() {
        Ok(()) => AZIOT_KEYS_RC_OK,
        Err(err) => err,
    }
}
