// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
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
//! All calls to [`aziot_keys_get_function_list`] or any function in [`AZIOT_KEYS_FUNCTION_LIST`] are serialized, ie a function will not be called
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

/// Version 2.0.0.0
pub const AZIOT_KEYS_VERSION_2_0_0_0: AZIOT_KEYS_VERSION = AZIOT_KEYS_VERSION {
    inner: 0x02_00_00_00,
};

/// The base struct of all of function lists.
#[derive(Debug)]
#[repr(C)]
pub struct AZIOT_KEYS_FUNCTION_LIST {
    /// The version of the API represented in this function list.
    ///
    /// The specific subtype of `AZIOT_KEYS_FUNCTION_LIST` can be determined by inspecting this value.
    pub version: AZIOT_KEYS_VERSION,
}

/// The specific implementation of [`AZIOT_KEYS_FUNCTION_LIST`] for API version 2.0.0.0
#[derive(Debug)]
#[repr(C)]
pub struct AZIOT_KEYS_FUNCTION_LIST_2_0_0_0 {
    /// The value of `base.version` must be [`AZIOT_KEYS_VERSION_2_0_0_0`].
    pub base: AZIOT_KEYS_FUNCTION_LIST,

    /// Set a parameter on this library.
    ///
    /// `name` must not be `NULL`.
    /// `value` may be `NULL`.
    ///
    /// The caller may free the name string after this method returns. If the implementation needs to hold on to it, it must make a copy.
    ///
    /// The interpretation of names and values depends on the implementation. A special case is for names that start with `preloaded_key:`,
    /// such as `preloaded_key:foo`. This defines a user-provided association of the key ID "foo" with the location specified by `value`.
    /// Any call that uses the key with ID "foo" must use the location specified by `value`. Note that this does not mean the key already exists
    /// at that location; but it does mean that `create_key_if_not_exists` (for example) must create the key at that location and not any other.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - `name` is `NULL`.
    ///   - `name` is not recognized by this implementation, or invalid in some other way.
    ///   - `value` is invalid.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub set_parameter: unsafe extern "C" fn(
        name: *const std::os::raw::c_char,
        value: *const std::os::raw::c_char,
    ) -> AZIOT_KEYS_RC,

    /// Create or load a key pair identified by the specified `id`.
    ///
    /// - If a key pair with that ID exists and can be loaded, it will be left as-is.
    /// - If a key pair with that ID does not exist, a new key will be created. It will be saved such that it can be looked up later using that same ID.
    ///
    /// `preferred_algorithms` dictates the caller's preference for the key algorithm. It is a string with components separated by COLON U+003A `:`,
    /// where each component specifies the name of an algorithm and will be attempted by the implementation in that order.
    /// The valid components are `"ec-p256"` for secp256r1, `"rsa-2048"` for 2048-bit RSA, `"rsa-4096"` for 4096-bit RSA, and `"*"` which indicates
    /// any algorithm of the implementation's choice. For example, the caller might use `"ec-p256:rsa-2048:*"` to indicate that it would like
    /// the implementation to use secp256r1, else RSA-2048 if that fails, else any other algorithm of the implementation's choice if that also fails.
    ///
    /// If an implementation does not recognize a particular component as an algorithm, or is unable to use the algorithm to generate a key pair,
    /// it must ignore that component and try the next one. If no components are left, the implementation returns an error.
    /// The implementation is allowed to be unable to generate a key pair regardless of which algorithms are specified; this is true even if
    /// the wildcard algorithm is specified.
    ///
    /// If `preferred_algorithms` is `NULL`, it must be interpreted the same as if it was `"*"`.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - `id` is `NULL`.
    ///   - `id` is invalid.
    ///   - `preferred_algorithms` is invalid.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub create_key_pair_if_not_exists: unsafe extern "C" fn(
        id: *const std::os::raw::c_char,
        preferred_algorithms: *const std::os::raw::c_char,
    ) -> AZIOT_KEYS_RC,

    /// Load an existing key pair identified by the specified `id`.
    ///
    /// This validates that a key pair with the given ID exists and can be loaded.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - `id` is `NULL`.
    ///   - `id` is invalid.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub load_key_pair: unsafe extern "C" fn(id: *const std::os::raw::c_char) -> AZIOT_KEYS_RC,

    /// Get the value of a parameter of the key pair identified by the specified `id`.
    ///
    /// `type_` must be set to one of the `AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_*` constants.
    ///
    /// `value` is an output byte buffer allocated by the caller to store the parameter value.
    /// The caller sets `value_len` to the address of the length of the buffer.
    /// The implementation populates `value` with the parameter value and sets `value_len` to the number of bytes it wrote to `value`.
    ///
    /// It is allowed for the caller to call the function with `value` set to `NULL`. In this case the implementation calculates
    /// an upper bound for how many bytes will be needed to store the parameter value, sets that in `value_len` and returns.
    ///
    /// The format of the data stored in `value` is determined by the `type_`. See the documentation of those constants for details.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - `id` is `NULL`.
    ///   - `id` is invalid.
    ///   - The key pair specified by `id` does not exist.
    ///   - `type_` is not a valid parameter type for the key pair specified by `id`.
    ///   - `value` is insufficiently large to hold the parameter value.
    ///   - `value_len` is `NULL`.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub get_key_pair_parameter: unsafe extern "C" fn(
        id: *const std::os::raw::c_char,
        // Would be nice to be able to use r#type, but https://github.com/eqrion/cbindgen/issues/410
        type_: AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE,
        value: *mut std::os::raw::c_uchar,
        value_len: *mut usize,
    ) -> AZIOT_KEYS_RC,

    /// Create or load a key identified by the specified `id`.
    ///
    /// - If a key with that ID exists and can be loaded, it will be left as-is.
    /// - If a key with that ID does not exist, a new random key will be created with the number of bytes specified by `length`.
    ///   It will be saved such that it can be looked up later using that same ID.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - `id` is `NULL`.
    ///   - `id` is invalid.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub create_key_if_not_exists:
        unsafe extern "C" fn(id: *const std::os::raw::c_char, length: usize) -> AZIOT_KEYS_RC,

    /// Load an existing key identified by the specified `id`.
    ///
    /// This validates that a key with the given ID exists and can be loaded.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - `id` is `NULL`.
    ///   - `id` is invalid.
    ///   - The key specified by `id` does not exist.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub load_key: unsafe extern "C" fn(id: *const std::os::raw::c_char) -> AZIOT_KEYS_RC,

    /// Import a symmetric key with the given `id`.
    ///
    /// It will be saved such that it can be looked up later using that same ID.
    ///
    /// If a key with that ID already exists, the existing key will be overwritten.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - `id` is `NULL`.
    ///   - `id` is invalid.
    ///   - `bytes` is `NULL`.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub import_key: unsafe extern "C" fn(
        id: *const std::os::raw::c_char,
        bytes: *const u8,
        bytes_len: usize,
    ) -> AZIOT_KEYS_RC,

    /// Derive a key with a given base key using some derivation data, and return the derived key.
    ///
    /// The derivation process used by this function must be identical to
    /// the derivation process used by `encrypt` with the `AZIOT_KEYS_ENCRYPT_MECHANISM_DERIVED` mechanism and
    /// the derivation process used by `sign` with the `AZIOT_KEYS_SIGN_MECHANISM_DERIVED` mechanism.
    ///
    /// `base_id` is the ID of the key that will be used to derive the new key.
    ///
    /// `derivation_data` is a byte buffer containing the data that used for the derivation.
    /// The caller sets `derivation_data_len` to the length of the buffer.
    ///
    /// `derived_key` is an output byte buffer allocated by the caller to store the derived key.
    /// The caller sets `derived_key_len` to the address of the length of the buffer.
    /// The implementation populates `derived_key` with the parameter derived_key and sets `derived_key_len` to the number of bytes it wrote to `derived_key`.
    ///
    /// It is allowed for the caller to call the function with `derived_key` set to `NULL`. In this case the implementation calculates
    /// an upper bound for how many bytes will be needed to store the derived key, sets that in `derived_key_len` and returns.
    ///
    /// The new key is not persisted by the implementation, only returned in `derived_key`.
    /// If the caller wishes to persist it, they can import it with `import_key`.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - `base_id` is `NULL`.
    ///   - `base_id` is invalid.
    ///   - The key specified by `base_id` does not exist.
    ///   - `derivation_data` is `NULL`.
    ///   - `derived_key` is insufficiently large to hold the parameter value.
    ///   - `derived_key_len` is `NULL`.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub derive_key: unsafe extern "C" fn(
        base_id: *const std::os::raw::c_char,
        derivation_data: *const u8,
        derivation_data_len: usize,
        derived_key: *mut std::os::raw::c_uchar,
        derived_key_len: *mut usize,
    ) -> AZIOT_KEYS_RC,

    /// Sign the given digest using the key or key pair identified by the specified `id`.
    ///
    /// `mechanism` must be set to one of the `AZIOT_KEYS_SIGN_MECHANISM_*` constants.
    /// `parameters` must be set according to the `mechanism`, as documented on the constants.
    ///
    /// `digest` is a byte buffer containing the data that must be signed.
    /// The caller sets `digest_len` to the length of the buffer.
    ///
    /// `signature` is an output byte buffer allocated by the caller to store the signature.
    /// The caller sets `signature_len` to the address of the length of the buffer.
    /// The implementation populates `signature` with the signature and sets `signature_len` to the number of bytes it wrote to `signature`.
    ///
    /// It is allowed for the caller to call the function with `signature` set to `NULL`. In this case the implementation calculates
    /// an upper bound for how many bytes will be needed to store the signature, sets that in `signature_len` and returns.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - `id` is `NULL`.
    ///   - `id` is invalid.
    ///   - The key or key pair specified by `id` does not exist.
    ///   - `mechanism` is not a valid signature mechanism for the key or key pair specified by `id`.
    ///   - `parameters` is invalid.
    ///   - `digest` is `NULL`.
    ///   - `signature` is insufficiently large to hold the signature.
    ///   - `signature_len` is `NULL`.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub sign: unsafe extern "C" fn(
        id: *const std::os::raw::c_char,
        mechanism: AZIOT_KEYS_SIGN_MECHANISM,
        parameters: *const std::ffi::c_void,
        digest: *const std::os::raw::c_uchar,
        digest_len: usize,
        signature: *mut std::os::raw::c_uchar,
        signature_len: *mut usize,
    ) -> AZIOT_KEYS_RC,

    /// Verify the signature of the given digest using the key or key pair (but see note below) identified by the specified `id`.
    ///
    /// `mechanism` must be set to one of the `AZIOT_KEYS_SIGN_MECHANISM_*` constants.
    /// `parameters` must be set according to the `mechanism`, as documented on the constants.
    ///
    /// `digest` is a byte buffer containing the data that must be signed.
    /// The caller sets `digest_len` to the length of the buffer.
    ///
    /// `signature` is a byte buffer containing the signature that the caller expects the data to have.
    /// The caller sets `signature_len` to the length of the buffer.
    ///
    /// `ok` is an output parameter that stores whether the signature could be verified or not.
    /// If the function is able to compute the signature of the data, it sets `ok` and returns `AZIOT_KEYS_RC_OK`.
    /// `ok` is set to 0 if the signature is invalid and non-zero if the signature is valid.
    /// The value stored in `ok` is only meaningful if the function returns `AZIOT_KEYS_RC_OK`, otherwise it must be ignored.
    ///
    /// Note: The implementation is not required to support verification with key pairs, ie `AZIOT_KEYS_SIGN_MECHANISM_ECDSA`.
    /// The caller can do the verification themselves with the public parameters of the EC key as obtained via `get_key_pair_parameter`.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - `id` is `NULL`.
    ///   - `id` is invalid.
    ///   - The key or key pair specified by `id` does not exist.
    ///   - `mechanism` is not a valid signature mechanism for the key or key pair specified by `id`.
    ///   - `parameters` is invalid.
    ///   - `digest` is `NULL`.
    ///   - `signature` is `NULL`.
    ///   - `ok` is `NULL`.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub verify: unsafe extern "C" fn(
        id: *const std::os::raw::c_char,
        mechanism: AZIOT_KEYS_SIGN_MECHANISM,
        parameters: *const std::ffi::c_void,
        digest: *const std::os::raw::c_uchar,
        digest_len: usize,
        signature: *const std::os::raw::c_uchar,
        signature_len: usize,
        ok: *mut std::os::raw::c_int,
    ) -> AZIOT_KEYS_RC,

    /// Encrypt the given plaintext using the key or key pair identified by the specified `id`.
    ///
    /// `mechanism` must be set to one of the `AZIOT_KEYS_ENCRYPT_MECHANISM_*` constants.
    /// `parameters` must be set according to the `mechanism`, as documented on the constants.
    ///
    /// `plaintext` is a byte buffer containing the data that must be encrypted.
    /// The caller sets `plaintext_len` to the length of the buffer.
    ///
    /// `ciphertext` is an output byte buffer allocated by the caller to store the encrypted data.
    /// The caller sets `ciphertext_len` to the address of the length of the buffer.
    /// The implementation populates `ciphertext` with the ciphertext and sets `ciphertext_len` to the number of bytes it wrote to `ciphertext`.
    ///
    /// It is allowed for the caller to call the function with `ciphertext` set to `NULL`. In this case the implementation calculates
    /// an upper bound for how many bytes will be needed to store the ciphertext, sets that in `ciphertext_len` and returns.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - `id` is `NULL`.
    ///   - `id` is invalid.
    ///   - The key or key pair specified by `id` does not exist.
    ///   - `mechanism` is not a valid encryption mechanism for the key or key pair specified by `id`.
    ///   - `parameters` is invalid.
    ///   - `plaintext` is `NULL`.
    ///   - `ciphertext` is insufficiently large to hold the ciphertext.
    ///   - `ciphertext_len` is `NULL`.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub encrypt: unsafe extern "C" fn(
        id: *const std::os::raw::c_char,
        mechanism: AZIOT_KEYS_ENCRYPT_MECHANISM,
        parameters: *const std::ffi::c_void,
        plaintext: *const std::os::raw::c_uchar,
        plaintext_len: usize,
        ciphertext: *mut std::os::raw::c_uchar,
        ciphertext_len: *mut usize,
    ) -> AZIOT_KEYS_RC,

    /// Decrypt the given plaintext using the key or key pair identified by the specified `id`.
    ///
    /// `mechanism` must be set to one of the `AZIOT_KEYS_ENCRYPT_MECHANISM_*` constants.
    /// `parameters` must be set according to the `mechanism`, as documented on the constants.
    ///
    /// `ciphertext` is a byte buffer containing the data that must be signed.
    /// The caller sets `ciphertext_len` to the length of the buffer.
    ///
    /// `plaintext` is an output byte buffer allocated by the caller to store the decrypted data.
    /// The caller sets `plaintext_len` to the address of the length of the buffer.
    /// The implementation populates `plaintext` with the plaintext and sets `plaintext_len` to the number of bytes it wrote to `plaintext`.
    ///
    /// It is allowed for the caller to call the function with `plaintext` set to `NULL`. In this case the implementation calculates
    /// an upper bound for how many bytes will be needed to store the plaintext, sets that in `plaintext_len` and returns.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - `id` is `NULL`.
    ///   - `id` is invalid.
    ///   - The key or key pair specified by `id` does not exist.
    ///   - `mechanism` is not a valid encryption mechanism for the key or key pair specified by `id`.
    ///   - `parameters` is invalid.
    ///   - `ciphertext` is `NULL`.
    ///   - `plaintext` is insufficiently large to hold the ciphertext.
    ///   - `plaintext_len` is `NULL`.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub decrypt: unsafe extern "C" fn(
        id: *const std::os::raw::c_char,
        mechanism: AZIOT_KEYS_ENCRYPT_MECHANISM,
        parameters: *const std::ffi::c_void,
        ciphertext: *const std::os::raw::c_uchar,
        ciphertext_len: usize,
        plaintext: *mut std::os::raw::c_uchar,
        plaintext_len: *mut usize,
    ) -> AZIOT_KEYS_RC,
}

#[cfg(any())]
#[no_mangle]
pub extern "C" fn cbindgen_unused_AZIOT_KEYS_FUNCTION_LIST_2_0_0_0(
) -> AZIOT_KEYS_FUNCTION_LIST_2_0_0_0 {
    unimplemented!();
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
    pfunction_list: *mut *const AZIOT_KEYS_FUNCTION_LIST,
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

/// Used with `encrypt` / `decrypt` to encrypt / decrypt using an AEAD mechanism, like AES-256-GCM.
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
