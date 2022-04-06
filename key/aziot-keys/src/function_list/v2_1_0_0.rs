// Copyright (c) Microsoft. All rights reserved.

//! Function list type version 2.1.0.0

use crate::AZIOT_KEYS_VERSION;

/// Version 2.1.0.0
pub const AZIOT_KEYS_VERSION_2_1_0_0: AZIOT_KEYS_VERSION = AZIOT_KEYS_VERSION {
    inner: 0x02_01_00_00,
};

/// The specific implementation of [`AZIOT_KEYS_FUNCTION_LIST`] for API version 2.1.0.0
#[derive(Debug)]
#[repr(C)]
pub struct AZIOT_KEYS_FUNCTION_LIST_2_1_0_0 {
    /// The value of `base.version` must be [`AZIOT_KEYS_VERSION_2_1_0_0`].
    pub base: super::AZIOT_KEYS_FUNCTION_LIST,

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
    ) -> crate::AZIOT_KEYS_RC,

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
    ) -> crate::AZIOT_KEYS_RC,

    /// Move an existing key pair to another `id`.
    ///
    /// This function replaces any existing key and the destination `id`.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - either `from` or `to` is `NULL`.
    ///   - either `from` or `to` is invalid.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub move_key_pair: unsafe extern "C" fn(
        from: *const std::os::raw::c_char,
        to: *const std::os::raw::c_char,
    ) -> crate::AZIOT_KEYS_RC,

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
    pub load_key_pair:
        unsafe extern "C" fn(id: *const std::os::raw::c_char) -> crate::AZIOT_KEYS_RC,

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
        type_: crate::AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE,
        value: *mut std::os::raw::c_uchar,
        value_len: *mut usize,
    ) -> crate::AZIOT_KEYS_RC,

    /// Delete an existing key pair identified by the specified `id`.
    ///
    /// This function succeeds if a key with the specified ID doesn't already exist.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - `id` is `NULL`.
    ///   - `id` is invalid.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub delete_key_pair:
        unsafe extern "C" fn(id: *const std::os::raw::c_char) -> crate::AZIOT_KEYS_RC,

    /// Create or load a key identified by the specified `id`.
    ///
    /// - If a key with that ID exists and can be loaded, it will be left as-is.
    /// - If a key with that ID does not exist, a new random key will be created.
    ///   It will be saved such that it can be looked up later using that same ID.
    ///
    /// `usage` specifies what the key will be used for.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - `id` is `NULL`.
    ///   - `id` is invalid.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub create_key_if_not_exists: unsafe extern "C" fn(
        id: *const std::os::raw::c_char,
        usage: crate::AZIOT_KEYS_KEY_USAGE,
    ) -> crate::AZIOT_KEYS_RC,

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
    pub load_key: unsafe extern "C" fn(id: *const std::os::raw::c_char) -> crate::AZIOT_KEYS_RC,

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
        usage: crate::AZIOT_KEYS_KEY_USAGE,
    ) -> crate::AZIOT_KEYS_RC,

    /// Delete an existing key identified by the specified `id`.
    ///
    /// This function succeeds if a key with the specified ID doesn't already exist.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
    ///   - `id` is `NULL`.
    ///   - `id` is invalid.
    ///
    /// - `AZIOT_KEYS_RC_ERR_EXTERNAL`
    pub delete_key: unsafe extern "C" fn(id: *const std::os::raw::c_char) -> crate::AZIOT_KEYS_RC,

    /// Derive a key with a given base key using some derivation data, and return the derived key.
    ///
    /// The derivation process used by this function must be identical to
    /// the derivation process used by `encrypt` with the `AZIOT_KEYS_ENCRYPT_MECHANISM_DERIVED` mechanism and
    /// the derivation process used by `sign` with the `AZIOT_KEYS_SIGN_MECHANISM_DERIVED` mechanism.
    ///
    /// `base_id` is the ID of the key that will be used to derive the new key. The key must have been created / imported
    /// with the [`crate::AZIOT_KEYS_KEY_USAGE_DERIVE`] usage.
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
    ) -> crate::AZIOT_KEYS_RC,

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
        mechanism: crate::AZIOT_KEYS_SIGN_MECHANISM,
        parameters: *const std::ffi::c_void,
        digest: *const std::os::raw::c_uchar,
        digest_len: usize,
        signature: *mut std::os::raw::c_uchar,
        signature_len: *mut usize,
    ) -> crate::AZIOT_KEYS_RC,

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
        mechanism: crate::AZIOT_KEYS_SIGN_MECHANISM,
        parameters: *const std::ffi::c_void,
        digest: *const std::os::raw::c_uchar,
        digest_len: usize,
        signature: *const std::os::raw::c_uchar,
        signature_len: usize,
        ok: *mut std::os::raw::c_int,
    ) -> crate::AZIOT_KEYS_RC,

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
        mechanism: crate::AZIOT_KEYS_ENCRYPT_MECHANISM,
        parameters: *const std::ffi::c_void,
        plaintext: *const std::os::raw::c_uchar,
        plaintext_len: usize,
        ciphertext: *mut std::os::raw::c_uchar,
        ciphertext_len: *mut usize,
    ) -> crate::AZIOT_KEYS_RC,

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
        mechanism: crate::AZIOT_KEYS_ENCRYPT_MECHANISM,
        parameters: *const std::ffi::c_void,
        ciphertext: *const std::os::raw::c_uchar,
        ciphertext_len: usize,
        plaintext: *mut std::os::raw::c_uchar,
        plaintext_len: *mut usize,
    ) -> crate::AZIOT_KEYS_RC,
}

#[cfg(any())]
#[no_mangle]
pub extern "C" fn cbindgen_unused_AZIOT_KEYS_FUNCTION_LIST_2_1_0_0(
) -> AZIOT_KEYS_FUNCTION_LIST_2_1_0_0 {
    unimplemented!();
}
