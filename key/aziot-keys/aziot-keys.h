/**
 * Copyright (c) Microsoft. All rights reserved.
 *
 * This header specifies the API used for libaziot-keys. This library is used to create and load keys by the Azure IoT Keys Service.
 *
 *
 * # API conventions
 *
 * All functions return an `unsigned int` to indicate success or failure. See the [`AZIOT_KEYS_RC`] type's docs for details about these constants.
 *
 * The only function exported by this library is [`aziot_keys_get_function_list`]. Call this function to get the version of the API
 * that this library exports, as well as the function pointers to the key operations. See its docs for more details.
 *
 * All calls to [`aziot_keys_get_function_list`] or any function in [`AZIOT_KEYS_FUNCTION_LIST`] are serialized, ie a function will not be called
 * while another function is running. However, it is not guaranteed that all function calls will be made from the same operating system thread.
 * Thus, implementations do not need to worry about locking to prevent concurrent access, but should also not store data in thread-local storage.
 */

#include <stdint.h>

/**
 * Represents the version of the API exported by this library.
 */
typedef unsigned int AZIOT_KEYS_VERSION;

/**
 * The base struct of all of function lists.
 */
typedef struct {
    /**
     * The version of the API represented in this function list.
     *
     * The specific subtype of `AZIOT_KEYS_FUNCTION_LIST` can be determined by inspecting this value.
     */
    AZIOT_KEYS_VERSION version;
} AZIOT_KEYS_FUNCTION_LIST;

/**
 * Return code of a function. This is a transparent wrapper around a `std::os::raw::c_uint` (`unsigned int`).
 *
 * One of the `AZIOT_KEYS_RC_ERR_*` constants.
 */
typedef unsigned int AZIOT_KEYS_RC;

/**
 * Used as the parameter type with `get_key_pair_parameter`.
 *
 * One of the `AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_*` constants.
 */
typedef unsigned int AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE;

/**
 * The usage of key being created with `create_key_if_not_exists` or
 * being imported with `import_key`.
 *
 * This is a bitflag type, so its values can be combined. But note that not all combinations of flags
 * are valid.
 */
typedef unsigned int AZIOT_KEYS_KEY_USAGE;

/**
 * The mechanism used with `sign` / `verify`.
 *
 * One of the `AZIOT_KEYS_SIGN_MECHANISM_*` constants.
 */
typedef unsigned int AZIOT_KEYS_SIGN_MECHANISM;

/**
 * The mechanism used with `encrypt` / `decrypt`.
 *
 * One of the `AZIOT_KEYS_ENCRYPT_MECHANISM_*` constants.
 */
typedef unsigned int AZIOT_KEYS_ENCRYPT_MECHANISM;

/**
 * The specific implementation of [`AZIOT_KEYS_FUNCTION_LIST`] for API version 2.0.0.0
 */
typedef struct {
    /**
     * The value of `base.version` must be [`AZIOT_KEYS_VERSION_2_0_0_0`].
     */
    AZIOT_KEYS_FUNCTION_LIST base;
    /**
     * Set a parameter on this library.
     *
     * `name` must not be `NULL`.
     * `value` may be `NULL`.
     *
     * The caller may free the name string after this method returns. If the implementation needs to hold on to it, it must make a copy.
     *
     * The interpretation of names and values depends on the implementation. A special case is for names that start with `preloaded_key:`,
     * such as `preloaded_key:foo`. This defines a user-provided association of the key ID "foo" with the location specified by `value`.
     * Any call that uses the key with ID "foo" must use the location specified by `value`. Note that this does not mean the key already exists
     * at that location; but it does mean that `create_key_if_not_exists` (for example) must create the key at that location and not any other.
     *
     * # Errors
     *
     * - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
     *   - `name` is `NULL`.
     *   - `name` is not recognized by this implementation, or invalid in some other way.
     *   - `value` is invalid.
     *
     * - `AZIOT_KEYS_RC_ERR_EXTERNAL`
     */
    AZIOT_KEYS_RC (*set_parameter)(const char *name, const char *value);
    /**
     * Create or load a key pair identified by the specified `id`.
     *
     * - If a key pair with that ID exists and can be loaded, it will be left as-is.
     * - If a key pair with that ID does not exist, a new key will be created. It will be saved such that it can be looked up later using that same ID.
     *
     * `preferred_algorithms` dictates the caller's preference for the key algorithm. It is a string with components separated by COLON U+003A `:`,
     * where each component specifies the name of an algorithm and will be attempted by the implementation in that order.
     * The valid components are `"ec-p256"` for secp256r1, `"rsa-2048"` for 2048-bit RSA, `"rsa-4096"` for 4096-bit RSA, and `"*"` which indicates
     * any algorithm of the implementation's choice. For example, the caller might use `"ec-p256:rsa-2048:*"` to indicate that it would like
     * the implementation to use secp256r1, else RSA-2048 if that fails, else any other algorithm of the implementation's choice if that also fails.
     *
     * If an implementation does not recognize a particular component as an algorithm, or is unable to use the algorithm to generate a key pair,
     * it must ignore that component and try the next one. If no components are left, the implementation returns an error.
     * The implementation is allowed to be unable to generate a key pair regardless of which algorithms are specified; this is true even if
     * the wildcard algorithm is specified.
     *
     * If `preferred_algorithms` is `NULL`, it must be interpreted the same as if it was `"*"`.
     *
     * # Errors
     *
     * - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
     *   - `id` is `NULL`.
     *   - `id` is invalid.
     *   - `preferred_algorithms` is invalid.
     *
     * - `AZIOT_KEYS_RC_ERR_EXTERNAL`
     */
    AZIOT_KEYS_RC (*create_key_pair_if_not_exists)(const char *id, const char *preferred_algorithms);
    /**
     * Load an existing key pair identified by the specified `id`.
     *
     * This validates that a key pair with the given ID exists and can be loaded.
     *
     * # Errors
     *
     * - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
     *   - `id` is `NULL`.
     *   - `id` is invalid.
     *
     * - `AZIOT_KEYS_RC_ERR_EXTERNAL`
     */
    AZIOT_KEYS_RC (*load_key_pair)(const char *id);
    /**
     * Get the value of a parameter of the key pair identified by the specified `id`.
     *
     * `type_` must be set to one of the `AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_*` constants.
     *
     * `value` is an output byte buffer allocated by the caller to store the parameter value.
     * The caller sets `value_len` to the address of the length of the buffer.
     * The implementation populates `value` with the parameter value and sets `value_len` to the number of bytes it wrote to `value`.
     *
     * It is allowed for the caller to call the function with `value` set to `NULL`. In this case the implementation calculates
     * an upper bound for how many bytes will be needed to store the parameter value, sets that in `value_len` and returns.
     *
     * The format of the data stored in `value` is determined by the `type_`. See the documentation of those constants for details.
     *
     * # Errors
     *
     * - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
     *   - `id` is `NULL`.
     *   - `id` is invalid.
     *   - The key pair specified by `id` does not exist.
     *   - `type_` is not a valid parameter type for the key pair specified by `id`.
     *   - `value` is insufficiently large to hold the parameter value.
     *   - `value_len` is `NULL`.
     *
     * - `AZIOT_KEYS_RC_ERR_EXTERNAL`
     */
    AZIOT_KEYS_RC (*get_key_pair_parameter)(const char *id, AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE type_, unsigned char *value, uintptr_t *value_len);
    /**
     * Create or load a key identified by the specified `id`.
     *
     * - If a key with that ID exists and can be loaded, it will be left as-is.
     * - If a key with that ID does not exist, a new random key will be created.
     *   It will be saved such that it can be looked up later using that same ID.
     *
     * `usage` specifies what the key will be used for.
     *
     * # Errors
     *
     * - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
     *   - `id` is `NULL`.
     *   - `id` is invalid.
     *
     * - `AZIOT_KEYS_RC_ERR_EXTERNAL`
     */
    AZIOT_KEYS_RC (*create_key_if_not_exists)(const char *id, AZIOT_KEYS_KEY_USAGE usage);
    /**
     * Load an existing key identified by the specified `id`.
     *
     * This validates that a key with the given ID exists and can be loaded.
     *
     * # Errors
     *
     * - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
     *   - `id` is `NULL`.
     *   - `id` is invalid.
     *   - The key specified by `id` does not exist.
     *
     * - `AZIOT_KEYS_RC_ERR_EXTERNAL`
     */
    AZIOT_KEYS_RC (*load_key)(const char *id);
    /**
     * Import a symmetric key with the given `id`.
     *
     * It will be saved such that it can be looked up later using that same ID.
     *
     * If a key with that ID already exists, the existing key will be overwritten.
     *
     * # Errors
     *
     * - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
     *   - `id` is `NULL`.
     *   - `id` is invalid.
     *   - `bytes` is `NULL`.
     *
     * - `AZIOT_KEYS_RC_ERR_EXTERNAL`
     */
    AZIOT_KEYS_RC (*import_key)(const char *id, const uint8_t *bytes, uintptr_t bytes_len, AZIOT_KEYS_KEY_USAGE usage);
    /**
     * Derive a key with a given base key using some derivation data, and return the derived key.
     *
     * The derivation process used by this function must be identical to
     * the derivation process used by `encrypt` with the `AZIOT_KEYS_ENCRYPT_MECHANISM_DERIVED` mechanism and
     * the derivation process used by `sign` with the `AZIOT_KEYS_SIGN_MECHANISM_DERIVED` mechanism.
     *
     * `base_id` is the ID of the key that will be used to derive the new key. The key must have been created / imported
     * with the [`AZIOT_KEYS_KEY_USAGE_DERIVE`] usage.
     *
     * `derivation_data` is a byte buffer containing the data that used for the derivation.
     * The caller sets `derivation_data_len` to the length of the buffer.
     *
     * `derived_key` is an output byte buffer allocated by the caller to store the derived key.
     * The caller sets `derived_key_len` to the address of the length of the buffer.
     * The implementation populates `derived_key` with the parameter derived_key and sets `derived_key_len` to the number of bytes it wrote to `derived_key`.
     *
     * It is allowed for the caller to call the function with `derived_key` set to `NULL`. In this case the implementation calculates
     * an upper bound for how many bytes will be needed to store the derived key, sets that in `derived_key_len` and returns.
     *
     * The new key is not persisted by the implementation, only returned in `derived_key`.
     * If the caller wishes to persist it, they can import it with `import_key`.
     *
     * # Errors
     *
     * - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
     *   - `base_id` is `NULL`.
     *   - `base_id` is invalid.
     *   - The key specified by `base_id` does not exist.
     *   - `derivation_data` is `NULL`.
     *   - `derived_key` is insufficiently large to hold the parameter value.
     *   - `derived_key_len` is `NULL`.
     *
     * - `AZIOT_KEYS_RC_ERR_EXTERNAL`
     */
    AZIOT_KEYS_RC (*derive_key)(const char *base_id, const uint8_t *derivation_data, uintptr_t derivation_data_len, unsigned char *derived_key, uintptr_t *derived_key_len);
    /**
     * Sign the given digest using the key or key pair identified by the specified `id`.
     *
     * `mechanism` must be set to one of the `AZIOT_KEYS_SIGN_MECHANISM_*` constants.
     * `parameters` must be set according to the `mechanism`, as documented on the constants.
     *
     * `digest` is a byte buffer containing the data that must be signed.
     * The caller sets `digest_len` to the length of the buffer.
     *
     * `signature` is an output byte buffer allocated by the caller to store the signature.
     * The caller sets `signature_len` to the address of the length of the buffer.
     * The implementation populates `signature` with the signature and sets `signature_len` to the number of bytes it wrote to `signature`.
     *
     * It is allowed for the caller to call the function with `signature` set to `NULL`. In this case the implementation calculates
     * an upper bound for how many bytes will be needed to store the signature, sets that in `signature_len` and returns.
     *
     * # Errors
     *
     * - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
     *   - `id` is `NULL`.
     *   - `id` is invalid.
     *   - The key or key pair specified by `id` does not exist.
     *   - `mechanism` is not a valid signature mechanism for the key or key pair specified by `id`.
     *   - `parameters` is invalid.
     *   - `digest` is `NULL`.
     *   - `signature` is insufficiently large to hold the signature.
     *   - `signature_len` is `NULL`.
     *
     * - `AZIOT_KEYS_RC_ERR_EXTERNAL`
     */
    AZIOT_KEYS_RC (*sign)(const char *id, AZIOT_KEYS_SIGN_MECHANISM mechanism, const void *parameters, const unsigned char *digest, uintptr_t digest_len, unsigned char *signature, uintptr_t *signature_len);
    /**
     * Verify the signature of the given digest using the key or key pair (but see note below) identified by the specified `id`.
     *
     * `mechanism` must be set to one of the `AZIOT_KEYS_SIGN_MECHANISM_*` constants.
     * `parameters` must be set according to the `mechanism`, as documented on the constants.
     *
     * `digest` is a byte buffer containing the data that must be signed.
     * The caller sets `digest_len` to the length of the buffer.
     *
     * `signature` is a byte buffer containing the signature that the caller expects the data to have.
     * The caller sets `signature_len` to the length of the buffer.
     *
     * `ok` is an output parameter that stores whether the signature could be verified or not.
     * If the function is able to compute the signature of the data, it sets `ok` and returns `AZIOT_KEYS_RC_OK`.
     * `ok` is set to 0 if the signature is invalid and non-zero if the signature is valid.
     * The value stored in `ok` is only meaningful if the function returns `AZIOT_KEYS_RC_OK`, otherwise it must be ignored.
     *
     * Note: The implementation is not required to support verification with key pairs, ie `AZIOT_KEYS_SIGN_MECHANISM_ECDSA`.
     * The caller can do the verification themselves with the public parameters of the EC key as obtained via `get_key_pair_parameter`.
     *
     * # Errors
     *
     * - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
     *   - `id` is `NULL`.
     *   - `id` is invalid.
     *   - The key or key pair specified by `id` does not exist.
     *   - `mechanism` is not a valid signature mechanism for the key or key pair specified by `id`.
     *   - `parameters` is invalid.
     *   - `digest` is `NULL`.
     *   - `signature` is `NULL`.
     *   - `ok` is `NULL`.
     *
     * - `AZIOT_KEYS_RC_ERR_EXTERNAL`
     */
    AZIOT_KEYS_RC (*verify)(const char *id, AZIOT_KEYS_SIGN_MECHANISM mechanism, const void *parameters, const unsigned char *digest, uintptr_t digest_len, const unsigned char *signature, uintptr_t signature_len, int *ok);
    /**
     * Encrypt the given plaintext using the key or key pair identified by the specified `id`.
     *
     * `mechanism` must be set to one of the `AZIOT_KEYS_ENCRYPT_MECHANISM_*` constants.
     * `parameters` must be set according to the `mechanism`, as documented on the constants.
     *
     * `plaintext` is a byte buffer containing the data that must be encrypted.
     * The caller sets `plaintext_len` to the length of the buffer.
     *
     * `ciphertext` is an output byte buffer allocated by the caller to store the encrypted data.
     * The caller sets `ciphertext_len` to the address of the length of the buffer.
     * The implementation populates `ciphertext` with the ciphertext and sets `ciphertext_len` to the number of bytes it wrote to `ciphertext`.
     *
     * It is allowed for the caller to call the function with `ciphertext` set to `NULL`. In this case the implementation calculates
     * an upper bound for how many bytes will be needed to store the ciphertext, sets that in `ciphertext_len` and returns.
     *
     * # Errors
     *
     * - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
     *   - `id` is `NULL`.
     *   - `id` is invalid.
     *   - The key or key pair specified by `id` does not exist.
     *   - `mechanism` is not a valid encryption mechanism for the key or key pair specified by `id`.
     *   - `parameters` is invalid.
     *   - `plaintext` is `NULL`.
     *   - `ciphertext` is insufficiently large to hold the ciphertext.
     *   - `ciphertext_len` is `NULL`.
     *
     * - `AZIOT_KEYS_RC_ERR_EXTERNAL`
     */
    AZIOT_KEYS_RC (*encrypt)(const char *id, AZIOT_KEYS_ENCRYPT_MECHANISM mechanism, const void *parameters, const unsigned char *plaintext, uintptr_t plaintext_len, unsigned char *ciphertext, uintptr_t *ciphertext_len);
    /**
     * Decrypt the given plaintext using the key or key pair identified by the specified `id`.
     *
     * `mechanism` must be set to one of the `AZIOT_KEYS_ENCRYPT_MECHANISM_*` constants.
     * `parameters` must be set according to the `mechanism`, as documented on the constants.
     *
     * `ciphertext` is a byte buffer containing the data that must be signed.
     * The caller sets `ciphertext_len` to the length of the buffer.
     *
     * `plaintext` is an output byte buffer allocated by the caller to store the decrypted data.
     * The caller sets `plaintext_len` to the address of the length of the buffer.
     * The implementation populates `plaintext` with the plaintext and sets `plaintext_len` to the number of bytes it wrote to `plaintext`.
     *
     * It is allowed for the caller to call the function with `plaintext` set to `NULL`. In this case the implementation calculates
     * an upper bound for how many bytes will be needed to store the plaintext, sets that in `plaintext_len` and returns.
     *
     * # Errors
     *
     * - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
     *   - `id` is `NULL`.
     *   - `id` is invalid.
     *   - The key or key pair specified by `id` does not exist.
     *   - `mechanism` is not a valid encryption mechanism for the key or key pair specified by `id`.
     *   - `parameters` is invalid.
     *   - `ciphertext` is `NULL`.
     *   - `plaintext` is insufficiently large to hold the ciphertext.
     *   - `plaintext_len` is `NULL`.
     *
     * - `AZIOT_KEYS_RC_ERR_EXTERNAL`
     */
    AZIOT_KEYS_RC (*decrypt)(const char *id, AZIOT_KEYS_ENCRYPT_MECHANISM mechanism, const void *parameters, const unsigned char *ciphertext, uintptr_t ciphertext_len, unsigned char *plaintext, uintptr_t *plaintext_len);
} AZIOT_KEYS_FUNCTION_LIST_2_0_0_0;

/**
 * Used with `sign` / `verify` with the [`AZIOT_KEYS_SIGN_MECHANISM_DERIVED`] mechanism.
 */
typedef struct {
    /**
     * The data used to derive the new key.
     */
    const unsigned char *derivation_data;
    /**
     * The length of the `derivation_data` buffer.
     */
    uintptr_t derivation_data_len;
    /**
     * The signature mechanism to use with the derived key.
     *
     * One of the `AZIOT_KEYS_SIGN_MECHANISM_*` constants.
     */
    AZIOT_KEYS_SIGN_MECHANISM mechanism;
    /**
     * The parameters of the signature mechanism specified by `mechanism`.
     */
    const void *parameters;
} AZIOT_KEYS_SIGN_DERIVED_PARAMETERS;

/**
 * Used with `encrypt` / `decrypt` with the [`AZIOT_KEYS_ENCRYPT_MECHANISM_AEAD`] mechanism.
 */
typedef struct {
    /**
     * The IV.
     */
    const unsigned char *iv;
    /**
     * The length of the `iv` buffer.
     */
    uintptr_t iv_len;
    /**
     * The AAD.
     */
    const unsigned char *aad;
    /**
     * The length of the `aad` buffer.
     */
    uintptr_t aad_len;
} AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS;

/**
 * Used with `encrypt` / `decrypt` with the [`AZIOT_KEYS_ENCRYPT_MECHANISM_DERIVED`] mechanism.
 */
typedef struct {
    /**
     * The data used to derive the new key.
     */
    const unsigned char *derivation_data;
    /**
     * The length of the `derivation_data` buffer.
     */
    uintptr_t derivation_data_len;
    /**
     * The encryption mechanism to use with the derived key.
     *
     * One of the `AZIOT_KEYS_ENCRYPT_MECHANISM_*` constants.
     */
    AZIOT_KEYS_ENCRYPT_MECHANISM mechanism;
    /**
     * The parameters of the encryption mechanism specified by `mechanism`.
     */
    const void *parameters;
} AZIOT_KEYS_ENCRYPT_DERIVED_PARAMETERS;

/**
 * The algorithm of a key pair, as returned by `get_key_pair_parameter`.
 *
 * One of the `AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM_*` constants.
 */
typedef unsigned int AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM;

/**
 * The operation succeeded.
 */
#define AZIOT_KEYS_RC_OK 0

/**
 * The operation failed because a parameter has an invalid value.
 */
#define AZIOT_KEYS_RC_ERR_INVALID_PARAMETER 1

/**
 * The library encountered an error with an external resource, such as an I/O error or RPC error.
 */
#define AZIOT_KEYS_RC_ERR_EXTERNAL 2

/**
 * Version 2.0.0.0
 */
#define AZIOT_KEYS_VERSION_2_0_0_0 33554432

/**
 * Used as the parameter type with `get_key_pair_parameter` to get the key algorithm.
 *
 * The value returned by `get_key_pair_parameter` will be one of the `AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM_*` constants.
 */
#define AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_ALGORITHM 1

/**
 * Used as the parameter type with `get_key_pair_parameter` to get the curve OID of an EC key.
 *
 * The value returned by `get_key_pair_parameter` will be a byte buffer containing a DER-encoded OID.
 */
#define AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_EC_CURVE_OID 2

/**
 * Used as the parameter type with `get_key_pair_parameter` to get the point of an EC key.
 *
 * The value returned by `get_key_pair_parameter` will be a byte buffer containing a DER-encoded octet string in RFC 5490 format.
 */
#define AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_EC_POINT 3

/**
 * Used as the parameter type with `get_key_pair_parameter` to get the modulus of an RSA key.
 *
 * The value returned by `get_key_pair_parameter` will be a byte buffer holding a big-endian bignum.
 */
#define AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_RSA_MODULUS 4

/**
 * Used as the parameter type with `get_key_pair_parameter` to get the exponent of an RSA key.
 *
 * The value returned by `get_key_pair_parameter` will be a byte buffer holding a big-endian bignum.
 */
#define AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_RSA_EXPONENT 5

/**
 * The key pair is an EC key.
 */
#define AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM_EC 1

/**
 * The key pair is an RSA key.
 */
#define AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM_RSA 2

/**
 * The key can be used for deriving other keys.
 *
 * Cannot be combined with [`AZIOT_KEYS_KEY_USAGE_ENCRYPT`]
 */
#define AZIOT_KEYS_KEY_USAGE_DERIVE 1

/**
 * The key can be used for encryption.
 *
 * Cannot be combined with [`AZIOT_KEYS_KEY_USAGE_DERIVE`] or [`AZIOT_KEYS_KEY_USAGE_SIGN`]
 */
#define AZIOT_KEYS_KEY_USAGE_ENCRYPT 16

/**
 * The key can be used for signing.
 *
 * Cannot be combined with [`AZIOT_KEYS_KEY_USAGE_ENCRYPT`]
 */
#define AZIOT_KEYS_KEY_USAGE_SIGN AZIOT_KEYS_KEY_USAGE_DERIVE

/**
 * Used with `sign` / `verify` to sign / verify using ECDSA.
 *
 * The `parameters` parameter of `sign` / `verify` is unused and ignored.
 */
#define AZIOT_KEYS_SIGN_MECHANISM_ECDSA 1

/**
 * Used with `sign` / `verify` to sign / verify using HMAC-SHA256.
 *
 * The `parameters` parameter of `sign` / `verify` is unused and ignored.
 */
#define AZIOT_KEYS_SIGN_MECHANISM_HMAC_SHA256 2

/**
 * Used with `sign` / `verify` to sign / verify using a derived key.
 *
 * The `id` parameter of `sign` / `verify` is set to the ID of the base key.
 * The `parameters` parameter of `sign` / `verify` must be set to an `AZIOT_KEYS_SIGN_DERIVED_PARAMETERS` value.
 */
#define AZIOT_KEYS_SIGN_MECHANISM_DERIVED 3

/**
 * Used with `encrypt` / `decrypt` to encrypt / decrypt using an AEAD mechanism, like AES-GCM.
 *
 * The exact AEAD algorithm used is left to the implementation and need not always be the same.
 * The caller must not make any assumptions about the format of the ciphertext.
 *
 * The `parameters` parameter of `encrypt` / `decrypt` must be set to an `AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS` value.
 */
#define AZIOT_KEYS_ENCRYPT_MECHANISM_AEAD 1

/**
 * Used with `encrypt` / `decrypt` to encrypt / decrypt using RSA with PKCS1 padding.
 *
 * The `parameters` parameter of `encrypt` / `decrypt` is unused and ignored.
 */
#define AZIOT_KEYS_ENCRYPT_MECHANISM_RSA_PKCS1 2

/**
 * Used with `encrypt` / `decrypt` to encrypt / decrypt using RSA with no padding. Padding will have been performed by the caller.
 *
 * The `parameters` parameter of `encrypt` / `decrypt` is unused and ignored.
 */
#define AZIOT_KEYS_ENCRYPT_MECHANISM_RSA_NO_PADDING 3

/**
 * Used with `encrypt` / `decrypt` to encrypt / decrypt using a derived key.
 *
 * The `id` parameter of `encrypt` / `decrypt` is set to the ID of the base key.
 * The `parameters` parameter of `encrypt` / `decrypt` must be set to an `AZIOT_KEYS_ENCRYPT_DERIVED_PARAMETERS` value.
 */
#define AZIOT_KEYS_ENCRYPT_MECHANISM_DERIVED 4


/**
 * Get the list of functions for operations corresponding to the specified version.
 *
 * Implementations can use this function for initialization, since it is guaranteed to be called before any operations.
 * However it is not an error to call this function multiple times, for the same or different version,
 * so implementations must ensure they only run their initialization once.
 *
 * The pointer returned from this function must not be freed by the caller, and its contents must not be mutated.
 *
 * # Errors
 *
 * - `AZIOT_KEYS_RC_ERR_INVALID_PARAMETER`:
 *   - `version` is not recognized by this implementation.
 *   - `pfunction_list` is `NULL`.
 */
AZIOT_KEYS_RC aziot_keys_get_function_list(AZIOT_KEYS_VERSION version,
                                           const AZIOT_KEYS_FUNCTION_LIST **pfunction_list);



