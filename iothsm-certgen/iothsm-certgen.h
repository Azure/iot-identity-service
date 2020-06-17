/**
 * This header specifies the API used for libiothsm-certgen. This library is used to create and load certificates for the Azure IoT Edge daemon.
 *
 *
 * # API conventions
 *
 * All functions return a `unsigned int` to indicate success or failure. See the [`CERTGEN_ERROR`] type's docs for details about these constants.
 *
 * The only function exported by a certgen library is [`CERTGEN_get_function_list`]. Call this function to get the version of the certgen API
 * that this library exports, as well as the function pointers to the certgen operations. See its docs for more details.
 *
 * All calls to [`CERTGEN_get_function_list`] or any function in [`CERTGEN_FUNCTION_LIST`] are serialized, ie a function will not be called
 * while another function is running. However, it is not guaranteed that all function calls will be made from the same operating system thread.
 * Thus, implementations do not need to worry about locking to prevent concurrent access, but should also not store data in thread-local storage.
 */

#include <openssl/ossl_typ.h>

/**
 * Error type. This is a transparent wrapper around a `std::os::raw::c_uint` (`unsigned int`).
 *
 * Either `CERTGEN_SUCCESS` or one of the `CERTGEN_ERROR_*` constants.
 */
typedef unsigned int CERTGEN_ERROR;

/**
 * Represents the version of the certgen API exported by this library.
 */
typedef unsigned int CERTGEN_VERSION;

/**
 * The kind of cert that is being requested.
 *
 * One of the `CERTGEN_CERT_KIND_*` constants.
 */
typedef unsigned int CERTGEN_CERT_KIND;

/**
 * The specific implementation of [`CERTGEN_FUNCTION_LIST`] for API version 2.0.0.0
 */
typedef struct {
    /**
     * The version of the certgen API exported by this library.
     *
     * For the `CERTGEN_FUNCTION_LIST_2_0_0_0` type, the value must be [`CERTGEN_VERSION_2_0_0_0`].
     */
    CERTGEN_VERSION version;
    /**
     * Set a parameter on this library.
     *
     * `name` must not be `NULL`.
     * `value` may be `NULL`.
     *
     * The caller may free the name string after this method returns. If the implementation needs to hold on to it, it must make a copy.
     *
     * The interpretation of names and values depends on the implementation.
     *
     * # Errors
     *
     * - `CERTGEN_ERROR_INVALID_PARAMETER`:
     *   - `name` is `NULL`.
     *   - `name` is not recognized by this implementation.
     *   - `value` is invalid.
     *
     * - `CERTGEN_ERROR_FATAL`
     */
    CERTGEN_ERROR (*set_parameter)(const char *name, const char *value);
    /**
     * Create or load a cert of the specified `kind`.
     *
     * - If `uri` is `NULL`:
     *   - If the implementation can generated a new signed cert (including the case where it decides to create a self-signed cert),
     *     it does so and saves at a location of the implementation's choice. It returns this cert in `pcert`.
     *   - Otherwise the implementation generates an unsigned cert. It returns this cert in `pcert`. The unsigned cert is not persisted anywhere.
     *
     * - If `uri` is not `NULL` and a cert exists at that URI, the implementation returns the cert in `pcert`.
     *
     * - If `uri` is not `NULL` and a cert does not exist at that URI:
     *   - If the implementation can generated a new signed cert (including the case where it decides to create a self-signed cert),
     *     it does so and saves it such that it can be looked up again later using that same URI. It returns this cert in `pcert`.
     *   - Otherwise the implementation generates an unsigned cert. It returns this cert in `pcert`. The unsigned cert is not persisted anywhere.
     *
     * Note again that the implementation must not persist unsigned certs such that future calls to `create_or_load_key` return
     * previously-created unsigned certs.
     *
     * The interpretation of a URI depends on the implementation. This library understands `file` URIs.
     *
     * In the case where the implementation needs to create a new cert, whether it can produce signed certificates or only unsigned ones depends on
     * the implementation. This library only produces self-signed certs for the Device CA kind, and unsigned certs for all other kinds.
     *
     * If the implementation returns an unsigned cert, it is the caller's job to sign it with a signer of its choice.
     * The signed cert can be imported back into the certgen implementation using [`import`]. If the caller specified a URI for `create_or_load_cert`,
     * it will almost certainly want to use the same URI for `import`, because it will need to use the URI given to `import` with `create_or_load_cert` later
     * when it wants to load the cert again.
     *
     * `public_key` and `private_key` are the keys to be used for creating a new cert. `private_key` would only get used if the implementation wants to make
     * a self-signed cert, but it is still required.
     *
     * # Errors
     *
     * - `CERTGEN_ERROR_INVALID_PARAMETER`:
     *   - `kind` is not recognized by this implementation, or the implementation does not support generating certs of this kind.
     *   - `uri` is not recognized by this implementation, or is invalid in some other way.
     *   - `public_key` is `NULL`.
     *   - `private_key` is `NULL`.
     *   - `pcert` is `NULL`.
     */
    CERTGEN_ERROR (*create_or_load_cert)(CERTGEN_CERT_KIND kind, const char *uri, EVP_PKEY *public_key, EVP_PKEY *private_key, X509 **pcert);
    /**
     * Import a cert of the specified `kind`.
     *
     * - If `uri` is `NULL`, then the cert will be saved at a location of the implementation's choice. This must be consistent with the choice
     *   made in [`create_or_load_cert`].
     * - If `uri` is not `NULL`, the cert will be saved such that it can be looked up later using [`create_or_load_cert`] with that same URI.
     *   If a cert already exists at the URI, it is overwritten.
     *
     * The interpretation of a URI depends on the implementation. This library understands `file` URIs.
     *
     * # Errors
     *
     * - `CERTGEN_ERROR_INVALID_PARAMETER`:
     *   - `kind` is not recognized by this implementation.
     *   - `uri` is not recognized by this implementation, or is invalid in some other way.
     *   - `cert` is `NULL`.
     */
    CERTGEN_ERROR (*import_cert)(CERTGEN_CERT_KIND kind, const char *uri, X509 *cert);
    /**
     * Delete a cert of the specified `kind`.
     *
     * If `uri` is `NULL`, then the cert's location will be determined by the implementation. This must be consistent with the choice
     * made in [`create_or_load_cert`].
     *
     * The interpretation of a URI depends on the implementation. This library understands `file` URIs.
     *
     * # Errors
     *
     * - `CERTGEN_ERROR_INVALID_PARAMETER`:
     *   - `kind` is not recognized by this implementation.
     *   - `uri` is not recognized by this implementation, or is invalid in some other way.
     */
    CERTGEN_ERROR (*delete_cert)(CERTGEN_CERT_KIND kind, const char *uri);
} CERTGEN_FUNCTION_LIST_2_0_0_0;

/**
 * The latest version of the certgen API defined in this header.
 *
 * Returned by [`CERTGEN_get_function_list`]
 */
typedef CERTGEN_FUNCTION_LIST_2_0_0_0 CERTGEN_FUNCTION_LIST;

/**
 * A device CA cert.
 */
#define CERTGEN_CERT_KIND_DEVICE_CA 2

/**
 * A device identity cert.
 */
#define CERTGEN_CERT_KIND_DEVICE_ID 1

/**
 * A module server cert.
 */
#define CERTGEN_CERT_KIND_MODULE_SERVER 4

/**
 * A workload CA cert.
 */
#define CERTGEN_CERT_KIND_WORKLOAD_CA 3

/**
 * The library encountered an error with an external resource, such as an I/O error or RPC error.
 */
#define CERTGEN_ERROR_EXTERNAL 3

/**
 * The library encountered an unrecoverable error. The process should exit as soon as possible.
 */
#define CERTGEN_ERROR_FATAL 1

/**
 * The operation failed because a parameter has an invalid value.
 */
#define CERTGEN_ERROR_INVALID_PARAMETER 2

/**
 * The operation succeeded.
 */
#define CERTGEN_SUCCESS 0

/**
 * Version 2.0.0.0
 */
#define CERTGEN_VERSION_2_0_0_0 33554432

/**
 * Get the list of functions for certgen operations.
 *
 * Implementations can use this function for initialization, since it is guaranteed to be called before any certgen operations.
 * However it is not an error to call this function multiple times, so implementations must ensure they only run their initialization once.
 *
 * The pointer returned from this function must not be freed by the caller, and its contents must not be mutated.
 */
CERTGEN_ERROR CERTGEN_get_function_list(const CERTGEN_FUNCTION_LIST **pfunction_list);
