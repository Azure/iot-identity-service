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

