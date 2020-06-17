#include <openssl/crypto.h>

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#include <openssl/ec.h>
#else
#include <openssl/ecdsa.h>
#endif

#include <openssl/engine.h>

#include <openssl/rsa.h>

/**
 * The *_get_ex_new_index functions are defined as functions in 1.0.0 and as macros in 1.1.0,
 * so invoke them from C instead of creating complicated bindings.
 */

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
int ks_dupf_engine_ex_data(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from, void *from_d, int idx, long argl, void *argp);
#else
int ks_dupf_engine_ex_data(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from, void *from_d, int idx, long argl, void *argp);
#endif
void ks_freef_engine_ex_data(void* parent, void* ptr, CRYPTO_EX_DATA* ad, int idx, long argl, void* argp);

int ks_get_engine_ex_index() {
	return ENGINE_get_ex_new_index(0, NULL, NULL, ks_dupf_engine_ex_data, ks_freef_engine_ex_data);
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
int ks_dupf_ec_key_ex_data(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from, void *from_d, int idx, long argl, void *argp);
#else
int ks_dupf_ec_key_ex_data(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from, void *from_d, int idx, long argl, void *argp);
#endif
void ks_freef_ec_key_ex_data(void* parent, void* ptr, CRYPTO_EX_DATA* ad, int idx, long argl, void* argp);

int ks_get_ec_key_ex_index() {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	return EC_KEY_get_ex_new_index(0, NULL, NULL, ks_dupf_ec_key_ex_data, ks_freef_ec_key_ex_data);
#else
	return ECDSA_get_ex_new_index(0, NULL, NULL, ks_dupf_ec_key_ex_data, ks_freef_ec_key_ex_data);
#endif
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
int ks_dupf_rsa_ex_data(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from, void *from_d, int idx, long argl, void *argp);
#else
int ks_dupf_rsa_ex_data(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from, void *from_d, int idx, long argl, void *argp);
#endif
void ks_freef_rsa_ex_data(void* parent, void* ptr, CRYPTO_EX_DATA* ad, int idx, long argl, void* argp);

int ks_get_rsa_ex_index() {
	return RSA_get_ex_new_index(0, NULL, NULL, ks_dupf_rsa_ex_data, ks_freef_rsa_ex_data);
}
