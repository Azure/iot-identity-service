#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

// Defined as macros, so wrap them in functions

int EVP_PKEY_CTX_get_signature_md_f(EVP_PKEY_CTX *ctx, EVP_MD **pmd) {
	return EVP_PKEY_CTX_get_signature_md(ctx, pmd);
}

int EVP_PKEY_CTX_get_rsa_mgf1_md_f(EVP_PKEY_CTX *ctx, EVP_MD **pmd) {
	return EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, pmd);
}

int EVP_PKEY_CTX_get_rsa_pss_saltlen_f(EVP_PKEY_CTX *ctx, int *plen) {
	return EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, plen);
}


#if OPENSSL_VERSION_NUMBER < 0x10100000L

RSA_METHOD *RSA_meth_dup(
	const RSA_METHOD *meth
) {
	// Manually memcpy meth into a new RSA_METHOD.
	// The only caveat is meth->name which is a char*, so needs to be strdup'd.

	RSA_METHOD* result = OPENSSL_malloc(sizeof(RSA_METHOD));
	if (result == NULL) {
		return NULL;
	}

	const char* result_name = OPENSSL_strdup(meth->name);
	if (result_name == NULL) {
		OPENSSL_free(result);
		return NULL;
	}

	memcpy(result, meth, sizeof(RSA_METHOD));
	result->name = result_name;

	return result;
}

int RSA_meth_set_flags(RSA_METHOD *meth, int flags) {
	meth->flags = flags;
	return 1;
}

int RSA_meth_set_priv_enc(
	RSA_METHOD *rsa,
	int (*priv_enc) (
		int flen,
		const unsigned char *from,
		unsigned char *to,
		RSA *rsa,
		int padding
	)
) {
	rsa->rsa_priv_enc = priv_enc;
	return 1;
}

int RSA_meth_set_priv_dec(
	RSA_METHOD *rsa,
	int (*priv_dec) (
		int flen,
		const unsigned char *from,
		unsigned char *to,
		RSA *rsa,
		int padding
	)
) {
	rsa->rsa_priv_dec = priv_dec;
	return 1;
}

#endif
