/* Copyright (c) Microsoft. All rights reserved. */

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

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
