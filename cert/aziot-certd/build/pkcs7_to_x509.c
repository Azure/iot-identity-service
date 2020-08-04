/* Copyright (c) Microsoft. All rights reserved. */

#include <openssl/objects.h>
#include <openssl/pkcs7.h>

/**
 * Extracts the X509 stack from a PKCS7 object.
 *
 * This is done in C since the Rust openssl and openssl-sys crates don't expose functions for this, and
 * doing it ourselves would require generating bindings for a lot of types.
 */
const struct stack_st_X509 *aziot_certd_pkcs7_to_x509(const PKCS7 *pkcs7) {
	const struct stack_st_X509 *cert_stack = NULL;

	if (OBJ_obj2nid(pkcs7->type) == NID_pkcs7_signed) {
		cert_stack = pkcs7->d.sign->cert;
	}

	return cert_stack;
}
