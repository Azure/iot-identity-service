// Copyright (c) Microsoft. All rights reserved.

/// A reference to an object stored in a slot.
pub struct Object<T> {
    session: std::sync::Arc<crate::Session>,
    handle: pkcs11_sys::CK_OBJECT_HANDLE,
    _key: std::marker::PhantomData<T>,
}

impl<T> Object<T> {
    pub(crate) fn new(
        session: std::sync::Arc<crate::Session>,
        handle: pkcs11_sys::CK_OBJECT_HANDLE,
    ) -> Self {
        Object {
            session,
            handle,
            _key: Default::default(),
        }
    }
}

impl Object<()> {
    /// Use this key to sign the given digest and store the result into the given signature buffer.
    pub fn sign(
        &self,
        digest: &[u8],
        signature: &mut [u8],
    ) -> Result<pkcs11_sys::CK_ULONG, SignError> {
        unsafe {
            // Signing with the key needs login
            self.session.login().map_err(SignError::LoginFailed)?;

            let signature_len = sign_inner(
                &self.session,
                self.handle,
                pkcs11_sys::CKM_SHA256_HMAC,
                digest,
                signature,
            )?;
            Ok(signature_len)
        }
    }
}

impl Object<()> {
    /// Use this key to verify the given digest has the given signature.
    pub fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, VerifyError> {
        unsafe {
            // Verifying with the key needs login
            self.session.login().map_err(VerifyError::LoginFailed)?;

            let ok = verify_inner(
                &self.session,
                self.handle,
                pkcs11_sys::CKM_SHA256_HMAC,
                digest,
                signature,
            )?;
            Ok(ok)
        }
    }
}

impl Object<()> {
    pub fn encrypt(
        &self,
        iv: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<pkcs11_sys::CK_ULONG, EncryptError> {
        unsafe {
            // Encrypting with the key needs login
            self.session.login().map_err(EncryptError::LoginFailed)?;

            let iv_len = std::convert::TryInto::try_into(iv.len()).expect("usize -> CK_ULONG");

            let params = pkcs11_sys::CK_GCM_PARAMS {
                pIv: iv.as_ptr(),
                ulIvLen: iv_len,
                ulIvBits: iv_len * 8,
                pAAD: aad.as_ptr(),
                ulAADLen: std::convert::TryInto::try_into(aad.len()).expect("usize -> CK_ULONG"),
                ulTagBits: 16 * 8,
            };
            let mechanism = pkcs11_sys::CK_MECHANISM_IN {
                mechanism: pkcs11_sys::CKM_AES_GCM,
                pParameter: &params as *const _ as _,
                ulParameterLen: std::convert::TryInto::try_into(std::mem::size_of_val(&params))
                    .expect("usize -> CK_ULONG"),
            };

            let ciphertext_len = encrypt_inner(
                &self.session,
                self.handle,
                &mechanism,
                plaintext,
                ciphertext,
            )?;
            Ok(ciphertext_len)
        }
    }
}

impl Object<()> {
    pub fn decrypt(
        &self,
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<pkcs11_sys::CK_ULONG, DecryptError> {
        unsafe {
            // Decrypting with the key needs login
            self.session.login().map_err(DecryptError::LoginFailed)?;

            let iv_len = std::convert::TryInto::try_into(iv.len()).expect("usize -> CK_ULONG");

            let params = pkcs11_sys::CK_GCM_PARAMS {
                pIv: iv.as_ptr(),
                ulIvLen: iv_len,
                ulIvBits: iv_len * 8,
                pAAD: aad.as_ptr(),
                ulAADLen: std::convert::TryInto::try_into(aad.len()).expect("usize -> CK_ULONG"),
                ulTagBits: 16 * 8,
            };
            let mechanism = pkcs11_sys::CK_MECHANISM_IN {
                mechanism: pkcs11_sys::CKM_AES_GCM,
                pParameter: &params as *const _ as _,
                ulParameterLen: std::convert::TryInto::try_into(std::mem::size_of_val(&params))
                    .expect("usize -> CK_ULONG"),
            };

            let plaintext_len = decrypt_inner(
                &self.session,
                self.handle,
                &mechanism,
                ciphertext,
                plaintext,
            )?;
            Ok(plaintext_len)
        }
    }
}

impl Object<openssl::ec::EcKey<openssl::pkey::Public>> {
    /// Get the EC parameters of this EC public key object.
    pub fn parameters(
        &self,
    ) -> Result<openssl::ec::EcKey<openssl::pkey::Public>, GetKeyParametersError> {
        unsafe {
            let curve = get_attribute_value_byte_buf(
                &self.session,
                self,
                pkcs11_sys::CKA_EC_PARAMS,
                self.session.context.C_GetAttributeValue,
            )?;
            let curve = openssl2::EcCurve::from_oid_der(&curve)
                .ok_or(GetKeyParametersError::UnrecognizedEcCurve(curve))?;
            let curve = curve.as_nid();
            let mut group = openssl::ec::EcGroup::from_curve_name(curve)
                .map_err(GetKeyParametersError::ConvertToOpenssl)?;

            group.set_asn1_flag(openssl::ec::Asn1Flag::NAMED_CURVE);

            // CKA_EC_POINT returns a DER encoded octet string representing the point.
            //
            // The octet string is in the RFC 5480 format which is exactly what EC_POINT_oct2point expected, so we just need to strip the DER type and length prefix.
            let point = get_attribute_value_byte_buf(
                &self.session,
                self,
                pkcs11_sys::CKA_EC_POINT,
                self.session.context.C_GetAttributeValue,
            )?;
            let point = openssl_sys2::d2i_ASN1_OCTET_STRING(
                std::ptr::null_mut(),
                &mut (point.as_ptr() as _),
                std::convert::TryInto::try_into(point.len()).expect("usize -> c_long"),
            );
            if point.is_null() {
                return Err(GetKeyParametersError::MalformedEcPoint(
                    openssl::error::ErrorStack::get(),
                ));
            }
            let point: openssl::asn1::Asn1String =
                foreign_types_shared::ForeignType::from_ptr(point);
            let mut big_num_context = openssl::bn::BigNumContext::new()
                .map_err(GetKeyParametersError::ConvertToOpenssl)?;
            let point =
                openssl::ec::EcPoint::from_bytes(&group, point.as_slice(), &mut big_num_context)
                    .map_err(GetKeyParametersError::ConvertToOpenssl)?;

            let parameters =
                openssl::ec::EcKey::<openssl::pkey::Public>::from_public_key(&group, &point)
                    .map_err(GetKeyParametersError::ConvertToOpenssl)?;

            Ok(parameters)
        }
    }
}

/// An error from getting the parameters of a key object.
#[derive(Debug)]
pub enum GetKeyParametersError {
    ConvertToOpenssl(openssl::error::ErrorStack),
    GetAttributeValueFailed(pkcs11_sys::CK_RV),
    MalformedEcPoint(openssl::error::ErrorStack),
    UnrecognizedEcCurve(Vec<u8>),
}

impl std::fmt::Display for GetKeyParametersError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetKeyParametersError::ConvertToOpenssl(_) => {
                write!(f, "could not convert components to openssl types")
            }
            GetKeyParametersError::GetAttributeValueFailed(result) => {
                write!(f, "C_GetAttributeValue failed with {}", result)
            }
            GetKeyParametersError::MalformedEcPoint(_) => {
                write!(f, "could not parse the DER-encoded EC point")
            }
            GetKeyParametersError::UnrecognizedEcCurve(curve) => {
                write!(f, "the EC point is using an unknown curve: {:?}", curve)
            }
        }
    }
}

impl Object<openssl::rsa::Rsa<openssl::pkey::Public>> {
    /// Get the RSA parameters of this RSA public key object.
    pub fn parameters(
        &self,
    ) -> Result<openssl::rsa::Rsa<openssl::pkey::Public>, GetKeyParametersError> {
        unsafe {
            let modulus = get_attribute_value_byte_buf(
                &self.session,
                self,
                pkcs11_sys::CKA_MODULUS,
                self.session.context.C_GetAttributeValue,
            )?;
            let modulus = openssl::bn::BigNum::from_slice(&modulus)
                .map_err(GetKeyParametersError::ConvertToOpenssl)?;

            let public_exponent = get_attribute_value_byte_buf(
                &self.session,
                self,
                pkcs11_sys::CKA_PUBLIC_EXPONENT,
                self.session.context.C_GetAttributeValue,
            )?;
            let public_exponent = openssl::bn::BigNum::from_slice(&public_exponent)
                .map_err(GetKeyParametersError::ConvertToOpenssl)?;

            let parameters = openssl::rsa::Rsa::<openssl::pkey::Public>::from_public_components(
                modulus,
                public_exponent,
            )
            .map_err(GetKeyParametersError::ConvertToOpenssl)?;
            Ok(parameters)
        }
    }
}

impl std::error::Error for GetKeyParametersError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            GetKeyParametersError::ConvertToOpenssl(inner) => Some(inner),
            GetKeyParametersError::GetAttributeValueFailed(_) => None,
            GetKeyParametersError::MalformedEcPoint(inner) => Some(inner),
            GetKeyParametersError::UnrecognizedEcCurve(_) => None,
        }
    }
}

impl Object<openssl::ec::EcKey<openssl::pkey::Private>> {
    /// Use this key to sign the given digest and store the result into the given signature buffer.
    pub fn sign(
        &self,
        digest: &[u8],
        signature: &mut [u8],
    ) -> Result<pkcs11_sys::CK_ULONG, SignError> {
        unsafe {
            // Signing with the private key needs login
            self.session.login().map_err(SignError::LoginFailed)?;

            let signature_len = sign_inner(
                &self.session,
                self.handle,
                pkcs11_sys::CKM_ECDSA,
                digest,
                signature,
            )?;
            Ok(signature_len)
        }
    }
}

pub enum RsaSignMechanism {
    Pkcs1,
    X509,
}

impl Object<openssl::rsa::Rsa<openssl::pkey::Private>> {
    /// Use this key to sign the given digest with the given mechanism type and store the result into the given signature buffer.
    pub fn sign(
        &self,
        mechanism: &RsaSignMechanism,
        digest: &[u8],
        signature: &mut [u8],
    ) -> Result<pkcs11_sys::CK_ULONG, SignError> {
        unsafe {
            // Signing with the private key needs login
            self.session.login().map_err(SignError::LoginFailed)?;

            let mechanism = match mechanism {
                RsaSignMechanism::Pkcs1 => pkcs11_sys::CKM_RSA_PKCS,
                RsaSignMechanism::X509 => pkcs11_sys::CKM_RSA_X509,
            };
            let signature_len =
                sign_inner(&self.session, self.handle, mechanism, digest, signature)?;
            Ok(signature_len)
        }
    }
}

impl Object<openssl::rsa::Rsa<openssl::pkey::Public>> {
    /// Use this key to encrypt the given plaintext and store the result into the given ciphertext buffer.
    pub fn encrypt(
        &self,
        mechanism: pkcs11_sys::CK_MECHANISM_TYPE,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<pkcs11_sys::CK_ULONG, EncryptError> {
        unsafe {
            let mechanism = pkcs11_sys::CK_MECHANISM_IN {
                mechanism,
                pParameter: std::ptr::null(),
                ulParameterLen: 0,
            };
            let ciphertext_len = encrypt_inner(
                &self.session,
                self.handle,
                &mechanism,
                plaintext,
                ciphertext,
            )?;
            Ok(ciphertext_len)
        }
    }
}

unsafe fn sign_inner(
    session: &crate::Session,
    handle: pkcs11_sys::CK_OBJECT_HANDLE,
    mechanism: pkcs11_sys::CK_MECHANISM_TYPE,
    digest: &[u8],
    signature: &mut [u8],
) -> Result<pkcs11_sys::CK_ULONG, SignError> {
    let mechanism = pkcs11_sys::CK_MECHANISM_IN {
        mechanism,
        pParameter: std::ptr::null(),
        ulParameterLen: 0,
    };
    let result = (session.context.C_SignInit)(session.handle, &mechanism, handle);
    if result != pkcs11_sys::CKR_OK {
        return Err(SignError::SignInitFailed(result));
    }

    let original_signature_len =
        std::convert::TryInto::try_into(signature.len()).expect("usize -> CK_ULONG");
    let mut signature_len = original_signature_len;

    let result = (session.context.C_Sign)(
        session.handle,
        digest.as_ptr(),
        std::convert::TryInto::try_into(digest.len()).expect("usize -> CK_ULONG"),
        signature.as_mut_ptr(),
        &mut signature_len,
    );
    if result != pkcs11_sys::CKR_OK {
        return Err(SignError::SignFailed(result));
    }
    assert!(signature_len <= original_signature_len);

    Ok(signature_len)
}

#[derive(Debug)]
#[allow(clippy::pub_enum_variant_names)]
pub enum SignError {
    LoginFailed(crate::LoginError),
    SignInitFailed(pkcs11_sys::CK_RV),
    SignFailed(pkcs11_sys::CK_RV),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::LoginFailed(_) => f.write_str("could not log in to the token"),
            SignError::SignInitFailed(result) => write!(f, "C_SignInit failed with {}", result),
            SignError::SignFailed(result) => write!(f, "C_Sign failed with {}", result),
        }
    }
}

impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            SignError::LoginFailed(inner) => Some(inner),
            SignError::SignInitFailed(_) => None,
            SignError::SignFailed(_) => None,
        }
    }
}

unsafe fn verify_inner(
    session: &crate::Session,
    handle: pkcs11_sys::CK_OBJECT_HANDLE,
    mechanism: pkcs11_sys::CK_MECHANISM_TYPE,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    let mechanism = pkcs11_sys::CK_MECHANISM_IN {
        mechanism,
        pParameter: std::ptr::null(),
        ulParameterLen: 0,
    };
    let result = (session.context.C_VerifyInit)(session.handle, &mechanism, handle);
    if result != pkcs11_sys::CKR_OK {
        return Err(VerifyError::VerifyInitFailed(result));
    }

    let result = (session.context.C_Verify)(
        session.handle,
        digest.as_ptr(),
        std::convert::TryInto::try_into(digest.len()).expect("usize -> CK_ULONG"),
        signature.as_ptr(),
        std::convert::TryInto::try_into(signature.len()).expect("usize -> CK_ULONG"),
    );
    match result {
        pkcs11_sys::CKR_OK => Ok(true),
        pkcs11_sys::CKR_SIGNATURE_INVALID | pkcs11_sys::CKR_SIGNATURE_LEN_RANGE => Ok(false),
        result => Err(VerifyError::VerifyFailed(result)),
    }
}

#[derive(Debug)]
#[allow(clippy::pub_enum_variant_names)]
pub enum VerifyError {
    LoginFailed(crate::LoginError),
    VerifyInitFailed(pkcs11_sys::CK_RV),
    VerifyFailed(pkcs11_sys::CK_RV),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::LoginFailed(_) => f.write_str("could not log in to the token"),
            VerifyError::VerifyInitFailed(result) => {
                write!(f, "C_VerifyInit failed with {}", result)
            }
            VerifyError::VerifyFailed(result) => write!(f, "C_Verify failed with {}", result),
        }
    }
}

impl std::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            VerifyError::LoginFailed(inner) => Some(inner),
            VerifyError::VerifyInitFailed(_) => None,
            VerifyError::VerifyFailed(_) => None,
        }
    }
}

unsafe fn encrypt_inner(
    session: &crate::Session,
    handle: pkcs11_sys::CK_OBJECT_HANDLE,
    mechanism: &pkcs11_sys::CK_MECHANISM_IN,
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> Result<pkcs11_sys::CK_ULONG, EncryptError> {
    let result = (session.context.C_EncryptInit)(session.handle, mechanism, handle);
    if result != pkcs11_sys::CKR_OK {
        return Err(EncryptError::EncryptInitFailed(result));
    }

    let original_ciphertext_len =
        std::convert::TryInto::try_into(ciphertext.len()).expect("usize -> CK_ULONG");
    let mut ciphertext_len = original_ciphertext_len;

    let result = (session.context.C_Encrypt)(
        session.handle,
        plaintext.as_ptr(),
        std::convert::TryInto::try_into(plaintext.len()).expect("usize -> CK_ULONG"),
        ciphertext.as_mut_ptr(),
        &mut ciphertext_len,
    );
    if result != pkcs11_sys::CKR_OK {
        return Err(EncryptError::EncryptFailed(result));
    }
    assert!(ciphertext_len <= original_ciphertext_len);

    Ok(ciphertext_len)
}

#[allow(clippy::pub_enum_variant_names)]
#[derive(Debug)]
pub enum EncryptError {
    EncryptInitFailed(pkcs11_sys::CK_RV),
    EncryptFailed(pkcs11_sys::CK_RV),
    LoginFailed(crate::LoginError),
}

impl std::fmt::Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptError::EncryptInitFailed(result) => {
                write!(f, "C_EncryptInit failed with {}", result)
            }
            EncryptError::EncryptFailed(result) => write!(f, "C_Encrypt failed with {}", result),
            EncryptError::LoginFailed(_) => f.write_str("could not log in to the token"),
        }
    }
}

impl std::error::Error for EncryptError {}

unsafe fn decrypt_inner(
    session: &crate::Session,
    handle: pkcs11_sys::CK_OBJECT_HANDLE,
    mechanism: &pkcs11_sys::CK_MECHANISM_IN,
    ciphertext: &[u8],
    plaintext: &mut [u8],
) -> Result<pkcs11_sys::CK_ULONG, DecryptError> {
    let result = (session.context.C_DecryptInit)(session.handle, mechanism, handle);
    if result != pkcs11_sys::CKR_OK {
        return Err(DecryptError::DecryptInitFailed(result));
    }

    let original_plaintext_len =
        std::convert::TryInto::try_into(plaintext.len()).expect("usize -> CK_ULONG");
    let mut plaintext_len = original_plaintext_len;

    let result = (session.context.C_Decrypt)(
        session.handle,
        ciphertext.as_ptr(),
        std::convert::TryInto::try_into(ciphertext.len()).expect("usize -> CK_ULONG"),
        plaintext.as_mut_ptr(),
        &mut plaintext_len,
    );
    if result != pkcs11_sys::CKR_OK {
        return Err(DecryptError::DecryptFailed(result));
    }
    assert!(plaintext_len <= original_plaintext_len);

    Ok(plaintext_len)
}

#[allow(clippy::pub_enum_variant_names)]
#[derive(Debug)]
pub enum DecryptError {
    DecryptInitFailed(pkcs11_sys::CK_RV),
    DecryptFailed(pkcs11_sys::CK_RV),
    LoginFailed(crate::LoginError),
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptError::DecryptInitFailed(result) => {
                write!(f, "C_DecryptInit failed with {}", result)
            }
            DecryptError::DecryptFailed(result) => write!(f, "C_Decrypt failed with {}", result),
            DecryptError::LoginFailed(_) => f.write_str("could not log in to the token"),
        }
    }
}

impl std::error::Error for DecryptError {}

/// Query an attribute value as a byte buffer of arbitrary length.
unsafe fn get_attribute_value_byte_buf<T>(
    session: &crate::Session,
    object: &Object<T>,
    r#type: pkcs11_sys::CK_ATTRIBUTE_TYPE,
    C_GetAttributeValue: pkcs11_sys::CK_C_GetAttributeValue,
) -> Result<Vec<u8>, GetKeyParametersError> {
    // Per the docs of C_GetAttributeValue, it is legal to call it with pValue == NULL and ulValueLen == 0.
    // In this case it will set ulValueLen to the size of buffer it needs and return CKR_OK.

    let mut attribute = pkcs11_sys::CK_ATTRIBUTE {
        r#type,
        pValue: std::ptr::null_mut(),
        ulValueLen: 0,
    };

    let result = C_GetAttributeValue(session.handle, object.handle, &mut attribute, 1);
    if result != pkcs11_sys::CKR_OK {
        return Err(GetKeyParametersError::GetAttributeValueFailed(result));
    }

    let mut buf = vec![
        0_u8;
        std::convert::TryInto::try_into(attribute.ulValueLen)
            .expect("CK_ULONG -> usize")
    ];
    attribute.pValue = buf.as_mut_ptr() as _;

    let result = C_GetAttributeValue(session.handle, object.handle, &mut attribute, 1);
    if result != pkcs11_sys::CKR_OK {
        return Err(GetKeyParametersError::GetAttributeValueFailed(result));
    }

    Ok(buf)
}
