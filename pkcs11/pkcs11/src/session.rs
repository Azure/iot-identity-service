// Copyright (c) Microsoft. All rights reserved.

pub struct Session {
    pub(crate) context: std::sync::Arc<crate::Context>,
    pub(crate) handle: pkcs11_sys::CK_SESSION_HANDLE,
    pin: Option<String>,
}

impl Session {
    pub(crate) fn new(
        context: std::sync::Arc<crate::Context>,
        handle: pkcs11_sys::CK_SESSION_HANDLE,
        pin: Option<String>,
    ) -> Self {
        Session {
            context,
            handle,
            pin,
        }
    }
}

pub enum KeyPair {
    Ec(
        crate::Object<openssl::ec::EcKey<openssl::pkey::Public>>,
        crate::Object<openssl::ec::EcKey<openssl::pkey::Private>>,
    ),
    Rsa(
        crate::Object<openssl::rsa::Rsa<openssl::pkey::Public>>,
        crate::Object<openssl::rsa::Rsa<openssl::pkey::Private>>,
    ),
}

pub enum PublicKey {
    Ec(crate::Object<openssl::ec::EcKey<openssl::pkey::Public>>),
    Rsa(crate::Object<openssl::rsa::Rsa<openssl::pkey::Public>>),
}

impl Session {
    /// Get a public key in the current session with the given label.
    pub fn get_public_key(
        self: std::sync::Arc<Self>,
        label: Option<&str>,
    ) -> Result<PublicKey, GetKeyError> {
        unsafe {
            let public_key_handle = self.get_key_inner(pkcs11_sys::CKO_PUBLIC_KEY, label)?;
            let public_key_mechanism_type = self.get_key_mechanism_type(public_key_handle)?;

            match public_key_mechanism_type {
                pkcs11_sys::CKK_EC => {
                    Ok(PublicKey::Ec(crate::Object::new(self, public_key_handle)))
                }
                pkcs11_sys::CKK_RSA => {
                    Ok(PublicKey::Rsa(crate::Object::new(self, public_key_handle)))
                }
                _ => Err(GetKeyError::MismatchedMechanismType),
            }
        }
    }

    /// Get a key pair in the current session with the given label.
    pub fn get_key_pair(
        self: std::sync::Arc<Self>,
        label: Option<&str>,
    ) -> Result<KeyPair, GetKeyError> {
        unsafe {
            // Private key access needs login
            self.login().map_err(GetKeyError::LoginFailed)?;

            let public_key_handle = self.get_key_inner(pkcs11_sys::CKO_PUBLIC_KEY, label)?;
            let public_key_mechanism_type = self.get_key_mechanism_type(public_key_handle)?;
            let private_key_handle = self.get_key_inner(pkcs11_sys::CKO_PRIVATE_KEY, label)?;
            let private_key_mechanism_type = self.get_key_mechanism_type(private_key_handle)?;

            match (public_key_mechanism_type, private_key_mechanism_type) {
                (pkcs11_sys::CKK_EC, pkcs11_sys::CKK_EC) => Ok(KeyPair::Ec(
                    crate::Object::new(self.clone(), public_key_handle),
                    crate::Object::new(self, private_key_handle),
                )),

                (pkcs11_sys::CKK_RSA, pkcs11_sys::CKK_RSA) => Ok(KeyPair::Rsa(
                    crate::Object::new(self.clone(), public_key_handle),
                    crate::Object::new(self, private_key_handle),
                )),

                _ => Err(GetKeyError::MismatchedMechanismType),
            }
        }
    }

    unsafe fn get_key_inner(
        &self,
        class: pkcs11_sys::CK_OBJECT_CLASS,
        label: Option<&str>,
    ) -> Result<pkcs11_sys::CK_OBJECT_HANDLE, GetKeyError> {
        let mut templates = vec![pkcs11_sys::CK_ATTRIBUTE_IN {
            r#type: pkcs11_sys::CKA_CLASS,
            pValue: &class as *const _ as _,
            ulValueLen: std::convert::TryInto::try_into(std::mem::size_of_val(&class))
                .expect("usize -> CK_ULONG"),
        }];
        if let Some(label) = label {
            templates.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                r#type: pkcs11_sys::CKA_LABEL,
                pValue: label.as_ptr() as *const _ as _,
                ulValueLen: std::convert::TryInto::try_into(label.len())
                    .expect("usize -> CK_ULONG"),
            });
        }
        let key_handle = {
            let mut find_objects =
                FindObjects::new(self, &templates).map_err(GetKeyError::FindObjectsFailed)?;
            match find_objects.next() {
                Some(key_handle) => key_handle.map_err(GetKeyError::FindObjectsFailed)?,
                None => return Err(GetKeyError::KeyDoesNotExist),
            }
        };

        Ok(key_handle)
    }

    unsafe fn get_key_mechanism_type(
        &self,
        key_handle: pkcs11_sys::CK_OBJECT_HANDLE,
    ) -> Result<pkcs11_sys::CK_KEY_TYPE, GetKeyError> {
        let mut key_type = pkcs11_sys::CKK_EC;
        let key_type_size = std::convert::TryInto::try_into(std::mem::size_of_val(&key_type))
            .expect("usize -> CK_ULONG");
        let mut attribute = pkcs11_sys::CK_ATTRIBUTE {
            r#type: pkcs11_sys::CKA_KEY_TYPE,
            pValue: &mut key_type as *mut _ as _,
            ulValueLen: key_type_size,
        };
        let result = (self.context.C_GetAttributeValue)(self.handle, key_handle, &mut attribute, 1);
        if result != pkcs11_sys::CKR_OK {
            return Err(GetKeyError::GetKeyTypeFailed(result));
        }

        Ok(key_type)
    }
}

/// An error from getting a key.
#[derive(Debug)]
pub enum GetKeyError {
    FindObjectsFailed(FindObjectsError),
    GetKeyTypeFailed(pkcs11_sys::CK_RV),
    KeyDoesNotExist,
    LoginFailed(LoginError),
    MismatchedMechanismType,
}

impl std::fmt::Display for GetKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetKeyError::FindObjectsFailed(_) => f.write_str("could not find objects"),
            GetKeyError::GetKeyTypeFailed(result) => write!(
                f,
                "C_GetAttributeValue(CKA_KEY_TYPE) failed with {}",
                result
            ),
            GetKeyError::KeyDoesNotExist => f.write_str("did not find any keys in the slot"),
            GetKeyError::LoginFailed(_) => f.write_str("could not log in to the token"),
            GetKeyError::MismatchedMechanismType => {
                f.write_str("public and private keys have different mechanisms")
            }
        }
    }
}

impl std::error::Error for GetKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            GetKeyError::FindObjectsFailed(inner) => Some(inner),
            GetKeyError::GetKeyTypeFailed(_) => None,
            GetKeyError::KeyDoesNotExist => None,
            GetKeyError::LoginFailed(inner) => Some(inner),
            GetKeyError::MismatchedMechanismType => None,
        }
    }
}

struct FindObjects<'session> {
    session: &'session Session,
}

impl<'session> FindObjects<'session> {
    unsafe fn new(
        session: &'session Session,
        templates: &'session [pkcs11_sys::CK_ATTRIBUTE_IN],
    ) -> Result<Self, FindObjectsError> {
        let result = (session.context.C_FindObjectsInit)(
            session.handle,
            templates.as_ptr(),
            std::convert::TryInto::try_into(templates.len()).expect("usize -> CK_ULONG"),
        );
        if result != pkcs11_sys::CKR_OK {
            return Err(FindObjectsError::FindObjectsInitFailed(result));
        }

        Ok(FindObjects { session })
    }
}

impl<'session> Iterator for FindObjects<'session> {
    type Item = Result<pkcs11_sys::CK_OBJECT_HANDLE, FindObjectsError>;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let mut object_handle = pkcs11_sys::CK_INVALID_OBJECT_HANDLE;
            let mut num_objects = 0;
            let result = (self.session.context.C_FindObjects)(
                self.session.handle,
                &mut object_handle,
                1,
                &mut num_objects,
            );
            if result != pkcs11_sys::CKR_OK {
                return Some(Err(FindObjectsError::FindObjectsFailed(
                    format!("C_FindObjects failed with {}", result).into(),
                )));
            }
            match num_objects {
                0 => None,
                1 if object_handle != pkcs11_sys::CK_INVALID_OBJECT_HANDLE => {
                    Some(Ok(object_handle))
                }
                1 => Some(Err(FindObjectsError::FindObjectsFailed(
                    "C_FindObjects found 1 object but object handle is still CK_INVALID_HANDLE"
                        .into(),
                ))),
                num_objects => Some(Err(FindObjectsError::FindObjectsFailed(
                    format!("C_FindObjects found {} objects", num_objects).into(),
                ))),
            }
        }
    }
}

impl<'session> Drop for FindObjects<'session> {
    fn drop(&mut self) {
        unsafe {
            let _ = (self.session.context.C_FindObjectsFinal)(self.session.handle);
        }
    }
}

/// An error from finding an object.
#[derive(Debug)]
pub enum FindObjectsError {
    FindObjectsFailed(std::borrow::Cow<'static, str>),
    FindObjectsInitFailed(pkcs11_sys::CK_RV),
}

impl std::fmt::Display for FindObjectsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindObjectsError::FindObjectsFailed(message) => f.write_str(message),
            FindObjectsError::FindObjectsInitFailed(result) => {
                write!(f, "C_FindObjectsInit failed with {}", result)
            }
        }
    }
}

impl std::error::Error for FindObjectsError {}

impl Session {
    /// Generate an EC key pair in the current session with the given curve and label.
    pub fn generate_ec_key_pair(
        self: std::sync::Arc<Self>,
        curve: openssl2::EcCurve,
        label: Option<&str>,
    ) -> Result<
        (
            crate::Object<openssl::ec::EcKey<openssl::pkey::Public>>,
            crate::Object<openssl::ec::EcKey<openssl::pkey::Private>>,
        ),
        GenerateKeyPairError,
    > {
        unsafe {
            let oid = curve.as_oid_der();

            let public_key_template = vec![pkcs11_sys::CK_ATTRIBUTE_IN {
                r#type: pkcs11_sys::CKA_EC_PARAMS,
                pValue: oid.as_ptr() as _,
                ulValueLen: std::convert::TryInto::try_into(oid.len()).expect("usize -> CK_ULONG"),
            }];

            let private_key_template = vec![];

            self.generate_key_pair_inner(
                pkcs11_sys::CKM_EC_KEY_PAIR_GEN,
                public_key_template,
                private_key_template,
                label,
            )
        }
    }

    /// Generate an RSA key pair in the current session with the given modulus size, exponent and label.
    pub fn generate_rsa_key_pair(
        self: std::sync::Arc<Self>,
        modulus_bits: pkcs11_sys::CK_ULONG,
        exponent: &openssl::bn::BigNumRef,
        label: Option<&str>,
    ) -> Result<
        (
            crate::Object<openssl::rsa::Rsa<openssl::pkey::Public>>,
            crate::Object<openssl::rsa::Rsa<openssl::pkey::Private>>,
        ),
        GenerateKeyPairError,
    > {
        unsafe {
            let exponent = exponent.to_vec();

            let public_key_template = vec![
                pkcs11_sys::CK_ATTRIBUTE_IN {
                    r#type: pkcs11_sys::CKA_MODULUS_BITS,
                    pValue: &modulus_bits as *const _ as _,
                    ulValueLen: std::convert::TryInto::try_into(std::mem::size_of_val(
                        &modulus_bits,
                    ))
                    .expect("usize -> CK_ULONG"),
                },
                pkcs11_sys::CK_ATTRIBUTE_IN {
                    r#type: pkcs11_sys::CKA_PUBLIC_EXPONENT,
                    pValue: exponent.as_ptr() as _,
                    ulValueLen: std::convert::TryInto::try_into(exponent.len())
                        .expect("usize -> CK_ULONG"),
                },
            ];

            let private_key_template = vec![];

            self.generate_key_pair_inner(
                pkcs11_sys::CKM_RSA_PKCS_KEY_PAIR_GEN,
                public_key_template,
                private_key_template,
                label,
            )
        }
    }

    unsafe fn generate_key_pair_inner<TPublic, TPrivate>(
        self: std::sync::Arc<Self>,
        mechanism: pkcs11_sys::CK_MECHANISM_TYPE,
        mut public_key_template: Vec<pkcs11_sys::CK_ATTRIBUTE_IN>,
        mut private_key_template: Vec<pkcs11_sys::CK_ATTRIBUTE_IN>,
        label: Option<&str>,
    ) -> Result<(crate::Object<TPublic>, crate::Object<TPrivate>), GenerateKeyPairError> {
        // Deleting existing keys and generating new ones needs login
        self.login().map_err(GenerateKeyPairError::LoginFailed)?;

        // If label is set, delete any existing objects with that label first
        if let Some(label) = label {
            for &class in &[pkcs11_sys::CKO_PUBLIC_KEY, pkcs11_sys::CKO_PRIVATE_KEY] {
                match self.get_key_inner(class, Some(label)) {
                    Ok(key_handle) => {
                        let result = (self.context.C_DestroyObject)(self.handle, key_handle);
                        if result != pkcs11_sys::CKR_OK {
                            return Err(GenerateKeyPairError::DeleteExistingKey(result));
                        }
                    }
                    Err(GetKeyError::KeyDoesNotExist) => (),
                    Err(err) => return Err(GenerateKeyPairError::GetExistingKey(err)),
                }
            }
        }

        let mechanism = pkcs11_sys::CK_MECHANISM_IN {
            mechanism,
            pParameter: std::ptr::null(),
            ulParameterLen: 0,
        };

        let r#true = pkcs11_sys::CK_TRUE;
        let true_size = std::convert::TryInto::try_into(std::mem::size_of_val(&r#true))
            .expect("usize -> CK_ULONG");
        let r#true = &r#true as *const _ as _;

        let r#false = pkcs11_sys::CK_FALSE;
        let false_size = std::convert::TryInto::try_into(std::mem::size_of_val(&r#false))
            .expect("usize -> CK_ULONG");
        let r#false = &r#false as *const _ as _;

        // The spec's example also passes in CKA_WRAP for the public key and CKA_UNWRAP for the private key,
        // but tpm2-pkcs11's impl of `C_GenerateKeyPair` does not recognize those and fails.
        //
        // We don't need them anyway, so we don't pass them.

        public_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
            r#type: pkcs11_sys::CKA_ENCRYPT,
            pValue: r#true,
            ulValueLen: true_size,
        });
        public_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
            r#type: pkcs11_sys::CKA_PRIVATE,
            pValue: r#false,
            ulValueLen: false_size,
        });
        public_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
            r#type: pkcs11_sys::CKA_TOKEN,
            pValue: r#true,
            ulValueLen: true_size,
        });
        public_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
            r#type: pkcs11_sys::CKA_VERIFY,
            pValue: r#true,
            ulValueLen: true_size,
        });
        if let Some(label) = label {
            public_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                r#type: pkcs11_sys::CKA_LABEL,
                pValue: label.as_ptr() as _,
                ulValueLen: std::convert::TryInto::try_into(label.len())
                    .expect("usize -> CK_ULONG"),
            });
        }

        private_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
            r#type: pkcs11_sys::CKA_DECRYPT,
            pValue: r#true,
            ulValueLen: true_size,
        });
        private_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
            r#type: pkcs11_sys::CKA_PRIVATE,
            pValue: r#true,
            ulValueLen: true_size,
        });
        private_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
            r#type: pkcs11_sys::CKA_SENSITIVE,
            pValue: r#true,
            ulValueLen: true_size,
        });
        private_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
            r#type: pkcs11_sys::CKA_SIGN,
            pValue: r#true,
            ulValueLen: true_size,
        });
        private_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
            r#type: pkcs11_sys::CKA_TOKEN,
            pValue: r#true,
            ulValueLen: true_size,
        });
        if let Some(label) = label {
            private_key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                r#type: pkcs11_sys::CKA_LABEL,
                pValue: label.as_ptr() as _,
                ulValueLen: std::convert::TryInto::try_into(label.len())
                    .expect("usize -> CK_ULONG"),
            });
        }

        let mut public_key_handle = pkcs11_sys::CK_INVALID_OBJECT_HANDLE;
        let mut private_key_handle = pkcs11_sys::CK_INVALID_OBJECT_HANDLE;

        let result = (self.context.C_GenerateKeyPair)(
            self.handle,
            &mechanism,
            public_key_template.as_ptr() as _,
            std::convert::TryInto::try_into(public_key_template.len()).expect("usize -> CK_ULONG"),
            private_key_template.as_ptr() as _,
            std::convert::TryInto::try_into(private_key_template.len()).expect("usize -> CK_ULONG"),
            &mut public_key_handle,
            &mut private_key_handle,
        );
        if result != pkcs11_sys::CKR_OK {
            return Err(GenerateKeyPairError::GenerateKeyPairFailed(result));
        }
        if public_key_handle == pkcs11_sys::CK_INVALID_OBJECT_HANDLE {
            return Err(GenerateKeyPairError::GenerateKeyPairDidNotReturnHandle(
                "public",
            ));
        }
        if private_key_handle == pkcs11_sys::CK_INVALID_OBJECT_HANDLE {
            return Err(GenerateKeyPairError::GenerateKeyPairDidNotReturnHandle(
                "private",
            ));
        }

        Ok((
            crate::Object::new(self.clone(), public_key_handle),
            crate::Object::new(self, private_key_handle),
        ))
    }
}

/// An error from generating a key pair.
#[derive(Debug)]
#[allow(clippy::pub_enum_variant_names)]
pub enum GenerateKeyPairError {
    DeleteExistingKey(pkcs11_sys::CK_RV),
    GenerateKeyPairDidNotReturnHandle(&'static str),
    GenerateKeyPairFailed(pkcs11_sys::CK_RV),
    GetExistingKey(GetKeyError),
    LoginFailed(crate::LoginError),
}

impl std::fmt::Display for GenerateKeyPairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
			GenerateKeyPairError::DeleteExistingKey(result) => write!(f, "C_DestroyObject failed with {}", result),
			GenerateKeyPairError::GenerateKeyPairDidNotReturnHandle(kind) =>
				write!(f, "could not generate key pair: C_GenerateKeyPair succeeded but {} key handle is still CK_INVALID_HANDLE", kind),
			GenerateKeyPairError::GenerateKeyPairFailed(result) => write!(f, "could not generate key pair: C_GenerateKeyPair failed with {}", result),
			GenerateKeyPairError::GetExistingKey(_) => write!(f, "could not get existing key object"),
			GenerateKeyPairError::LoginFailed(_) => f.write_str("could not log in to the token"),
		}
    }
}

impl std::error::Error for GenerateKeyPairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            GenerateKeyPairError::DeleteExistingKey(_) => None,
            GenerateKeyPairError::GenerateKeyPairDidNotReturnHandle(_) => None,
            GenerateKeyPairError::GenerateKeyPairFailed(_) => None,
            GenerateKeyPairError::GetExistingKey(inner) => Some(inner),
            GenerateKeyPairError::LoginFailed(inner) => Some(inner),
        }
    }
}

impl Session {
    pub(crate) unsafe fn login(&self) -> Result<(), LoginError> {
        let mut session_info = std::mem::MaybeUninit::uninit();
        let result = (self.context.C_GetSessionInfo)(self.handle, session_info.as_mut_ptr());
        if result != pkcs11_sys::CKR_OK {
            return Err(LoginError::GetSessionInfoFailed(result));
        }

        let session_info = session_info.assume_init();
        match session_info.state {
            pkcs11_sys::CKS_RO_USER_FUNCTIONS
            | pkcs11_sys::CKS_RW_USER_FUNCTIONS
            | pkcs11_sys::CKS_RW_SO_FUNCTIONS => return Ok(()),

            _ => (),
        }

        if let Some(pin) = &self.pin {
            let result = (self.context.C_Login)(
                self.handle,
                pkcs11_sys::CKU_USER,
                pin.as_ptr() as _,
                std::convert::TryInto::try_into(pin.len()).expect("usize -> CK_ULONG"),
            );
            if result != pkcs11_sys::CKR_OK && result != pkcs11_sys::CKR_USER_ALREADY_LOGGED_IN {
                return Err(LoginError::LoginFailed(result));
            }
        } else {
            // Don't fail if PIN was never provided to us. We decide to log in proactively, so it's *possible* the operation we're trying to log in for
            // doesn't actually need a login.
            //
            // So we pretend to succeed. If the operation did require a login after all, it'll fail with the approprate error.
        }

        Ok(())
    }
}

/// An error from logging in to the token.
#[derive(Debug)]
pub enum LoginError {
    GetSessionInfoFailed(pkcs11_sys::CK_RV),
    LoginFailed(pkcs11_sys::CK_RV),
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginError::GetSessionInfoFailed(result) => {
                write!(f, "C_GetSessionInfo failed with {}", result)
            }
            LoginError::LoginFailed(result) => write!(f, "C_Login failed with {}", result),
        }
    }
}

impl std::error::Error for LoginError {}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            let _ = (self.context.C_CloseSession)(self.handle);
        }
    }
}
