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

pub type Key = crate::Object<()>;

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

    /// Get a key in the current session with the given label.
    pub fn get_key(self: std::sync::Arc<Self>, label: Option<&str>) -> Result<Key, GetKeyError> {
        unsafe {
            // Private key access needs login
            self.login().map_err(GetKeyError::LoginFailed)?;

            let key_handle = self.get_key_inner(pkcs11_sys::CKO_SECRET_KEY, label)?;
            Ok(crate::Object::new(self, key_handle))
        }
    }

    unsafe fn get_key_inner(
        &self,
        class: pkcs11_sys::CK_OBJECT_CLASS,
        label: Option<&str>,
    ) -> Result<pkcs11_sys::CK_OBJECT_HANDLE, GetKeyError> {
        let mut templates = vec![pkcs11_sys::CK_ATTRIBUTE_IN {
            r#type: pkcs11_sys::CKA_CLASS,
            pValue: std::ptr::addr_of!(class).cast(),
            ulValueLen: std::convert::TryInto::try_into(std::mem::size_of_val(&class))
                .expect("usize -> CK_ULONG"),
        }];
        if let Some(label) = label {
            templates.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                r#type: pkcs11_sys::CKA_LABEL,
                pValue: label.as_ptr().cast(),
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
            pValue: std::ptr::addr_of_mut!(key_type).cast(),
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

/// An error from renaming a key.
#[derive(Debug)]
pub enum RenameKeyError {
    LoginFailed(LoginError),
    SourceNotFound,
    ChangeLabelFailed(pkcs11_sys::CK_RV),
}

impl std::fmt::Display for RenameKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RenameKeyError::LoginFailed(_) => f.write_str("could not log in to the token"),
            RenameKeyError::SourceNotFound => f.write_str("source not found"),
            RenameKeyError::ChangeLabelFailed(result) => {
                write!(f, "C_SetAttributeValue failed with {}", result)
            }
        }
    }
}

impl std::error::Error for RenameKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            RenameKeyError::LoginFailed(inner) => Some(inner),
            RenameKeyError::SourceNotFound => None,
            RenameKeyError::ChangeLabelFailed(_) => None,
        }
    }
}

impl Session {
    pub fn rename_key_pair(
        self: std::sync::Arc<Self>,
        from: &str,
        to: &str,
    ) -> Result<(), RenameKeyError> {
        unsafe {
            // Private key access needs login
            self.login().map_err(RenameKeyError::LoginFailed)?;

            let attribute = pkcs11_sys::CK_ATTRIBUTE_IN {
                r#type: pkcs11_sys::CKA_LABEL,
                pValue: to.as_ptr().cast(),
                ulValueLen: std::convert::TryInto::try_into(to.len()).expect("usize -> CK_ULONG"),
            };

            for &class in &[pkcs11_sys::CKO_PUBLIC_KEY, pkcs11_sys::CKO_PRIVATE_KEY] {
                let key_handle = self
                    .get_key_inner(class, Some(from))
                    .map_err(|_| RenameKeyError::SourceNotFound)?;

                let result =
                    (self.context.C_SetAttributeValue)(self.handle, key_handle, &attribute, 1);

                if result != pkcs11_sys::CKR_OK {
                    return Err(RenameKeyError::ChangeLabelFailed(result));
                }
            }
        }

        Ok(())
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyUsage {
    Aes,
    Hmac,
}

impl Session {
    /// Generate a symmetric key in the current session with the given length and label.
    pub fn generate_key(
        self: std::sync::Arc<Self>,
        label: Option<&str>,
        usage: KeyUsage,
    ) -> Result<Key, GenerateKeyError> {
        unsafe {
            // Deleting existing keys and generating new ones needs login
            self.login().map_err(GenerateKeyError::LoginFailed)?;

            // If label is set, delete any existing objects with that label first
            if let Some(label) = label {
                match self.get_key_inner(pkcs11_sys::CKO_SECRET_KEY, Some(label)) {
                    Ok(key_handle) => {
                        let result = (self.context.C_DestroyObject)(self.handle, key_handle);
                        if result != pkcs11_sys::CKR_OK {
                            return Err(GenerateKeyError::DeleteExistingKeyFailed(result));
                        }
                    }
                    Err(GetKeyError::KeyDoesNotExist) => (),
                    Err(err) => return Err(GenerateKeyError::GetExistingKeyFailed(err)),
                }
            }

            let r#true = pkcs11_sys::CK_TRUE;
            let true_size = std::convert::TryInto::try_into(std::mem::size_of_val(&r#true))
                .expect("usize -> CK_ULONG");
            let r#true = std::ptr::addr_of!(r#true).cast();

            // Common to all keys
            let mut key_template = vec![
                pkcs11_sys::CK_ATTRIBUTE_IN {
                    r#type: pkcs11_sys::CKA_PRIVATE,
                    pValue: r#true,
                    ulValueLen: true_size,
                },
                pkcs11_sys::CK_ATTRIBUTE_IN {
                    r#type: pkcs11_sys::CKA_SENSITIVE,
                    pValue: r#true,
                    ulValueLen: true_size,
                },
                pkcs11_sys::CK_ATTRIBUTE_IN {
                    r#type: pkcs11_sys::CKA_TOKEN,
                    pValue: r#true,
                    ulValueLen: true_size,
                },
                pkcs11_sys::CK_ATTRIBUTE_IN {
                    r#type: pkcs11_sys::CKA_VERIFY,
                    pValue: r#true,
                    ulValueLen: true_size,
                },
            ];

            if let Some(label) = label {
                key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                    r#type: pkcs11_sys::CKA_LABEL,
                    pValue: label.as_ptr().cast(),
                    ulValueLen: std::convert::TryInto::try_into(label.len())
                        .expect("usize -> CK_ULONG"),
                });
            }

            match usage {
                KeyUsage::Aes => {
                    // We want to use AES-256-GCM, but fall back to AES-128-GCM if the PKCS#11 implementation
                    // doesn't support AES-256-GCM (eg Cryptoauthlib on ATECC608A).
                    //
                    // Unfortunately PKCS#11 doesn't give us a way to know up-front if the token supports AES-256-GCM or not.
                    // So first try creating a 256-bit key. If that fails, try again with a 128-bit key.
                    // If that also fails, return an error.

                    let mechanism = pkcs11_sys::CK_MECHANISM_IN {
                        mechanism: pkcs11_sys::CKM_AES_KEY_GEN,
                        pParameter: std::ptr::null(),
                        ulParameterLen: 0,
                    };

                    key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                        r#type: pkcs11_sys::CKA_DECRYPT,
                        pValue: r#true,
                        ulValueLen: true_size,
                    });
                    key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                        r#type: pkcs11_sys::CKA_ENCRYPT,
                        pValue: r#true,
                        ulValueLen: true_size,
                    });

                    let key_type = pkcs11_sys::CKK_AES;
                    key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                        r#type: pkcs11_sys::CKA_KEY_TYPE,
                        pValue: std::ptr::addr_of!(key_type).cast(),
                        ulValueLen: std::convert::TryInto::try_into(std::mem::size_of_val(
                            &key_type,
                        ))
                        .expect("usize -> CK_ULONG"),
                    });

                    let key_template_except_value_len = key_template.clone();

                    let mut len: pkcs11_sys::CK_ULONG =
                        std::convert::TryInto::try_into(32).expect("usize -> CK_ULONG");
                    let len_size: pkcs11_sys::CK_ULONG =
                        std::convert::TryInto::try_into(std::mem::size_of_val(&len))
                            .expect("usize -> CK_ULONG");

                    key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                        r#type: pkcs11_sys::CKA_VALUE_LEN,
                        pValue: std::ptr::addr_of!(len).cast(),
                        ulValueLen: len_size,
                    });

                    let mut key_handle = pkcs11_sys::CK_INVALID_OBJECT_HANDLE;
                    let result = (self.context.C_GenerateKey)(
                        self.handle,
                        &mechanism,
                        key_template.as_ptr().cast(),
                        std::convert::TryInto::try_into(key_template.len())
                            .expect("usize -> CK_ULONG"),
                        &mut key_handle,
                    );
                    if result == pkcs11_sys::CKR_OK
                        && key_handle != pkcs11_sys::CK_INVALID_OBJECT_HANDLE
                    {
                        return Ok(crate::Object::new(self, key_handle));
                    }

                    // C_GenerateKey failed. Try with a 128-bit key.

                    let mut key_template = key_template_except_value_len;
                    len = 16;
                    key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                        r#type: pkcs11_sys::CKA_VALUE_LEN,
                        pValue: std::ptr::addr_of!(len).cast(),
                        ulValueLen: len_size,
                    });

                    let mut key_handle = pkcs11_sys::CK_INVALID_OBJECT_HANDLE;
                    let result = (self.context.C_GenerateKey)(
                        self.handle,
                        &mechanism,
                        key_template.as_ptr().cast(),
                        std::convert::TryInto::try_into(key_template.len())
                            .expect("usize -> CK_ULONG"),
                        &mut key_handle,
                    );
                    if result != pkcs11_sys::CKR_OK {
                        return Err(GenerateKeyError::GenerateKeyFailed(result));
                    }
                    if key_handle == pkcs11_sys::CK_INVALID_OBJECT_HANDLE {
                        return Err(GenerateKeyError::GenerateKeyDidNotReturnHandle);
                    }

                    Ok(crate::Object::new(self, key_handle))
                }

                KeyUsage::Hmac => {
                    // HMAC-SHA256 uses 256-bit keys

                    let mechanism = pkcs11_sys::CK_MECHANISM_IN {
                        mechanism: pkcs11_sys::CKM_GENERIC_SECRET_KEY_GEN,
                        pParameter: std::ptr::null(),
                        ulParameterLen: 0,
                    };

                    let len: pkcs11_sys::CK_ULONG =
                        std::convert::TryInto::try_into(32).expect("usize -> CK_ULONG");
                    let len_size: pkcs11_sys::CK_ULONG =
                        std::convert::TryInto::try_into(std::mem::size_of_val(&len))
                            .expect("usize -> CK_ULONG");

                    key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                        r#type: pkcs11_sys::CKA_SIGN,
                        pValue: r#true,
                        ulValueLen: true_size,
                    });
                    key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                        r#type: pkcs11_sys::CKA_VALUE_LEN,
                        pValue: std::ptr::addr_of!(len).cast(),
                        ulValueLen: len_size,
                    });

                    let key_type = pkcs11_sys::CKK_GENERIC_SECRET;
                    key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                        r#type: pkcs11_sys::CKA_KEY_TYPE,
                        pValue: std::ptr::addr_of!(key_type).cast(),
                        ulValueLen: std::mem::size_of_val(&key_type)
                            .try_into()
                            .expect("usize -> CK_ULONG"),
                    });

                    let mut key_handle = pkcs11_sys::CK_INVALID_OBJECT_HANDLE;
                    let result = (self.context.C_GenerateKey)(
                        self.handle,
                        &mechanism,
                        key_template.as_ptr().cast(),
                        std::convert::TryInto::try_into(key_template.len())
                            .expect("usize -> CK_ULONG"),
                        &mut key_handle,
                    );
                    if result != pkcs11_sys::CKR_OK {
                        return Err(GenerateKeyError::GenerateKeyFailed(result));
                    }
                    if key_handle == pkcs11_sys::CK_INVALID_OBJECT_HANDLE {
                        return Err(GenerateKeyError::GenerateKeyDidNotReturnHandle);
                    }

                    Ok(crate::Object::new(self, key_handle))
                }
            }
        }
    }
}

/// An error from generating a key pair.
#[derive(Debug)]
pub enum GenerateKeyError {
    DeleteExistingKeyFailed(pkcs11_sys::CK_RV),
    GenerateKeyDidNotReturnHandle,
    GenerateKeyFailed(pkcs11_sys::CK_RV),
    GetExistingKeyFailed(GetKeyError),
    LoginFailed(crate::LoginError),
}

impl std::fmt::Display for GenerateKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenerateKeyError::DeleteExistingKeyFailed(result) => write!(f, "C_DestroyObject failed with {}", result),
            GenerateKeyError::GenerateKeyDidNotReturnHandle =>
                f.write_str("could not generate key pair: C_GenerateKey succeeded but key handle is still CK_INVALID_HANDLE"),
            GenerateKeyError::GenerateKeyFailed(result) => write!(f, "could not generate key: C_GenerateKey failed with {}", result),
            GenerateKeyError::GetExistingKeyFailed(_) => write!(f, "could not get existing key object"),
            GenerateKeyError::LoginFailed(_) => f.write_str("could not log in to the token"),
        }
    }
}

impl std::error::Error for GenerateKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            GenerateKeyError::DeleteExistingKeyFailed(_) => None,
            GenerateKeyError::GenerateKeyDidNotReturnHandle => None,
            GenerateKeyError::GenerateKeyFailed(_) => None,
            GenerateKeyError::GetExistingKeyFailed(inner) => Some(inner),
            GenerateKeyError::LoginFailed(inner) => Some(inner),
        }
    }
}

impl Session {
    /// Import a symmetric key in the current session with the given bytes and label.
    pub fn import_key(
        self: std::sync::Arc<Self>,
        bytes: &[u8],
        label: Option<&str>,
        usage: KeyUsage,
    ) -> Result<Key, ImportKeyError> {
        unsafe {
            // Deleting existing keys and importing new ones needs login
            self.login().map_err(ImportKeyError::LoginFailed)?;

            // If label is set, delete any existing objects with that label first
            if let Some(label) = label {
                match self.get_key_inner(pkcs11_sys::CKO_SECRET_KEY, Some(label)) {
                    Ok(key_handle) => {
                        let result = (self.context.C_DestroyObject)(self.handle, key_handle);
                        if result != pkcs11_sys::CKR_OK {
                            return Err(ImportKeyError::DeleteExistingKeyFailed(result));
                        }
                    }
                    Err(GetKeyError::KeyDoesNotExist) => (),
                    Err(err) => return Err(ImportKeyError::GetExistingKeyFailed(err)),
                }
            }

            let class = pkcs11_sys::CKO_SECRET_KEY;

            let r#true = pkcs11_sys::CK_TRUE;
            let true_size = std::convert::TryInto::try_into(std::mem::size_of_val(&r#true))
                .expect("usize -> CK_ULONG");
            let r#true = std::ptr::addr_of!(r#true).cast();

            // Common to all keys
            let mut key_template = vec![
                pkcs11_sys::CK_ATTRIBUTE_IN {
                    r#type: pkcs11_sys::CKA_CLASS,
                    pValue: std::ptr::addr_of!(class).cast(),
                    ulValueLen: std::convert::TryInto::try_into(std::mem::size_of_val(&class))
                        .expect("usize -> CK_ULONG"),
                },
                pkcs11_sys::CK_ATTRIBUTE_IN {
                    r#type: pkcs11_sys::CKA_PRIVATE,
                    pValue: r#true,
                    ulValueLen: true_size,
                },
                pkcs11_sys::CK_ATTRIBUTE_IN {
                    r#type: pkcs11_sys::CKA_SENSITIVE,
                    pValue: r#true,
                    ulValueLen: true_size,
                },
                pkcs11_sys::CK_ATTRIBUTE_IN {
                    r#type: pkcs11_sys::CKA_TOKEN,
                    pValue: r#true,
                    ulValueLen: true_size,
                },
                pkcs11_sys::CK_ATTRIBUTE_IN {
                    r#type: pkcs11_sys::CKA_VALUE,
                    pValue: bytes.as_ptr().cast(),
                    ulValueLen: std::convert::TryInto::try_into(bytes.len())
                        .expect("usize -> CK_ULONG"),
                },
            ];

            if let Some(label) = label {
                key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                    r#type: pkcs11_sys::CKA_LABEL,
                    pValue: label.as_ptr().cast(),
                    ulValueLen: std::convert::TryInto::try_into(label.len())
                        .expect("usize -> CK_ULONG"),
                });
            }

            let key_type = match usage {
                KeyUsage::Aes => {
                    key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                        r#type: pkcs11_sys::CKA_DECRYPT,
                        pValue: r#true,
                        ulValueLen: true_size,
                    });
                    key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                        r#type: pkcs11_sys::CKA_ENCRYPT,
                        pValue: r#true,
                        ulValueLen: true_size,
                    });

                    pkcs11_sys::CKK_AES
                }

                KeyUsage::Hmac => {
                    key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                        r#type: pkcs11_sys::CKA_SIGN,
                        pValue: r#true,
                        ulValueLen: true_size,
                    });
                    key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                        r#type: pkcs11_sys::CKA_VERIFY,
                        pValue: r#true,
                        ulValueLen: true_size,
                    });

                    pkcs11_sys::CKK_GENERIC_SECRET
                }
            };

            key_template.push(pkcs11_sys::CK_ATTRIBUTE_IN {
                r#type: pkcs11_sys::CKA_KEY_TYPE,
                pValue: std::ptr::addr_of!(key_type).cast(),
                ulValueLen: std::convert::TryInto::try_into(std::mem::size_of_val(&key_type))
                    .expect("usize -> CK_ULONG"),
            });

            let mut key_handle = pkcs11_sys::CK_INVALID_OBJECT_HANDLE;

            let result = (self.context.C_CreateObject)(
                self.handle,
                key_template.as_ptr().cast(),
                std::convert::TryInto::try_into(key_template.len()).expect("usize -> CK_ULONG"),
                &mut key_handle,
            );
            if result != pkcs11_sys::CKR_OK {
                return Err(ImportKeyError::CreateObjectFailed(result));
            }
            if key_handle == pkcs11_sys::CK_INVALID_OBJECT_HANDLE {
                return Err(ImportKeyError::CreateObjectDidNotReturnHandle);
            }

            Ok(crate::Object::new(self, key_handle))
        }
    }
}

/// An error from generating a key pair.
#[derive(Debug)]
pub enum ImportKeyError {
    CreateObjectDidNotReturnHandle,
    CreateObjectFailed(pkcs11_sys::CK_RV),
    DeleteExistingKeyFailed(pkcs11_sys::CK_RV),
    GetExistingKeyFailed(GetKeyError),
    LoginFailed(crate::LoginError),
}

impl std::fmt::Display for ImportKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportKeyError::CreateObjectDidNotReturnHandle =>
                f.write_str("could not generate key pair: C_CreateObject succeeded but key handle is still CK_INVALID_HANDLE"),
            ImportKeyError::CreateObjectFailed(result) => write!(f, "could not generate key pair: C_CreateObject failed with {}", result),
            ImportKeyError::DeleteExistingKeyFailed(result) => write!(f, "C_DestroyObject failed with {}", result),
            ImportKeyError::GetExistingKeyFailed(_) => write!(f, "could not get existing key object"),
            ImportKeyError::LoginFailed(_) => f.write_str("could not log in to the token"),
        }
    }
}

impl std::error::Error for ImportKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            ImportKeyError::CreateObjectDidNotReturnHandle => None,
            ImportKeyError::CreateObjectFailed(_) => None,
            ImportKeyError::DeleteExistingKeyFailed(_) => None,
            ImportKeyError::GetExistingKeyFailed(inner) => Some(inner),
            ImportKeyError::LoginFailed(inner) => Some(inner),
        }
    }
}

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
                pValue: oid.as_ptr().cast(),
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
                    pValue: std::ptr::addr_of!(modulus_bits).cast(),
                    ulValueLen: std::convert::TryInto::try_into(std::mem::size_of_val(
                        &modulus_bits,
                    ))
                    .expect("usize -> CK_ULONG"),
                },
                pkcs11_sys::CK_ATTRIBUTE_IN {
                    r#type: pkcs11_sys::CKA_PUBLIC_EXPONENT,
                    pValue: exponent.as_ptr().cast(),
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
                            return Err(GenerateKeyPairError::DeleteExistingKeyFailed(result));
                        }
                    }
                    Err(GetKeyError::KeyDoesNotExist) => (),
                    Err(err) => return Err(GenerateKeyPairError::GetExistingKeyFailed(err)),
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
        let r#true = std::ptr::addr_of!(r#true).cast();

        let r#false = pkcs11_sys::CK_FALSE;
        let false_size = std::convert::TryInto::try_into(std::mem::size_of_val(&r#false))
            .expect("usize -> CK_ULONG");
        let r#false = std::ptr::addr_of!(r#false).cast();

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
                pValue: label.as_ptr().cast(),
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
                pValue: label.as_ptr().cast(),
                ulValueLen: std::convert::TryInto::try_into(label.len())
                    .expect("usize -> CK_ULONG"),
            });
        }

        let mut public_key_handle = pkcs11_sys::CK_INVALID_OBJECT_HANDLE;
        let mut private_key_handle = pkcs11_sys::CK_INVALID_OBJECT_HANDLE;

        let result = (self.context.C_GenerateKeyPair)(
            self.handle,
            &mechanism,
            public_key_template.as_ptr().cast(),
            std::convert::TryInto::try_into(public_key_template.len()).expect("usize -> CK_ULONG"),
            private_key_template.as_ptr().cast(),
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
pub enum GenerateKeyPairError {
    DeleteExistingKeyFailed(pkcs11_sys::CK_RV),
    GenerateKeyPairDidNotReturnHandle(&'static str),
    GenerateKeyPairFailed(pkcs11_sys::CK_RV),
    GetExistingKeyFailed(GetKeyError),
    LoginFailed(crate::LoginError),
}

impl std::fmt::Display for GenerateKeyPairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenerateKeyPairError::DeleteExistingKeyFailed(result) => write!(f, "C_DestroyObject failed with {}", result),
            GenerateKeyPairError::GenerateKeyPairDidNotReturnHandle(kind) =>
                write!(f, "could not generate key pair: C_GenerateKeyPair succeeded but {} key handle is still CK_INVALID_HANDLE", kind),
            GenerateKeyPairError::GenerateKeyPairFailed(result) => write!(f, "could not generate key pair: C_GenerateKeyPair failed with {}", result),
            GenerateKeyPairError::GetExistingKeyFailed(_) => write!(f, "could not get existing key object"),
            GenerateKeyPairError::LoginFailed(_) => f.write_str("could not log in to the token"),
        }
    }
}

impl std::error::Error for GenerateKeyPairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            GenerateKeyPairError::DeleteExistingKeyFailed(_) => None,
            GenerateKeyPairError::GenerateKeyPairDidNotReturnHandle(_) => None,
            GenerateKeyPairError::GenerateKeyPairFailed(_) => None,
            GenerateKeyPairError::GetExistingKeyFailed(inner) => Some(inner),
            GenerateKeyPairError::LoginFailed(inner) => Some(inner),
        }
    }
}

impl Session {
    /// Delete a symmetric key in the current session with the given label.
    pub fn delete_key(self: std::sync::Arc<Self>, label: &str) -> Result<(), DeleteKeyError> {
        unsafe {
            // Deleting existing keys needs login
            self.login().map_err(DeleteKeyError::LoginFailed)?;

            match self.get_key_inner(pkcs11_sys::CKO_SECRET_KEY, Some(label)) {
                Ok(key_handle) => {
                    let result = (self.context.C_DestroyObject)(self.handle, key_handle);
                    if result != pkcs11_sys::CKR_OK {
                        return Err(DeleteKeyError::DeleteExistingKeyFailed(result));
                    }
                }
                Err(GetKeyError::KeyDoesNotExist) => (),
                Err(err) => return Err(DeleteKeyError::GetExistingKeyFailed(err)),
            }

            Ok(())
        }
    }
}

/// An error from generating a key pair.
#[derive(Debug)]
pub enum DeleteKeyError {
    DeleteExistingKeyFailed(pkcs11_sys::CK_RV),
    GetExistingKeyFailed(GetKeyError),
    LoginFailed(crate::LoginError),
}

impl std::fmt::Display for DeleteKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeleteKeyError::DeleteExistingKeyFailed(result) => {
                write!(f, "C_DestroyObject failed with {}", result)
            }
            DeleteKeyError::GetExistingKeyFailed(_) => {
                write!(f, "could not get existing key object")
            }
            DeleteKeyError::LoginFailed(_) => f.write_str("could not log in to the token"),
        }
    }
}

impl std::error::Error for DeleteKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            DeleteKeyError::DeleteExistingKeyFailed(_) => None,
            DeleteKeyError::GetExistingKeyFailed(inner) => Some(inner),
            DeleteKeyError::LoginFailed(inner) => Some(inner),
        }
    }
}

impl Session {
    /// Delete a key pair in the current session with the given label.
    pub fn delete_key_pair(
        self: std::sync::Arc<Self>,
        label: &str,
    ) -> Result<(), DeleteKeyPairError> {
        unsafe {
            // Deleting existing keys needs login
            self.login().map_err(DeleteKeyPairError::LoginFailed)?;

            for &class in &[pkcs11_sys::CKO_PUBLIC_KEY, pkcs11_sys::CKO_PRIVATE_KEY] {
                match self.get_key_inner(class, Some(label)) {
                    Ok(key_handle) => {
                        let result = (self.context.C_DestroyObject)(self.handle, key_handle);
                        if result != pkcs11_sys::CKR_OK {
                            return Err(DeleteKeyPairError::DeleteExistingKeyFailed(result));
                        }
                    }
                    Err(GetKeyError::KeyDoesNotExist) => (),
                    Err(err) => return Err(DeleteKeyPairError::GetExistingKeyFailed(err)),
                }
            }

            Ok(())
        }
    }
}

/// An error from generating a key pair.
#[derive(Debug)]
pub enum DeleteKeyPairError {
    DeleteExistingKeyFailed(pkcs11_sys::CK_RV),
    GetExistingKeyFailed(GetKeyError),
    LoginFailed(crate::LoginError),
}

impl std::fmt::Display for DeleteKeyPairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeleteKeyPairError::DeleteExistingKeyFailed(result) => {
                write!(f, "C_DestroyObject failed with {}", result)
            }
            DeleteKeyPairError::GetExistingKeyFailed(_) => {
                write!(f, "could not get existing key object")
            }
            DeleteKeyPairError::LoginFailed(_) => f.write_str("could not log in to the token"),
        }
    }
}

impl std::error::Error for DeleteKeyPairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            DeleteKeyPairError::DeleteExistingKeyFailed(_) => None,
            DeleteKeyPairError::GetExistingKeyFailed(inner) => Some(inner),
            DeleteKeyPairError::LoginFailed(inner) => Some(inner),
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
                pin.as_ptr().cast(),
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
