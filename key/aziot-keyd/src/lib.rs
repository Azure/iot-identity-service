// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_and_return,
    clippy::let_unit_value,
    clippy::missing_errors_doc
)]

mod error;
pub use error::{Error, InternalError};

mod keys;

mod http;

use aziot_keyd_config::{Config, Endpoints};

pub async fn main(
    config: Config,
    _: std::path::PathBuf,
    _: std::path::PathBuf,
) -> Result<(http_common::Connector, http::Service), Box<dyn std::error::Error>> {
    let Config {
        aziot_keys,
        preloaded_keys,
        endpoints: Endpoints {
            aziot_keyd: connector,
        },
    } = config;

    let api = {
        let mut keys = keys::Keys::new()?;

        for (name, value) in aziot_keys {
            let name = std::ffi::CString::new(name.clone()).map_err(|err| {
                Error::Internal(InternalError::ReadConfig(
                    format!(
                        "key {:?} in [aziot_keys] section of the configuration could not be converted to a C string: {}",
                        name, err,
                    )
                    .into(),
                ))
            })?;

            let value =
                std::ffi::CString::new(value).map_err(|err| Error::Internal(InternalError::ReadConfig(format!(
                    "value of key {:?} in [aziot_keys] section of the configuration could not be converted to a C string: {}",
                    name, err,
                ).into())))?;

            keys.set_parameter(&name, &value)?;
        }

        for (key_id, value) in preloaded_keys {
            let name = format!("preloaded_key:{}", key_id);
            let name =
                std::ffi::CString::new(name).map_err(|err| Error::Internal(InternalError::ReadConfig(format!(
                    "key ID {:?} in [preloaded_keys] section of the configuration could not be converted to a C string: {}",
                    key_id, err,
                ).into())))?;

            let value =
                std::ffi::CString::new(value).map_err(|err| Error::Internal(InternalError::ReadConfig(format!(
                    "location of key ID {:?} in [preloaded_keys] section of the configuration could not be converted to a C string: {}",
                    key_id, err,
                ).into())))?;

            keys.set_parameter(&name, &value)?;
        }

        Api { keys }
    };
    let api = std::sync::Arc::new(futures_util::lock::Mutex::new(api));

    let service = http::Service { api };

    Ok((connector, service))
}

pub struct Api {
    keys: keys::Keys,
}

impl Api {
    pub fn new(
        aziot_keys: std::collections::BTreeMap<String, String>,
        preloaded_keys: std::collections::BTreeMap<String, String>,
    ) -> Result<Self, Error> {
        let mut keys = keys::Keys::new()?;

        for (name, value) in aziot_keys {
            let name = std::ffi::CString::new(name.clone()).map_err(|err| {
                Error::Internal(InternalError::ReadConfig(
                    format!(
                        "key {:?} in [aziot_keys] section of the configuration could not be converted to a C string: {}",
                        name, err,
                    )
                    .into(),
                ))
            })?;

            let value =
                std::ffi::CString::new(value).map_err(|err| Error::Internal(InternalError::ReadConfig(format!(
                    "value of key {:?} in [aziot_keys] section of the configuration could not be converted to a C string: {}",
                    name, err,
                ).into())))?;

            keys.set_parameter(&name, &value)?;
        }

        for (key_id, value) in preloaded_keys {
            let name = format!("preloaded_key:{}", key_id);
            let name =
                std::ffi::CString::new(name).map_err(|err| Error::Internal(InternalError::ReadConfig(format!(
                    "key ID {:?} in [preloaded_keys] section of the configuration could not be converted to a C string: {}",
                    key_id, err,
                ).into())))?;

            let value =
                std::ffi::CString::new(value).map_err(|err| Error::Internal(InternalError::ReadConfig(format!(
                    "location of key ID {:?} in [preloaded_keys] section of the configuration could not be converted to a C string: {}",
                    key_id, err,
                ).into())))?;

            keys.set_parameter(&name, &value)?;
        }

        Ok(Api { keys })
    }

    pub fn create_key_pair_if_not_exists(
        &mut self,
        id: &str,
        preferred_algorithms: Option<&str>,
    ) -> Result<aziot_key_common::KeyHandle, Error> {
        let id_cstr = std::ffi::CString::new(id.to_owned())
            .map_err(|err| Error::invalid_parameter("id", err))?;
        let preferred_algorithms = preferred_algorithms
            .map(|preferred_algorithms| std::ffi::CString::new(preferred_algorithms.to_owned()))
            .transpose()
            .map_err(|err| Error::invalid_parameter("preferred_algorithms", err))?;
        self.keys.create_key_pair_if_not_exists(
            &id_cstr,
            preferred_algorithms.as_ref().map(AsRef::as_ref),
        )?;

        let handle = key_id_to_handle(&KeyId::KeyPair(id.into()), &mut self.keys)?;
        Ok(handle)
    }

    pub fn load_key_pair(&mut self, id: &str) -> Result<aziot_key_common::KeyHandle, Error> {
        let id_cstr = std::ffi::CString::new(id.to_owned())
            .map_err(|err| Error::invalid_parameter("id", err))?;
        self.keys.load_key_pair(&id_cstr)?;

        let handle = key_id_to_handle(&KeyId::KeyPair(id.into()), &mut self.keys)?;
        Ok(handle)
    }

    pub fn get_key_pair_public_parameter(
        &mut self,
        handle: &aziot_key_common::KeyHandle,
        parameter_name: &str,
    ) -> Result<String, Error> {
        let (_, id_cstr) = key_handle_to_id(handle, &mut self.keys)?;

        let parameter_value = self
            .keys
            .get_key_pair_public_parameter(&id_cstr, parameter_name)?;
        Ok(parameter_value)
    }

    pub fn create_key_if_not_exists(
        &mut self,
        id: &str,
        value: aziot_key_common::CreateKeyValue,
    ) -> Result<aziot_key_common::KeyHandle, Error> {
        let id_cstr = std::ffi::CString::new(id.to_owned())
            .map_err(|err| Error::invalid_parameter("id", err))?;

        match value {
            aziot_key_common::CreateKeyValue::Generate { length } => {
                self.keys.create_key_if_not_exists(&id_cstr, length)?
            }

            aziot_key_common::CreateKeyValue::Import { bytes } => {
                self.keys.import_key(&id_cstr, &bytes)?
            }
        }

        let handle = key_id_to_handle(&KeyId::Key(id.into()), &mut self.keys)?;
        Ok(handle)
    }

    pub fn load_key(&mut self, id: &str) -> Result<aziot_key_common::KeyHandle, Error> {
        let id_cstr = std::ffi::CString::new(id.to_owned())
            .map_err(|err| Error::invalid_parameter("id", err))?;
        self.keys.load_key(&id_cstr)?;

        let handle = key_id_to_handle(&KeyId::Key(id.into()), &mut self.keys)?;
        Ok(handle)
    }

    pub fn create_derived_key(
        &mut self,
        base_handle: &aziot_key_common::KeyHandle,
        derivation_data: &[u8],
    ) -> Result<aziot_key_common::KeyHandle, Error> {
        let handle = key_id_to_handle(
            &KeyId::Derived(
                std::borrow::Cow::Borrowed(base_handle),
                derivation_data.into(),
            ),
            &mut self.keys,
        )?;
        Ok(handle)
    }

    pub fn export_derived_key(
        &mut self,
        handle: &aziot_key_common::KeyHandle,
    ) -> Result<Vec<u8>, Error> {
        let (id, id_cstr) = key_handle_to_id(handle, &mut self.keys)?;

        let derived_key = if let KeyId::Derived(_, derivation_data) = id {
            self.keys.derive_key(&id_cstr, &derivation_data)?
        } else {
            return Err(Error::invalid_parameter(
                "handle",
                "handle is not for a derived key",
            ));
        };
        Ok(derived_key)
    }

    pub fn sign(
        &mut self,
        handle: &aziot_key_common::KeyHandle,
        mechanism: aziot_key_common::SignMechanism,
        digest: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let (id, id_cstr) = key_handle_to_id(handle, &mut self.keys)?;
        let signature = match (id, mechanism) {
            (KeyId::KeyPair(_), aziot_key_common::SignMechanism::Ecdsa) => self.keys.sign(
                &id_cstr,
                keys::sys::AZIOT_KEYS_SIGN_MECHANISM_ECDSA,
                std::ptr::null(),
                digest,
            )?,

            (KeyId::Key(_), aziot_key_common::SignMechanism::HmacSha256) => self.keys.sign(
                &id_cstr,
                keys::sys::AZIOT_KEYS_SIGN_MECHANISM_HMAC_SHA256,
                std::ptr::null(),
                digest,
            )?,

            (KeyId::Derived(_, derivation_data), aziot_key_common::SignMechanism::HmacSha256) => {
                let parameters = keys::sys::AZIOT_KEYS_SIGN_DERIVED_PARAMETERS {
                    derivation_data: derivation_data.as_ptr(),
                    derivation_data_len: derivation_data.len(),
                    mechanism: keys::sys::AZIOT_KEYS_SIGN_MECHANISM_HMAC_SHA256,
                    parameters: std::ptr::null(),
                };

                self.keys.sign(
                    &id_cstr,
                    keys::sys::AZIOT_KEYS_SIGN_MECHANISM_DERIVED,
                    &parameters as *const _ as *const std::ffi::c_void,
                    digest,
                )?
            }

            _ => {
                return Err(Error::invalid_parameter(
                    "mechanism",
                    "mechanism cannot be used with this key type",
                ))
            }
        };

        Ok(signature)
    }

    pub fn encrypt(
        &mut self,
        handle: &aziot_key_common::KeyHandle,
        mechanism: aziot_key_common::EncryptMechanism,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let (id, id_cstr) = key_handle_to_id(handle, &mut self.keys)?;

        let ciphertext = match (id, mechanism) {
            (KeyId::Key(_), aziot_key_common::EncryptMechanism::Aead { iv, aad }) => {
                let parameters = keys::sys::AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS {
                    iv: iv.as_ptr(),
                    iv_len: iv.len(),
                    aad: aad.as_ptr(),
                    aad_len: aad.len(),
                };

                self.keys.encrypt(
                    &id_cstr,
                    keys::sys::AZIOT_KEYS_ENCRYPT_MECHANISM_AEAD,
                    &parameters as *const _ as *const std::ffi::c_void,
                    plaintext,
                )?
            }

            (KeyId::KeyPair(_), aziot_key_common::EncryptMechanism::RsaPkcs1) => {
                self.keys.encrypt(
                    &id_cstr,
                    keys::sys::AZIOT_KEYS_ENCRYPT_MECHANISM_RSA_PKCS1,
                    std::ptr::null_mut(),
                    plaintext,
                )?
            }

            (KeyId::KeyPair(_), aziot_key_common::EncryptMechanism::RsaNoPadding) => {
                self.keys.encrypt(
                    &id_cstr,
                    keys::sys::AZIOT_KEYS_ENCRYPT_MECHANISM_RSA_NO_PADDING,
                    std::ptr::null_mut(),
                    plaintext,
                )?
            }

            (
                KeyId::Derived(_, derivation_data),
                aziot_key_common::EncryptMechanism::Aead { iv, aad },
            ) => {
                let parameters = keys::sys::AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS {
                    iv: iv.as_ptr(),
                    iv_len: iv.len(),
                    aad: aad.as_ptr(),
                    aad_len: aad.len(),
                };

                let parameters = keys::sys::AZIOT_KEYS_ENCRYPT_DERIVED_PARAMETERS {
                    derivation_data: derivation_data.as_ptr(),
                    derivation_data_len: derivation_data.len(),
                    mechanism: keys::sys::AZIOT_KEYS_ENCRYPT_MECHANISM_AEAD,
                    parameters: &parameters as *const _ as *const std::ffi::c_void,
                };

                self.keys.encrypt(
                    &id_cstr,
                    keys::sys::AZIOT_KEYS_ENCRYPT_MECHANISM_DERIVED,
                    &parameters as *const _ as *const std::ffi::c_void,
                    plaintext,
                )?
            }

            _ => {
                return Err(Error::invalid_parameter(
                    "mechanism",
                    "mechanism cannot be used with this key type",
                ))
            }
        };

        Ok(ciphertext)
    }

    pub fn decrypt(
        &mut self,
        handle: &aziot_key_common::KeyHandle,
        mechanism: aziot_key_common::EncryptMechanism,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let (id, id_cstr) = key_handle_to_id(handle, &mut self.keys)?;

        let plaintext = match (id, mechanism) {
            (KeyId::Key(_), aziot_key_common::EncryptMechanism::Aead { iv, aad }) => {
                let parameters = keys::sys::AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS {
                    iv: iv.as_ptr(),
                    iv_len: iv.len(),
                    aad: aad.as_ptr(),
                    aad_len: aad.len(),
                };

                self.keys.decrypt(
                    &id_cstr,
                    keys::sys::AZIOT_KEYS_ENCRYPT_MECHANISM_AEAD,
                    &parameters as *const _ as *const std::ffi::c_void,
                    ciphertext,
                )?
            }

            (
                KeyId::Derived(_, derivation_data),
                aziot_key_common::EncryptMechanism::Aead { iv, aad },
            ) => {
                let parameters = keys::sys::AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS {
                    iv: iv.as_ptr(),
                    iv_len: iv.len(),
                    aad: aad.as_ptr(),
                    aad_len: aad.len(),
                };

                let parameters = keys::sys::AZIOT_KEYS_ENCRYPT_DERIVED_PARAMETERS {
                    derivation_data: derivation_data.as_ptr(),
                    derivation_data_len: derivation_data.len(),
                    mechanism: keys::sys::AZIOT_KEYS_ENCRYPT_MECHANISM_AEAD,
                    parameters: &parameters as *const _ as *const std::ffi::c_void,
                };

                self.keys.decrypt(
                    &id_cstr,
                    keys::sys::AZIOT_KEYS_ENCRYPT_MECHANISM_DERIVED,
                    &parameters as *const _ as *const std::ffi::c_void,
                    ciphertext,
                )?
            }

            _ => {
                return Err(Error::invalid_parameter(
                    "mechanism",
                    "mechanism cannot be used with this key type",
                ))
            }
        };

        Ok(plaintext)
    }
}

/// Decoded from a [`aziot_key_common::KeyHandle`]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
enum KeyId<'a> {
    KeyPair(std::borrow::Cow<'a, str>),
    Key(std::borrow::Cow<'a, str>),
    Derived(
        std::borrow::Cow<'a, aziot_key_common::KeyHandle>,
        std::borrow::Cow<'a, [u8]>,
    ),
}

impl KeyId<'_> {
    fn borrow(&self) -> KeyId<'_> {
        match self {
            KeyId::KeyPair(id) => KeyId::KeyPair(std::borrow::Cow::Borrowed(&**id)),
            KeyId::Key(id) => KeyId::Key(std::borrow::Cow::Borrowed(&**id)),
            KeyId::Derived(base_handle, derivation_data) => KeyId::Derived(
                std::borrow::Cow::Borrowed(&**base_handle),
                std::borrow::Cow::Borrowed(&**derivation_data),
            ),
        }
    }
}

fn master_encryption_key_id() -> &'static std::ffi::CStr {
    const MASTER_ENCRYPTION_KEY_ID_C: &[u8] = b"master-encryption-key\0";
    std::ffi::CStr::from_bytes_with_nul(MASTER_ENCRYPTION_KEY_ID_C)
        .expect("hard-coded key ID is valid CStr")
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Sr<'a> {
    key_id: KeyId<'a>,
    nonce: String,
}

fn key_handle_to_id(
    handle: &aziot_key_common::KeyHandle,
    keys: &mut keys::Keys,
) -> Result<(KeyId<'static>, std::ffi::CString), Error> {
    // DEVNOTE:
    //
    // Map errors from using the master encryption key to Error::Internal instead of relying on `?`,
    // because all errors from using the master encryption key are internal errors.

    let params = handle.0.split('&');

    let mut sr = None;
    let mut sig = None;

    for param in params {
        if let Some(value) = param.strip_prefix("sr=") {
            let value = base64::decode(value.as_bytes())
                .map_err(|_e| Error::invalid_parameter("handle", "invalid handle"))?;
            let value = String::from_utf8(value)
                .map_err(|_e| Error::invalid_parameter("handle", "invalid handle"))?;
            sr = Some(value);
        } else if let Some(value) = param.strip_prefix("sig=") {
            let value = base64::decode(value.as_bytes())
                .map_err(|_e| Error::invalid_parameter("handle", "invalid handle"))?;
            sig = Some(value);
        }
    }

    let sr = sr.ok_or_else(|| Error::invalid_parameter("handle", "invalid handle"))?;
    let sig = sig.ok_or_else(|| Error::invalid_parameter("handle", "invalid handle"))?;

    let master_encryption_key_id = master_encryption_key_id();
    keys.create_key_if_not_exists(master_encryption_key_id, 32)
        .map_err(|err| Error::Internal(InternalError::CreateKeyIfNotExistsGenerate(err)))?;
    let ok = keys
        .verify(
            master_encryption_key_id,
            keys::sys::AZIOT_KEYS_SIGN_MECHANISM_HMAC_SHA256,
            std::ptr::null(),
            sr.as_bytes(),
            &sig,
        )
        .map_err(|err| Error::Internal(InternalError::Verify(err)))?;
    if !ok {
        return Err(Error::invalid_parameter("handle", "invalid handle"));
    }

    let sr: Sr<'static> = serde_json::from_str(&sr)
        .map_err(|_e| Error::invalid_parameter("handle", "invalid handle"))?;

    let id = sr.key_id;

    let id_cstr = match &id {
        KeyId::KeyPair(id) => {
            let id_cstr = std::ffi::CString::new(id.clone().into_owned())
                .map_err(|err| Error::invalid_parameter("handle", err))?;
            id_cstr
        }

        KeyId::Key(id) => {
            let id_cstr = std::ffi::CString::new(id.clone().into_owned())
                .map_err(|err| Error::invalid_parameter("handle", err))?;
            id_cstr
        }

        KeyId::Derived(base_handle, _) => {
            let (_, base_id_cstr) = key_handle_to_id(&base_handle, keys)?;
            base_id_cstr
        }
    };

    Ok((id, id_cstr))
}

fn key_id_to_handle(
    id: &KeyId<'_>,
    keys: &mut keys::Keys,
) -> Result<aziot_key_common::KeyHandle, Error> {
    let sr = {
        let mut nonce = [0_u8; 64];
        openssl::rand::rand_bytes(&mut nonce)
            .map_err(|err| Error::Internal(InternalError::GenerateNonce(err)))?;
        let nonce = base64::encode(&nonce[..]);

        let sr = Sr {
            key_id: id.borrow(),
            nonce,
        };
        let sr = serde_json::to_string(&sr).expect("cannot fail to convert Sr to JSON");
        sr
    };

    let master_encryption_key_id = master_encryption_key_id();
    keys.create_key_if_not_exists(master_encryption_key_id, 32)
        .map_err(|err| Error::Internal(InternalError::CreateKeyIfNotExistsGenerate(err)))?;
    let sig = keys
        .sign(
            master_encryption_key_id,
            keys::sys::AZIOT_KEYS_SIGN_MECHANISM_HMAC_SHA256,
            std::ptr::null(),
            sr.as_bytes(),
        )
        .map_err(|err| Error::Internal(InternalError::Sign(err)))?;

    // TODO: se for expiry

    // This *could* use percent-encoding instead of string concat. However, the only potential problem with base64-encoded values can arise from a trailing =,
    // since = is also used between a key and its value. But that usage of = is not ambiguous, so it isn't a problem.
    let token = format!(
        "sr={}&sig={}",
        base64::encode(sr.as_bytes()),
        base64::encode(&sig)
    );

    let handle = aziot_key_common::KeyHandle(token);
    Ok(handle)
}
