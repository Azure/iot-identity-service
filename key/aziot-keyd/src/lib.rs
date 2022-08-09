// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_and_return,
    clippy::let_unit_value,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]

use async_trait::async_trait;

mod error;
pub use error::{Error, InternalError};

mod keys;

mod http;

use aziot_keyd_config::{Config, Endpoints, Principal};

use config_common::watcher::UpdateConfig;

#[allow(clippy::unused_async)]
pub async fn main(
    config: Config,
    config_path: std::path::PathBuf,
    config_directory_path: std::path::PathBuf,
) -> Result<(http_common::Connector, http::Service), Box<dyn std::error::Error>> {
    let Config {
        aziot_keys,
        preloaded_keys,
        endpoints: Endpoints {
            aziot_keyd: connector,
        },
        principal,
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

        Api {
            keys,
            principals: principal_to_map(principal),
        }
    };
    let api = std::sync::Arc::new(futures_util::lock::Mutex::new(api));

    config_common::watcher::start_watcher(config_path, config_directory_path, api.clone());

    let service = http::Service { api };

    Ok((connector, service))
}

struct Api {
    keys: keys::Keys,
    principals: std::collections::BTreeMap<libc::uid_t, Vec<wildmatch::WildMatch>>,
}

impl Api {
    pub fn create_key_pair_if_not_exists(
        &mut self,
        id: &str,
        preferred_algorithms: Option<&str>,
        user: libc::uid_t,
    ) -> Result<aziot_key_common::KeyHandle, Error> {
        if !self.authorize(user, id) {
            return Err(Error::Unauthorized(user, id.to_owned()));
        }

        let id_cstr = std::ffi::CString::new(id.to_owned())
            .map_err(|err| Error::invalid_parameter("id", err))?;
        let preferred_algorithms = preferred_algorithms
            .map(|preferred_algorithms| std::ffi::CString::new(preferred_algorithms.to_owned()))
            .transpose()
            .map_err(|err| Error::invalid_parameter("preferred_algorithms", err))?;
        self.keys
            .create_key_pair_if_not_exists(&id_cstr, preferred_algorithms.as_deref())?;

        let handle = key_id_to_handle(&KeyId::KeyPair(id.into()), &mut self.keys)?;
        Ok(handle)
    }

    pub fn move_key_pair(&mut self, from: &str, to: &str, user: libc::uid_t) -> Result<(), Error> {
        // Require the caller to be authorized to modify both keys.
        if !self.authorize(user, from) {
            return Err(Error::Unauthorized(user, from.to_owned()));
        }

        if !self.authorize(user, to) {
            return Err(Error::Unauthorized(user, to.to_owned()));
        }

        let from_cstr = std::ffi::CString::new(from.to_owned())
            .map_err(|err| Error::invalid_parameter("from", err))?;
        let to_cstr = std::ffi::CString::new(to.to_owned())
            .map_err(|err| Error::invalid_parameter("to", err))?;

        self.keys.move_key_pair(&from_cstr, &to_cstr)?;

        Ok(())
    }

    pub fn load_key_pair(
        &mut self,
        id: &str,
        user: libc::uid_t,
    ) -> Result<aziot_key_common::KeyHandle, Error> {
        if !self.authorize(user, id) {
            return Err(Error::Unauthorized(user, id.to_owned()));
        }

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

    pub fn delete_key_pair(&mut self, handle: &aziot_key_common::KeyHandle) -> Result<(), Error> {
        let (id, id_cstr) = key_handle_to_id(handle, &mut self.keys)?;

        match id {
            KeyId::KeyPair(_) => self.keys.delete_key_pair(&id_cstr)?,

            _ => {
                return Err(Error::invalid_parameter(
                    "handle",
                    "handle is not for a key pair",
                ))
            }
        };

        Ok(())
    }

    pub fn create_key_if_not_exists(
        &mut self,
        id: &str,
        value: aziot_key_common::CreateKeyValue,
        usage: &[aziot_key_common::KeyUsage],
        user: libc::uid_t,
    ) -> Result<aziot_key_common::KeyHandle, Error> {
        if !self.authorize(user, id) {
            return Err(Error::Unauthorized(user, id.to_owned()));
        }

        let id_cstr = std::ffi::CString::new(id.to_owned())
            .map_err(|err| Error::invalid_parameter("id", err))?;

        let mut usage_raw = 0;
        for &usage in usage {
            match usage {
                aziot_key_common::KeyUsage::Derive => {
                    usage_raw |= keys::sys::AZIOT_KEYS_KEY_USAGE_DERIVE;
                }
                aziot_key_common::KeyUsage::Encrypt => {
                    usage_raw |= keys::sys::AZIOT_KEYS_KEY_USAGE_ENCRYPT;
                }
                aziot_key_common::KeyUsage::Sign => {
                    usage_raw |= keys::sys::AZIOT_KEYS_KEY_USAGE_SIGN;
                }
            }
        }

        match value {
            aziot_key_common::CreateKeyValue::Generate => {
                self.keys.create_key_if_not_exists(&id_cstr, usage_raw)?;
            }

            aziot_key_common::CreateKeyValue::Import { bytes } => {
                self.keys.import_key(&id_cstr, &bytes, usage_raw)?;
            }
        }

        let handle = key_id_to_handle(&KeyId::Key(id.into()), &mut self.keys)?;
        Ok(handle)
    }

    pub fn load_key(
        &mut self,
        id: &str,
        user: libc::uid_t,
    ) -> Result<aziot_key_common::KeyHandle, Error> {
        if !self.authorize(user, id) {
            return Err(Error::Unauthorized(user, id.to_owned()));
        }

        let id_cstr = std::ffi::CString::new(id.to_owned())
            .map_err(|err| Error::invalid_parameter("id", err))?;
        self.keys.load_key(&id_cstr)?;

        let handle = key_id_to_handle(&KeyId::Key(id.into()), &mut self.keys)?;
        Ok(handle)
    }

    pub fn delete_key(&mut self, handle: &aziot_key_common::KeyHandle) -> Result<(), Error> {
        let (id, id_cstr) = key_handle_to_id(handle, &mut self.keys)?;

        match id {
            KeyId::Key(_) => self.keys.delete_key(&id_cstr)?,

            _ => {
                return Err(Error::invalid_parameter(
                    "handle",
                    "handle is not for a key",
                ))
            }
        };

        Ok(())
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
                    std::ptr::addr_of!(parameters).cast(),
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
                    std::ptr::addr_of!(parameters).cast(),
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
                    parameters: std::ptr::addr_of!(parameters).cast(),
                };

                self.keys.encrypt(
                    &id_cstr,
                    keys::sys::AZIOT_KEYS_ENCRYPT_MECHANISM_DERIVED,
                    std::ptr::addr_of!(parameters).cast(),
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
                    std::ptr::addr_of!(parameters).cast(),
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
                    parameters: std::ptr::addr_of!(parameters).cast(),
                };

                self.keys.decrypt(
                    &id_cstr,
                    keys::sys::AZIOT_KEYS_ENCRYPT_MECHANISM_DERIVED,
                    std::ptr::addr_of!(parameters).cast(),
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

    fn authorize(&self, user: libc::uid_t, id: &str) -> bool {
        // Root user is always authorized.
        if user == 0 {
            return true;
        }

        // Authorize user based on stored principals config.
        if let Some(keys) = self.principals.get(&user) {
            return keys.iter().any(|key| key.matches(id));
        }

        false
    }
}

#[async_trait]
impl UpdateConfig for Api {
    type Config = Config;
    type Error = Error;

    #[allow(clippy::unused_async)]
    async fn update_config(&mut self, new_config: Self::Config) -> Result<(), Self::Error> {
        log::info!("Detected change in config files. Updating config.");

        // Only allow runtime updates to principals.
        let Config {
            aziot_keys: _,
            preloaded_keys: _,
            endpoints: _,
            principal,
        } = new_config;
        self.principals = principal_to_map(principal);

        log::info!("Config update finished.");
        Ok(())
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

fn handle_validation_key_id(keys: &mut keys::Keys) -> Result<&'static std::ffi::CStr, Error> {
    const HANDLE_VALIDATION_KEY_ID_C: &[u8] = b"handle-validation-key\0";
    let handle_validation_key_id = std::ffi::CStr::from_bytes_with_nul(HANDLE_VALIDATION_KEY_ID_C)
        .expect("hard-coded key ID is valid CStr");
    keys.create_key_if_not_exists(
        handle_validation_key_id,
        keys::sys::AZIOT_KEYS_KEY_USAGE_SIGN,
    )
    .map_err(|err| Error::Internal(InternalError::CreateKeyIfNotExistsGenerate(err)))?;
    Ok(handle_validation_key_id)
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
    // Map errors from using the handle validation key to Error::Internal instead of relying on `?`,
    // because all errors from using the handle validation key are internal errors.

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

    let handle_validation_key = handle_validation_key_id(keys)?;
    let ok = keys
        .verify(
            handle_validation_key,
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
            let (_, base_id_cstr) = key_handle_to_id(base_handle, keys)?;
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

    let handle_validation_key = handle_validation_key_id(keys)?;
    let sig = keys
        .sign(
            handle_validation_key,
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

fn principal_to_map(
    principal: Vec<Principal>,
) -> std::collections::BTreeMap<libc::uid_t, Vec<wildmatch::WildMatch>> {
    let mut result: std::collections::BTreeMap<_, Vec<_>> = Default::default();

    for Principal { uid, keys } in principal {
        result
            .entry(uid)
            .or_default()
            .extend(keys.into_iter().map(|key| wildmatch::WildMatch::new(&key)));
    }

    result
}
