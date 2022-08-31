// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_and_return,
    clippy::missing_errors_doc
)]

mod error;
mod http;

use aziot_tpmd_config::{Config, TpmAuthConfig};
use tss_minimal::types::{fill_tpm2b_buffer, sys as types_sys};
use tss_minimal::{EsysContext, Marshal, Persistent, Unmarshal};

use error::{Error, InternalError};

#[allow(clippy::unused_async)]
pub async fn main(
    config: Config,
    _: std::path::PathBuf,
    _: std::path::PathBuf,
) -> Result<(http_common::Incoming, http::Service), Box<dyn std::error::Error>> {
    let api = Api::new(&config).map_err(|e| Error::Internal(InternalError::InitTpm(e)))?;
    let api = std::sync::Arc::new(futures_util::lock::Mutex::new(api));

    let service = http::Service { api };

    let incoming = config
        .endpoints
        .aziot_tpmd
        .incoming(
            http_common::SOCKET_DEFAULT_PERMISSION,
            config.max_requests,
            None,
        )
        .await?;

    Ok((incoming, service))
}

pub struct Api {
    context: EsysContext,
    endorsement_key: Persistent,
    storage_root_key: Persistent,
    auth_key: Option<Persistent>,
    auth_key_index: u32,
}

impl Api {
    pub fn new(config: &Config) -> tss_minimal::Result<Self> {
        let TpmAuthConfig { endorsement, owner } = &config.shared.hierarchy_authorization;

        let endorsement = endorsement.to_bytes_with_nul();
        let owner = owner.to_bytes_with_nul();
        let context = EsysContext::new(&config.shared.tcti)?;

        context.set_auth(
            &Persistent::ENDORSEMENT_HIERARCHY,
            #[allow(clippy::cast_possible_truncation)]
            &types_sys::TPM2B_AUTH {
                // TODO: restrict length in configuration
                size: endorsement.len() as _,
                buffer: fill_tpm2b_buffer(endorsement),
            },
        )?;
        context.set_auth(
            &Persistent::OWNER_HIERARCHY,
            #[allow(clippy::cast_possible_truncation)]
            &types_sys::TPM2B_AUTH {
                // TODO: restrict length in configuration
                size: owner.len() as _,
                buffer: fill_tpm2b_buffer(owner),
            },
        )?;

        let endorsement_key =
            match context.from_tpm_public(tss_minimal::handle::ENDORSEMENT_KEY, None) {
                Ok(handle) => handle,
                Err(e) => {
                    log::error!(
                        "could not read endorsement key from {:#x}: {}",
                        tss_minimal::handle::ENDORSEMENT_KEY,
                        e
                    );
                    let handle = context.create_primary(
                        &Persistent::PASSWORD_SESSION,
                        Persistent::ENDORSEMENT_HIERARCHY,
                        unsafe { &std::mem::zeroed() },
                        &tss_minimal::types::EK_RSA_TEMPLATE,
                        None,
                    )?;
                    context
                        .evict(
                            Persistent::OWNER_HIERARCHY,
                            &handle,
                            &Persistent::PASSWORD_SESSION,
                            tss_minimal::handle::ENDORSEMENT_KEY,
                        )?
                        .expect("existing endorsement key was evicted, but could not be read!")
                }
            };
        let storage_root_key =
            match context.from_tpm_public(tss_minimal::handle::STORAGE_ROOT_KEY, None) {
                Ok(handle) => handle,
                Err(e) => {
                    log::error!(
                        "could not read storage root key from {:#x}: {}",
                        tss_minimal::handle::STORAGE_ROOT_KEY,
                        e
                    );
                    let handle = context.create_primary(
                        &Persistent::PASSWORD_SESSION,
                        Persistent::OWNER_HIERARCHY,
                        unsafe { &std::mem::zeroed() },
                        &tss_minimal::types::SRK_RSA_TEMPLATE,
                        None,
                    )?;
                    context
                        .evict(
                            Persistent::OWNER_HIERARCHY,
                            &handle,
                            &Persistent::PASSWORD_SESSION,
                            tss_minimal::handle::STORAGE_ROOT_KEY,
                        )?
                        .expect("existing storage root key was evicted, but could not be read!")
                }
            };
        let auth_key_index =
            tss_minimal::handle::PERSISTENT_OBJECT_BASE + config.shared.auth_key_index;
        let auth_key = context.from_tpm_public(auth_key_index, None).ok();

        Ok(Self {
            context,
            endorsement_key,
            storage_root_key,
            auth_key,
            auth_key_index,
        })
    }

    pub fn get_tpm_keys(&mut self) -> tss_minimal::Result<(Vec<u8>, Vec<u8>)> {
        let endorsement_public = self.context.read_public(&self.endorsement_key)?;
        let storage_public = self.context.read_public(&self.storage_root_key)?;

        let mut size = 0;
        size.marshal(&*endorsement_public)?;
        let mut endorsement_out = vec![0; size];
        endorsement_out
            .as_mut_slice()
            .marshal(&*endorsement_public)?;

        size.marshal(&*storage_public)?;
        let mut storage_out = vec![0; size];
        storage_out.as_mut_slice().marshal(&*storage_public)?;

        Ok((endorsement_out, storage_out))
    }

    pub fn sign_with_auth_key(&mut self, data: &[u8]) -> tss_minimal::Result<Vec<u8>> {
        let hmac = self.context.hmac(
            self.auth_key.as_ref().unwrap_or(&Persistent::NONE),
            &Persistent::PASSWORD_SESSION,
            types_sys::DEF_TPM2_ALG_SHA256,
            data,
        )?;

        Ok(hmac.buffer[..usize::from(hmac.size)].to_vec())
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn import_auth_key(&mut self, mut key: &[u8]) -> tss_minimal::Result<()> {
        if let Some(handle) = self.auth_key.take() {
            let res = self.context.evict(
                Persistent::OWNER_HIERARCHY,
                &handle,
                &Persistent::PASSWORD_SESSION,
                0,
            );

            if let Err(e) = res {
                // NOTE: It is likely that another process interacting with the
                // TPM evicted the key.
                log::warn!("could not evict previous auth key: {}", e);
            }
        }

        let credential_blob = key.unmarshal()?;
        let secret = key.unmarshal()?;

        let mut ek_auth = self.context.start_auth_session(
            tss_minimal::types::sys::DEF_TPM2_SE_POLICY,
            &types_sys::TPMT_SYM_DEF {
                algorithm: types_sys::DEF_TPM2_ALG_AES,
                keyBits: types_sys::TPMU_SYM_KEY_BITS { aes: 128 },
                mode: types_sys::TPMU_SYM_MODE {
                    aes: types_sys::DEF_TPM2_ALG_CFB,
                },
            },
            types_sys::DEF_TPM2_ALG_SHA256,
        )?;
        tss_minimal::Policy::new(
            tss_minimal::PolicyKind::Secret {
                handle: &Persistent::ENDORSEMENT_HIERARCHY,
                auth: &Persistent::PASSWORD_SESSION,
            },
            &self.context,
        )
        .apply(&mut ek_auth)?;

        let inner = self.context.activate_credential(
            &self.storage_root_key,
            Some(&Persistent::PASSWORD_SESSION),
            &self.endorsement_key,
            Some(&ek_auth),
            &credential_blob,
            &secret,
        )?;

        let id_key_dup_blob = key.unmarshal()?;
        let key_seed = key.unmarshal()?;
        let id_key_public = key.unmarshal()?;

        let id_key_private = self.context.import(
            &self.storage_root_key,
            &Persistent::PASSWORD_SESSION,
            Some(&types_sys::TPM2B_DATA {
                size: inner.size,
                buffer: fill_tpm2b_buffer(&inner.buffer),
            }),
            &id_key_public,
            &id_key_dup_blob,
            &key_seed,
            &types_sys::TPMT_SYM_DEF_OBJECT {
                algorithm: types_sys::DEF_TPM2_ALG_AES,
                keyBits: types_sys::TPMU_SYM_KEY_BITS { aes: 128 },
                mode: types_sys::TPMU_SYM_MODE {
                    aes: types_sys::DEF_TPM2_ALG_CFB,
                },
            },
        )?;

        let auth_key_handle = self.context.load(
            &self.storage_root_key,
            &Persistent::PASSWORD_SESSION,
            &id_key_private,
            &id_key_public,
        )?;

        let auth_key_handle = self
            .context
            .evict(
                Persistent::OWNER_HIERARCHY,
                &auth_key_handle,
                &Persistent::PASSWORD_SESSION,
                self.auth_key_index,
            )?
            .expect("Esys_EvictControl with a transient handle returns a persistent handle");

        self.auth_key = Some(auth_key_handle);

        Ok(())
    }
}
