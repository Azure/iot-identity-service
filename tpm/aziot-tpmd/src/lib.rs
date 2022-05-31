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
use tss_minimal::handle::FixedHandle;
use tss_minimal::types::{fill_tpm2b_buffer, sys as types_sys};
use tss_minimal::{AuthSession, EsysContext, Handle, Hierarchy, Marshal, Unmarshal};

use error::{Error, InternalError};

#[allow(clippy::unused_async)]
pub async fn main(
    config: Config,
    _: std::path::PathBuf,
    _: std::path::PathBuf,
) -> Result<(http_common::Connector, http::Service), Box<dyn std::error::Error>> {
    let api = Api::new(&config).map_err(|e| Error::Internal(InternalError::InitTpm(e)))?;
    let api = std::sync::Arc::new(futures_util::lock::Mutex::new(api));

    let service = http::Service { api };

    Ok((config.endpoints.aziot_tpmd, service))
}

pub struct Api {
    context: EsysContext,
    endorsement_key: FixedHandle,
    storage_root_key: FixedHandle,
    auth_key: Option<FixedHandle>,
}

impl Api {
    #[allow(clippy::missing_panics_doc)]
    pub fn new(config: &Config) -> tss_minimal::Result<Self> {
        let TpmAuthConfig {
            endorsement,
            storage,
        } = &config.tpm_auth;

        let endorsement = endorsement.to_bytes_with_nul();
        let storage = storage.to_bytes_with_nul();
        let context = EsysContext::new(&config.tcti)?;

        context.set_auth(
            &tss_minimal::Hierarchy::ENDORSEMENT,
            #[allow(clippy::cast_possible_truncation)]
            &types_sys::TPM2B_AUTH {
                // TODO: restrict length in configuration
                size: endorsement.len() as _,
                buffer: fill_tpm2b_buffer(endorsement),
            },
        )?;
        context.set_auth(
            &tss_minimal::Hierarchy::OWNER,
            #[allow(clippy::cast_possible_truncation)]
            &types_sys::TPM2B_AUTH {
                // TODO: restrict length in configuration
                size: storage.len() as _,
                buffer: fill_tpm2b_buffer(storage),
            },
        )?;

        let endorsement_key = match context.from_tpm_public(0x8101_0001, None) {
            Ok(Handle::Fixed(handle)) => handle,
            Ok(_) => panic!("EsysContext::from_tpm_public must return a FixedHandle"),
            Err(e) => return Err(e),
        };
        let storage_root_key = match context.from_tpm_public(0x8100_0001, None) {
            Ok(Handle::Fixed(handle)) => handle,
            Ok(_) => panic!("EsysContext::from_tpm_public must return a FixedHandle"),
            Err(e) => return Err(e),
        };
        let auth_key = match context.from_tpm_public(0x8100_1000, None) {
            Ok(Handle::Fixed(handle)) => Some(handle),
            Ok(_) => panic!("EsysContext::from_tpm_public must return a FixedHandle"),
            _ => None,
        };

        Ok(Self {
            context,
            endorsement_key,
            storage_root_key,
            auth_key,
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
            self.auth_key.as_ref().unwrap_or(&FixedHandle::NONE),
            &tss_minimal::AuthSession::PASSWORD,
            types_sys::DEF_TPM2_ALG_SHA256,
            data,
        )?;

        Ok(hmac.buffer[..usize::from(hmac.size)].to_vec())
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn import_auth_key(&mut self, mut key: &[u8]) -> tss_minimal::Result<()> {
        if let Some(handle) = self.auth_key.take() {
            let res = self.context.evict(
                Hierarchy::OWNER,
                Handle::Fixed(handle),
                &AuthSession::PASSWORD,
                0,
            );

            if let Err(e) = res {
                // NOTE: It is likely that another process interacting with the
                // TPM evicted the key.
                log::warn!("could not evict previous auth key: {e}");
            }
        }

        let credential_blob = key.unmarshal()?;
        let secret = key.unmarshal()?;

        let ek_auth = self
            .context
            .start_auth_session(
                tss_minimal::SessionType::Policy,
                &types_sys::TPMT_SYM_DEF {
                    algorithm: types_sys::DEF_TPM2_ALG_AES,
                    keyBits: types_sys::TPMU_SYM_KEY_BITS { aes: 128 },
                    mode: types_sys::TPMU_SYM_MODE {
                        aes: types_sys::DEF_TPM2_ALG_CFB,
                    },
                },
                types_sys::DEF_TPM2_ALG_SHA256,
            )?
            .with_policy(tss_minimal::Policy::new(
                tss_minimal::PolicyKind::Secret {
                    handle: &Hierarchy::ENDORSEMENT,
                    auth: &AuthSession::PASSWORD,
                },
                &self.context,
            ))?;

        let inner = self.context.activate_credential(
            &self.storage_root_key,
            Some(&AuthSession::PASSWORD),
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
            &AuthSession::PASSWORD,
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
            &AuthSession::PASSWORD,
            &id_key_private,
            &id_key_public,
        )?;

        let auth_key_handle = self
            .context
            .evict(
                Hierarchy::OWNER,
                auth_key_handle,
                &AuthSession::PASSWORD,
                0x8100_1000,
            )?
            .expect("Esys_EvictControl with a transient handle returns a persistent handle");

        if let Handle::Fixed(handle) = auth_key_handle {
            self.auth_key = Some(handle);
        } else {
            panic!("Esys_EvictControl with a transient handle returns a persistent handle");
        }

        Ok(())
    }
}
