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
use tss_minimal::{AuthSession, EsysContext, Handle, Hierarchy};
use tss_minimal::handle::FixedHandle;
use tss_minimal::marshal::Unmarshal;
use tss_minimal::types::{fill_tpm2b_buffer, sys as types_sys};

use error::{Error, InternalError};

#[allow(clippy::unused_async)]
pub async fn main(
    config: Config,
    _: std::path::PathBuf,
    _: std::path::PathBuf,
) -> Result<(http_common::Connector, http::Service), Box<dyn std::error::Error>> {
    let api = Api::new(&config)
        .map_err(|e| Error::Internal(InternalError::InitTpm(e)))?;
    let api = std::sync::Arc::new(futures_util::lock::Mutex::new(api));

    let service = http::Service { api };

    Ok((config.endpoints.aziot_tpmd, service))
}

pub struct Api {
    context: EsysContext,
    endorsement_key: FixedHandle,
    storage_root_key: FixedHandle,
    auth_key: FixedHandle
}

impl Api {
    pub fn new(config: &Config) -> tss_minimal::Result<Self> {
        let TpmAuthConfig {
            endorsement,
            storage
        } = &config.tpm_auth;

        let endorsement = endorsement.to_bytes_with_nul();
        let storage = storage.to_bytes_with_nul();
        let context = EsysContext::new(&config.tcti)?;

        context.set_auth(
            &tss_minimal::Hierarchy::ENDORSEMENT,
            &types_sys::TPM2B_AUTH {
                size: endorsement.len() as _,
                buffer: fill_tpm2b_buffer(endorsement)
            }
        )?;
        context.set_auth(
            &tss_minimal::Hierarchy::OWNER,
            &types_sys::TPM2B_AUTH {
                size: storage.len() as _,
                buffer: fill_tpm2b_buffer(storage)
            }
        )?;

        let endorsement_key = match context.from_tpm_public(0x81010001, None) {
            Ok(Handle::Fixed(handle)) => handle,
            Ok(_) => panic!("EsysContext::from_tpm_public must return a FixedHandle"),
            Err(e) => return Err(e),
        };
        let storage_root_key = match context.from_tpm_public(0x81000001, None) {
            Ok(Handle::Fixed(handle)) => handle,
            Ok(_) => panic!("EsysContext::from_tpm_public must return a FixedHandle"),
            Err(e) =>  return Err(e),
        };
        let auth_key = match context.from_tpm_public(0x81000001, None) {
            Ok(Handle::Fixed(handle)) => handle,
            Ok(_) => panic!("EsysContext::from_tpm_public must return a FixedHandle"),
            _ => FixedHandle::NONE
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

        let endorsement_public = extract_key_data(&endorsement_public);
        let storage_public = extract_key_data(&storage_public);

        Ok((endorsement_public, storage_public))
    }

    pub fn sign_with_auth_key(&mut self, data: &[u8]) -> tss_minimal::Result<Vec<u8>> {
        let hmac = self.context.hmac(
            &self.auth_key,
            &tss_minimal::AuthSession::PASSWORD,
            types_sys::DEF_TPM2_ALG_SHA256,
            data
        )?;

        Ok(hmac.buffer[..usize::from(hmac.size)].to_vec())
    }

    pub fn import_auth_key(&mut self, mut key: &[u8]) -> tss_minimal::Result<()> {
        let credential_blob = key.unmarshal()?;
        let secret = key.unmarshal()?;
        
        let ek_auth = self.context
            .start_auth_session(
                tss_minimal::SessionType::Policy,
                &types_sys::TPMT_SYM_DEF {
                    algorithm: types_sys::DEF_TPM2_ALG_AES,
                    keyBits: types_sys::TPMU_SYM_KEY_BITS {
                        aes: 128
                    },
                    mode: types_sys::TPMU_SYM_MODE {
                        aes: types_sys::DEF_TPM2_ALG_CFB
                    }
                },
                types_sys::DEF_TPM2_ALG_SHA256
            )?
            .with_policy(tss_minimal::Policy::new(
                tss_minimal::PolicyKind::Secret {
                    handle: &Hierarchy::ENDORSEMENT,
                    auth: &AuthSession::PASSWORD
                },
                &self.context
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
                buffer: fill_tpm2b_buffer(&inner.buffer)
            }),
            &id_key_public,
            &id_key_dup_blob,
            &key_seed,
            &types_sys::TPMT_SYM_DEF_OBJECT {
                algorithm: types_sys::DEF_TPM2_ALG_AES,
                keyBits: types_sys::TPMU_SYM_KEY_BITS {
                    aes: 128
                },
                mode: types_sys::TPMU_SYM_MODE {
                    aes: types_sys::DEF_TPM2_ALG_CFB
                }
            },
        )?;

        /*
        let pub_template = types_sys::TPM2B_PUBLIC {
            size: 0,
            publicArea: types_sys::TPMT_PUBLIC {
                type_: types_sys::DEF_TPM2_ALG_SYMCIPHER,
                nameAlg: types_sys::DEF_TPM2_ALG_SHA256,
                objectAttributes:
                    types_sys::DEF_TPMA_OBJECT_FIXEDTPM
                    | types_sys::DEF_TPMA_OBJECT_FIXEDPARENT
                    | types_sys::DEF_TPMA_OBJECT_USERWITHAUTH
                    | types_sys::DEF_TPMA_OBJECT_DECRYPT,
                authPolicy: types_sys::TPM2B_AUTH {
                    size: 0,
                    buffer: fill_tpm2b_buffer(&[])
                },
                parameters: types_sys::TPMU_PUBLIC_PARMS {
                    symDetail: types_sys::TPMS_SYMCIPHER_PARMS {
                        sym: types_sys::TPMT_SYM_DEF_OBJECT {
                            algorithm: types_sys::DEF_TPM2_ALG_AES,
                            keyBits: types_sys::TPMU_SYM_KEY_BITS {
                                sym: inner.size * 8
                            },
                            mode: types_sys::TPMU_SYM_MODE {
                                sym: types_sys::DEF_TPM2_ALG_AES
                            }
                        }
                    }
                },
                unique: types_sys::TPMU_PUBLIC_ID {
                    sym: types_sys::TPM2B_DIGEST {
                        size: 0,
                        buffer: fill_tpm2b_buffer(&[])
                    }
                }
            }
        };
        
        let sen_template = types_sys::TPM2B_SENSITIVE_CREATE {
            size: 0,
            sensitive: types_sys::TPMS_SENSITIVE_CREATE {
                userAuth: types_sys::TPM2B_AUTH {
                    size: 0,
                    buffer: fill_tpm2b_buffer(&[]),
                },
                data: types_sys::TPM2B_SENSITIVE_DATA {
                    size: inner.size,
                    buffer: fill_tpm2b_buffer(&inner.buffer)
                }
            }
        };

        let (key_priv, key_pub) = self.context.create(
            &self.storage_root_key,
            &AuthSession::PASSWORD,
            &sen_template,
            &pub_template,
            None
        )?;
        */

        let auth_key_handle = self.context.load(
            &self.storage_root_key,
            &AuthSession::PASSWORD,
            &id_key_private,
            &id_key_public,
        )?;

        let auth_key_handle = self.context.evict(
            Hierarchy::OWNER,
            auth_key_handle,
            &AuthSession::PASSWORD,
            0x81001000
        )?.expect("Esys_EvictControl with a transient handle returns a persistent handle");

        if let Handle::Fixed(handle) = auth_key_handle {
            self.auth_key = handle;
        } else {
            panic!("Esys_EvictControl with a transient handle returns a persistent handle");
        }

        Ok(())
    }
}

fn extract_key_data(public_area: &types_sys::TPM2B_PUBLIC) -> Vec<u8> {
    match public_area.publicArea.type_ {
        types_sys::DEF_TPM2_ALG_RSA => unsafe {
            let key = public_area.publicArea.unique.rsa;
            key.buffer[..usize::from(key.size)].to_vec()
        },
        types_sys::DEF_TPM2_ALG_ECC => unsafe {
            let points = public_area.publicArea.unique.ecc;
            assert_eq!(points.x.size, points.y.size);
            [
                &points.x.buffer[..usize::from(points.x.size)],
                &points.y.buffer[..usize::from(points.y.size)]
            ].concat()
        }
        _ => panic!("unsupported algorithm type")
    }
}
