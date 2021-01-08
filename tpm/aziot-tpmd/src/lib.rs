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

use aziot_tpm::Tpm;
use aziot_tpm_common::TpmKeys;
use aziot_tpmd_config::{Config, Endpoints};

use error::{Error, InternalError};

pub async fn main(
    config: Config,
    _: std::path::PathBuf,
    _: std::path::PathBuf,
) -> Result<(http_common::Connector, http::Service), Box<dyn std::error::Error>> {
    let Config {
        endpoints: Endpoints {
            aziot_tpmd: connector,
        },
    } = config;

    let api = Api::new()?;
    let api = std::sync::Arc::new(futures_util::lock::Mutex::new(api));

    let service = http::Service { api };

    Ok((connector, service))
}

pub struct Api {
    tpm: Tpm,
}

impl Api {
    pub fn new() -> Result<Self, Error> {
        Ok(Api {
            tpm: Tpm::new().map_err(|e| Error::Internal(InternalError::InitTpm(e)))?,
        })
    }

    pub fn get_tpm_keys(&mut self) -> Result<TpmKeys, Error> {
        let keys = self
            .tpm
            .get_tpm_keys()
            .map_err(|e| Error::Internal(InternalError::GetTpmKeys(e)))?;
        Ok(TpmKeys {
            endorsement_key: keys.endorsement_key.to_vec(),
            storage_root_key: keys.storage_root_key.to_vec(),
        })
    }

    pub fn sign_with_auth_key(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.tpm
            .sign_with_auth_key(data)
            .map(|digest| digest.to_vec())
            .map_err(|e| Error::Internal(InternalError::SignWithAuthKey(e)))
    }

    pub fn import_auth_key(&mut self, key: &[u8]) -> Result<(), Error> {
        self.tpm
            .import_auth_key(key)
            .map_err(|e| Error::Internal(InternalError::SignWithAuthKey(e)))
    }
}
