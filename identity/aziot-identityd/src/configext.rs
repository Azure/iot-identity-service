// Copyright (c) Microsoft. All rights reserved.

use std::path::Path;

use aziot_identityd_config as config;

use crate::error::InternalError;

pub fn load_file(filename: &Path) -> Result<config::Settings, InternalError> {
    let settings = std::fs::read_to_string(filename).map_err(InternalError::LoadSettings)?;
    let settings: config::Settings =
        toml::from_str(&settings).map_err(InternalError::ParseSettings)?;

    settings.check().map_err(InternalError::BadSettings)
}

#[derive(Debug, Eq, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
pub struct HubDeviceInfo {
    pub hub_name: String,

    pub device_id: String,
}

impl HubDeviceInfo {
    pub fn new(filename: &Path) -> Result<Option<Self>, InternalError> {
        let info = std::fs::read_to_string(filename).map_err(InternalError::LoadDeviceInfo)?;

        let info = match info.as_str() {
            "unprovisioned" => None,
            _ => Some(toml::from_str(&info).map_err(InternalError::ParseDeviceInfo)?),
        };

        Ok(info)
    }

    pub fn unprovisioned() -> String {
        "unprovisioned".to_owned()
    }
}
