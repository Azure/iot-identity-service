// Copyright (c) Microsoft. All rights reserved.

use std::path::Path;

use aziot_identityd_config as config;

use crate::error::InternalError;

pub fn load_file(filename: &Path) -> Result<config::Settings, InternalError> {
    let settings = std::fs::read_to_string(filename).map_err(InternalError::LoadSettings)?;
    let settings: config::Settings =
        toml::from_str(&settings).map_err(InternalError::ParseSettings)?;

    check(settings)
}

pub fn check(settings: config::Settings) -> Result<config::Settings, InternalError> {
    let mut existing_names: std::collections::BTreeSet<aziot_identity_common::ModuleId> =
        std::collections::BTreeSet::default();

    for p in &settings.principal {
        if !existing_names.insert(p.name.clone()) {
            return Err(InternalError::BadSettings(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("duplicate module name: {}", p.name.0),
            )));
        }

        if let Some(t) = &p.id_type {
            if t.contains(&aziot_identity_common::IdType::Local) {
                // Require localid in config if any principal has local id_type.
                if settings.localid.is_none() {
                    return Err(InternalError::BadSettings(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "invalid config for {}: local id type requires localid config",
                            p.name.0
                        ),
                    )));
                }
            } else {
                // Reject principals that specify local identity options without the "local" type.
                if p.localid.is_some() {
                    return Err(InternalError::BadSettings(std::io::Error::new(
						std::io::ErrorKind::InvalidInput,
						format!("invalid config for {}: local identity options specified for non-local identity", p.name.0)
					)));
                }
            }

            // Require provisioning if any module or device identities are present.
            let provisioning_valid = match settings.provisioning.provisioning {
                config::ProvisioningType::None => {
                    !t.contains(&aziot_identity_common::IdType::Module)
                        && !t.contains(&aziot_identity_common::IdType::Device)
                }
                _ => true,
            };

            if !provisioning_valid {
                return Err(InternalError::BadSettings(std::io::Error::new(
						std::io::ErrorKind::InvalidInput,
						format!("invalid config for {}: module or device identity requires provisioning with IoT Hub", p.name.0)
					))
				);
            }
        }
    }

    Ok(settings)
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
