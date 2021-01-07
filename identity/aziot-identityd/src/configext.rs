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

pub fn prepare_authorized_principals(
    principal: &[config::Principal],
) -> (
    std::collections::BTreeMap<config::Uid, config::Principal>,
    std::collections::BTreeSet<aziot_identity_common::ModuleId>,
    std::collections::BTreeMap<
        aziot_identity_common::ModuleId,
        Option<aziot_identity_common::LocalIdOpts>,
    >,
) {
    let mut local_module_map: std::collections::BTreeMap<
        aziot_identity_common::ModuleId,
        Option<aziot_identity_common::LocalIdOpts>,
    > = std::collections::BTreeMap::new();
    let mut hub_module_set: std::collections::BTreeSet<aziot_identity_common::ModuleId> =
        std::collections::BTreeSet::new();
    let mut principal_map: std::collections::BTreeMap<config::Uid, config::Principal> =
        std::collections::BTreeMap::new();
    let mut found_daemon = false;

    for p in principal {
        if let Some(id_type) = &p.id_type {
            for i in id_type {
                match i {
                    aziot_identity_common::IdType::Module => hub_module_set.insert(p.name.clone()),
                    aziot_identity_common::IdType::Local => local_module_map
                        .insert(p.name.clone(), p.localid.clone())
                        .is_some(),
                    _ => true,
                };
            }
        } else if found_daemon {
            log::warn!("Principal {:?} is not authorized. Please ensure there is only one principal without a type in the config.toml", p.name);
            continue;
        } else {
            found_daemon = true
        }

        principal_map.insert(p.uid, p.clone());
    }

    (principal_map, hub_module_set, local_module_map)
}
