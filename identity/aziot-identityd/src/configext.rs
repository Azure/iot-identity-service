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
