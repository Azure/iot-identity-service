// Copyright (c) Microsoft. All rights reserved.

use std::fs;
use std::path::Path;

use crate::program_name;

pub enum LastModifiedError {
    Ignored,
    Warning(String),
    Failed(std::io::Error),
}

pub fn check_last_modified(services: &[&str]) -> Result<(), LastModifiedError> {
    let config = Path::new("/etc/aziot/config.toml");

    if !config.exists() {
        return Err(LastModifiedError::Ignored);
    }

    let config_metadata = match fs::metadata(config) {
        Ok(m) => m,
        Err(err) => return Err(LastModifiedError::Failed(err)),
    };

    let config_last_modified = config_metadata
        .modified()
        .expect("file metadata should contain valid last_modified");

    for service in services {
        let service_config = format!("/etc/aziot/{service}/config.d/00-super.toml");
        let service_config = Path::new(&service_config);

        if !service_config.exists() {
            return Err(LastModifiedError::Warning(format!(
                "{} does not exist.\n\
                Did you run '{} config apply'?",
                service_config.display(),
                program_name()
            )));
        }

        let service_config_metadata = match fs::metadata(service_config) {
            Ok(m) => m,
            Err(err) => return Err(LastModifiedError::Failed(err)),
        };

        let service_config_last_modified = service_config_metadata
            .modified()
            .expect("file metadata should contain valid last_modified");

        if config_last_modified > service_config_last_modified {
            return Err(LastModifiedError::Warning(format!(
                "{} was modified after {}'s config\n\
                You must run '{} config apply' to update {}'s config with the latest config.toml",
                config.display(),
                service,
                program_name(),
                service
            )));
        }
    }

    Ok(())
}
