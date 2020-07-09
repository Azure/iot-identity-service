// Copyright (c) Microsoft. All rights reserved.

use std::ffi::{OsStr, OsString};

use clap::{crate_description, crate_name, crate_version, App, Arg};
use log::info;

use crate::error::Error;
use crate::logging;
use crate::settings::Settings;

fn create_app<'a>(default_config_file: &'a OsStr) -> App<'a, 'a> {
    App::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .arg(
            Arg::with_name("config-file")
                .short("c")
                .long("config-file")
                .value_name("FILE")
                .help("Sets daemon configuration file")
                .takes_value(true)
                .default_value_os(default_config_file),
        )
}

pub fn init() -> Result<Settings, Error> {
    let default_config_file = OsString::from("/etc/aziot/identityd/config.toml");

    let matches = create_app(&default_config_file).get_matches();

    logging::init();

    info!("Starting Azure IoT Identity Service Daemon");
    info!("Version - {}", "1.0");

    let config_file: std::path::PathBuf = matches
        .value_of_os("config-file")
        .expect("arg has a default value")
        .to_os_string()
        .into();

    info!("Using config file: {}", config_file.display());

    let settings = init_idservice(&config_file)?;

    //TODO: Return a common object and call it for provisioning from IS
    aziot_common::init(&config_file)?;

    Ok(settings)
}

fn init_idservice(config_file: &std::path::Path) -> Result<Settings, Error> {
    let settings = Settings::new(&config_file)?;

    Ok(settings)
}
