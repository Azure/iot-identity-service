// Copyright (c) Microsoft. All rights reserved.

use std::{
    ffi::{OsStr, OsString},
    path::PathBuf,
};

use clap::{crate_description, crate_name, crate_version, App, Arg};
use log::info;

use crate::error::InternalError;
use crate::logging;

fn create_app(default_config_file: &OsStr) -> App<'_, '_> {
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

pub fn init() -> Result<PathBuf, InternalError> {
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

    Ok(config_file)
}
