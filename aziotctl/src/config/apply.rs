// Copyright (c) Microsoft. All rights reserved.

//! This subcommand takes the super-config file, converts it into the individual services' config files,
//! writes those files, and restarts the services.
//!
//! Note:
//!
//! Inline provisioning symmetric keys are saved to `/var/secrets/aziot/keyd/device-id` in order to be preloaded into the KS.
//! This command creates the directory structure and ACLs the directory and the file to the KS user.

use anyhow::{anyhow, Context};

use aziotctl_common::config as common_config;

#[derive(structopt::StructOpt)]
pub(crate) struct Options {
    /// The path of the config file.
    #[structopt(
        short = "-c",
        long,
        value_name = "CONFIG",
        default_value = "/etc/aziot/config.toml"
    )]
    config: std::path::PathBuf,
}

pub(crate) fn run(options: Options) -> anyhow::Result<()> {
    let Options { config } = options;

    let config = std::fs::read(config).context("could not read config file")?;
    let config = toml::from_slice(&config).context("could not parse config file")?;

    // In production, running as root is the easiest way to guarantee the tool has write access to every service's config file.
    // But it's convenient to not do this for the sake of development because the the development machine doesn't necessarily
    // have the package installed and the users created, and it's easier to have the config files owned by the current user anyway.
    //
    // So when running as root, get the four users appropriately.
    // Otherwise, if this is a debug build, fall back to using the current user.
    // Otherwise, tell the user to re-run as root.
    let (aziotks_user, aziotcs_user, aziotid_user, aziottpm_user) =
        if nix::unistd::Uid::current().is_root() {
            let aziotks_user = nix::unistd::User::from_name("aziotks")
                .context("could not query aziotks user information")?
                .ok_or_else(|| anyhow!("could not query aziotks user information"))?;

            let aziotcs_user = nix::unistd::User::from_name("aziotcs")
                .context("could not query aziotcs user information")?
                .ok_or_else(|| anyhow!("could not query aziotcs user information"))?;

            let aziotid_user = nix::unistd::User::from_name("aziotid")
                .context("could not query aziotid user information")?
                .ok_or_else(|| anyhow!("could not query aziotid user information"))?;

            let aziottpm_user = nix::unistd::User::from_name("aziottpm")
                .context("could not query aziottpm user information")?
                .ok_or_else(|| anyhow!("could not query aziottpm user information"))?;

            (aziotks_user, aziotcs_user, aziotid_user, aziottpm_user)
        } else if cfg!(debug_assertions) {
            let current_user = nix::unistd::User::from_uid(nix::unistd::Uid::current())
                .context("could not query current user information")?
                .ok_or_else(|| anyhow!("could not query current user information"))?;
            (
                current_user.clone(),
                current_user.clone(),
                current_user.clone(),
                current_user,
            )
        } else {
            return Err(anyhow!("this command must be run as root"));
        };

    let common_config::apply::RunOutput {
        keyd_config,
        certd_config,
        identityd_config,
        tpmd_config,
        preloaded_device_id_pk_bytes,
    } = common_config::apply::run(config, aziotcs_user.uid, aziotid_user.uid)?;

    let header = b"\
        # This file is auto-generated by `aziotctl config apply`\n\
        # Do not edit it manually; any edits will be lost when the command is run again.\n\
        \n\
    ";

    let keyd_config: Vec<_> = header
        .iter()
        .copied()
        .chain(toml::to_vec(&keyd_config).context("could not serialize aziot-keyd config")?)
        .collect();
    let certd_config: Vec<_> = header
        .iter()
        .copied()
        .chain(toml::to_vec(&certd_config).context("could not serialize aziot-certd config")?)
        .collect();
    let identityd_config: Vec<_> = header
        .iter()
        .copied()
        .chain(
            toml::to_vec(&identityd_config)
                .context("could not serialize aziot-identityd config")?,
        )
        .collect();
    let tpmd_config: Vec<_> = header
        .iter()
        .copied()
        .chain(toml::to_vec(&tpmd_config).context("could not serialize aziot-tpmd config")?)
        .collect();

    if let Some(preloaded_device_id_pk_bytes) = preloaded_device_id_pk_bytes {
        println!("Note: Symmetric key will be written to /var/secrets/aziot/keyd/device-id");

        common_config::create_dir_all("/var/secrets/aziot/keyd", &aziotks_user, 0o0700)?;
        common_config::write_file(
            "/var/secrets/aziot/keyd/device-id",
            &preloaded_device_id_pk_bytes,
            &aziotks_user,
            0o0600,
        )?;
    }

    common_config::write_file(
        "/etc/aziot/keyd/config.d/00-super.toml",
        &keyd_config,
        &aziotks_user,
        0o0600,
    )?;

    common_config::write_file(
        "/etc/aziot/certd/config.d/00-super.toml",
        &certd_config,
        &aziotcs_user,
        0o0600,
    )?;

    common_config::write_file(
        "/etc/aziot/identityd/config.d/00-super.toml",
        &identityd_config,
        &aziotid_user,
        0o0600,
    )?;

    common_config::write_file(
        "/etc/aziot/tpmd/config.d/00-super.toml",
        &tpmd_config,
        &aziottpm_user,
        0o0600,
    )?;

    println!("Azure IoT Identity Service has been configured successfully!");
    println!();
    println!("Restarting service for configuration to take effect...");
    aziotctl_common::restart(aziotctl_common::SERVICE_DEFINITIONS)?;
    println!("Done.");

    Ok(())
}
