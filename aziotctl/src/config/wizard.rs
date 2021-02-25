// Copyright (c) Microsoft. All rights reserved.

//! This subcommand interactively asks the user to give out basic provisioning information for their device and
//! creates the config files for the four services based on that information.
//!
//! Notes:
//!
//! - Provisioning with a symmetric key (manual or DPS) requires the key to be preloaded into KS, which means it needs to be
//!   saved to a file. This subcommand uses a file named `/var/secrets/aziot/keyd/device-id` for that purpose.
//!   It creates the directory structure and ACLs the directory and the file appropriately to the KS user.
//!
//! - `always_reprovision_on_startup` is enabled by default in IS provisioning settings.
//!
//! - This implementation assumes that Microsoft's implementation of libaziot-keys is being used, in that it generates the keyd config
//!   with the `aziot_keys.homedir_path` property set, and with validation that the preloaded keys must be `file://` or `pkcs11:` URIs.

use anyhow::{anyhow, Context, Result};

use aziotctl_common::config as common_config;

pub(crate) fn run() -> Result<()> {
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

    for &f in &[
        "/etc/aziot/certd/config.toml",
        "/etc/aziot/identityd/config.toml",
        "/etc/aziot/keyd/config.toml",
        "/etc/aziot/tpmd/config.toml",
    ] {
        // Don't overwrite any of the configs if they already exist.
        //
        // It would be less racy to test this right before we're about to overwrite the files, but by then we'll have asked the user
        // all of the questions and it would be a waste to give up.
        if std::path::Path::new(f).exists() {
            return Err(anyhow!(
                    "\
                    Cannot run because file {} already exists. \
                    Delete this file (after taking a backup if necessary) before running this command.\
                ",
                f
            ));
        }
    }

    println!("Welcome to the configuration tool for Azure IoT Identity Service.");
    println!();
    println!(
        "This command will set up the configurations for aziot-identityd and related services."
    );
    println!();

    let mut stdin: common_config::wizard::Stdin = Default::default();

    let common_config::wizard::RunOutput {
        keyd_config,
        certd_config,
        identityd_config,
        tpmd_config,
        preloaded_device_id_pk_bytes,
    } = common_config::wizard::run(&mut stdin, aziotcs_user.uid, aziotid_user.uid)?;

    let keyd_config =
        toml::to_vec(&keyd_config).context("could not serialize aziot-keyd config")?;
    let certd_config =
        toml::to_vec(&certd_config).context("could not serialize aziot-certd config")?;
    let identityd_config =
        toml::to_vec(&identityd_config).context("could not serialize aziot-identityd config")?;
    let tpmd_config =
        toml::to_vec(&tpmd_config).context("could not serialize aziot-certd config")?;

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
        "/etc/aziot/keyd/config.toml",
        &keyd_config,
        &aziotks_user,
        0o0600,
    )?;

    common_config::write_file(
        "/etc/aziot/certd/config.toml",
        &certd_config,
        &aziotcs_user,
        0o0600,
    )?;

    common_config::write_file(
        "/etc/aziot/identityd/config.toml",
        &identityd_config,
        &aziotid_user,
        0o0600,
    )?;

    common_config::write_file(
        "/etc/aziot/tpmd/config.toml",
        &tpmd_config,
        &aziottpm_user,
        0o0600,
    )?;

    println!("aziot-identity-service has been configured successfully!");
    println!(
        "You can find the configured files at /etc/aziot/{{key,cert,identity,tpm}}d/config.toml"
    );

    Ok(())
}
