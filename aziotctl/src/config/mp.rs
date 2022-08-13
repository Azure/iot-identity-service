// Copyright (c) Microsoft. All rights reserved.

//! This subcommand takes a connection string and writes out the super-config file
//! configured to use manual provisioning with that connection string.
//! All other settings are left as their defaults.

use anyhow::{anyhow, Context};

use aziotctl_common::config as common_config;

#[derive(structopt::StructOpt)]
pub(crate) struct Options {
    /// The connection string
    #[structopt(short = "c", long, value_name = "CONNECTION_STRING")]
    connection_string: String,

    /// The path of the system configuration file to write to
    #[structopt(
        short = "o",
        long,
        value_name = "FILE",
        default_value = "/etc/aziot/config.toml"
    )]
    out_config_file: std::path::PathBuf,

    /// Overwrite the new configuration file if it already exists
    #[structopt(short = "f", long)]
    force: bool,
}

pub(crate) fn run(options: Options) -> anyhow::Result<()> {
    let Options {
        connection_string,
        out_config_file,
        force,
    } = options;

    if !force && out_config_file.exists() {
        return Err(anyhow!(
            "\
File {} already exists. Azure IoT Identity Service has already been configured.

To have the configuration take effect, run:

    sudo aziotctl config apply

To reconfigure IoT Identity Service, run:

    sudo aziotctl config mp --force
",
            out_config_file.display()
        ));
    }

    let config = common_config::super_config::Config {
        hostname: None,
        parent_hostname: None,

        provisioning: common_config::super_config::Provisioning {
            provisioning: common_config::super_config::ProvisioningType::Manual {
                inner: common_config::super_config::ManualProvisioning::ConnectionString {
                    connection_string: common_config::super_config::ConnectionString::new(
                        connection_string,
                    )
                    .map_err(|e| anyhow!("invalid connection string: {}", e))?,
                },
            },
        },

        localid: None,

        cloud_timeout_sec: aziot_identityd_config::Settings::default_cloud_timeout(),

        cloud_retries: aziot_identityd_config::Settings::default_cloud_retries(),

        aziot_max_requests: Default::default(),

        aziot_keys: Default::default(),

        preloaded_keys: Default::default(),

        cert_issuance: Default::default(),

        preloaded_certs: Default::default(),

        tpm: Default::default(),

        endpoints: Default::default(),
    };
    let config = toml::to_vec(&config).context("could not serialize system config")?;

    let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .context("could not query current user information")?
        .ok_or_else(|| anyhow!("could not query current user information"))?;

    common_config::write_file(&out_config_file, &config, &user, 0o0600)?;

    println!("Azure IoT Identity Service has been configured successfully!");
    println!(
        "The configuration has been written to {}",
        out_config_file.display()
    );
    println!("To apply the new configuration to services, run:");
    println!();
    println!(
        "    sudo aziotctl config apply -c '{}'",
        out_config_file.display()
    );

    Ok(())
}
