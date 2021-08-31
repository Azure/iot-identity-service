// Copyright (c) Microsoft. All rights reserved.

use anyhow::{Error, Result};
use serde::Serialize;

use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};

use std::io;
use std::path::Path;

pub fn well_formed_configs() -> impl Iterator<Item = Box<dyn Checker>> {
    let v: Vec<Box<dyn Checker>> = vec![
        Box::new(WellFormedKeydConfig {}),
        Box::new(WellFormedCertdConfig {}),
        Box::new(WellFormedTpmdConfig {}),
        Box::new(WellFormedIdentitydConfig {}),
    ];
    v.into_iter()
}

#[derive(Serialize)]
struct WellFormedKeydConfig {}

#[async_trait::async_trait]
impl Checker for WellFormedKeydConfig {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "keyd-config-well-formed",
            description: "keyd configuration is well-formed",
        }
    }

    #[allow(clippy::unused_async)]
    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        let daemon_cfg = match load_daemon_cfg(
            "keyd",
            Path::new("/etc/aziot/keyd/config.toml"),
            Some(Path::new("/etc/aziot/keyd/config.d")),
            shared,
        ) {
            Ok(DaemonCfg::Cfg(daemon_cfg)) => daemon_cfg,
            Ok(DaemonCfg::PermissionDenied(e)) => return CheckResult::Fatal(e),
            Err(e) => return CheckResult::Failed(e),
        };

        cache.cfg.keyd = Some(daemon_cfg);
        CheckResult::Ok
    }
}

#[derive(Serialize)]
struct WellFormedCertdConfig {}

#[async_trait::async_trait]
impl Checker for WellFormedCertdConfig {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "certd-config-well-formed",
            description: "certd configuration is well-formed",
        }
    }

    #[allow(clippy::unused_async)]
    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        let daemon_cfg = match load_daemon_cfg(
            "certd",
            Path::new("/etc/aziot/certd/config.toml"),
            Some(Path::new("/etc/aziot/certd/config.d")),
            shared,
        ) {
            Ok(DaemonCfg::Cfg(daemon_cfg)) => daemon_cfg,
            Ok(DaemonCfg::PermissionDenied(e)) => return CheckResult::Fatal(e),
            Err(e) => return CheckResult::Failed(e),
        };

        cache.cfg.certd = Some(daemon_cfg);
        CheckResult::Ok
    }
}

#[derive(Serialize)]
struct WellFormedTpmdConfig {}

#[async_trait::async_trait]
impl Checker for WellFormedTpmdConfig {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "tpmd-config-well-formed",
            description: "tpmd configuration is well-formed",
        }
    }

    #[allow(clippy::unused_async)]
    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        let daemon_cfg = match load_daemon_cfg(
            "tpmd",
            Path::new("/etc/aziot/tpmd/config.toml"),
            Some(Path::new("/etc/aziot/tpmd/config.d")),
            shared,
        ) {
            Ok(DaemonCfg::Cfg(daemon_cfg)) => daemon_cfg,
            Ok(DaemonCfg::PermissionDenied(e)) => return CheckResult::Fatal(e),
            Err(e) => return CheckResult::Failed(e),
        };

        cache.cfg.tpmd = Some(daemon_cfg);
        CheckResult::Ok
    }
}

// DEVNOTE: identityd requires additional post-deserialize validation via it's `.check` method
#[derive(Serialize)]
struct WellFormedIdentitydConfig {}

#[async_trait::async_trait]
impl Checker for WellFormedIdentitydConfig {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "identityd-config-well-formed",
            description: "identityd configuration is well-formed",
        }
    }

    #[allow(clippy::unused_async)]
    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        let daemon_cfg: aziot_identityd_config::Settings = match load_daemon_cfg(
            "identityd",
            Path::new("/etc/aziot/identityd/config.toml"),
            Some(Path::new("/etc/aziot/identityd/config.d")),
            shared,
        ) {
            Ok(DaemonCfg::Cfg(daemon_cfg)) => daemon_cfg,
            Ok(DaemonCfg::PermissionDenied(e)) => return CheckResult::Fatal(e),
            Err(e) => return CheckResult::Failed(e),
        };

        let daemon_cfg = match daemon_cfg.check() {
            Ok(daemon_cfg) => daemon_cfg,
            Err(e) => return CheckResult::Failed(e.into()),
        };

        cache.cfg.identityd = Some(daemon_cfg);

        // At the same time, try to load the backup identityd config.
        // it's okay if it doesn't exist yet.
        match load_daemon_cfg::<aziot_identityd_config::Settings>(
            "identityd_prev",
            Path::new("/var/lib/aziot/identityd/prev_state"),
            None,
            shared,
        ) {
            Ok(DaemonCfg::Cfg(daemon_cfg)) => {
                if let Ok(daemon_cfg) = daemon_cfg.check() {
                    cache.cfg.identityd_prev = Some(daemon_cfg);
                }
            }
            Ok(DaemonCfg::PermissionDenied(_)) | Err(_) => {}
        };

        CheckResult::Ok
    }
}

enum DaemonCfg<T> {
    Cfg(T),
    PermissionDenied(Error),
}

fn load_daemon_cfg<T: serde::de::DeserializeOwned>(
    daemon: &str,
    config_path: &Path,
    config_directory_path: Option<&Path>,
    shared: &CheckerShared,
) -> Result<DaemonCfg<T>> {
    let daemon_cfg = match config_common::read_config(config_path, config_directory_path) {
        Ok(daemon_cfg) => daemon_cfg,

        Err(config_common::Error::ReadConfig(path, err)) => match err.downcast_ref::<io::Error>() {
            Some(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                if let Some(path) = path {
                    return Ok(DaemonCfg::PermissionDenied(
                        anyhow::anyhow!("{}", err)
                            .context(format!("error in file {}", path.display()))
                            .context(
                                "Could not open file. You might need to run this command as root.",
                            ),
                    ));
                }

                return Ok(DaemonCfg::PermissionDenied(
                    anyhow::anyhow!("{}", err).context(
                        "Could not open file. You might need to run this command as root.",
                    ),
                ));
            }

            _ => {
                let message = if shared.cfg.verbose {
                    format!(
                        "{}'s configuration is not well-formed.\n\
                        Note: In case of syntax errors, the error may not be exactly at the reported line number and position.",
                        daemon,
                    )
                } else {
                    format!("{}'s configuration file is not well-formed.", daemon)
                };

                if let Some(path) = path {
                    return Err(anyhow::anyhow!("{}", err)
                        .context(format!("error in file {}", path.display()))
                        .context(message));
                }

                return Err(anyhow::anyhow!("{}", err).context(message));
            }
        },
    };

    Ok(DaemonCfg::Cfg(daemon_cfg))
}
