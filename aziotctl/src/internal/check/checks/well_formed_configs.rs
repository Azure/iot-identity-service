// Copyright (c) Microsoft. All rights reserved.

use anyhow::{Error, Result};
use serde::Serialize;

use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};
use nix::unistd::{Gid, Group, Uid, User};
use std::fs;
use std::io;
use std::path::Path;

pub fn well_formed_configs() -> impl Iterator<Item = Box<dyn Checker>> {
    let mut v: Vec<Box<dyn Checker>> = Vec::new();

    v.push(Box::new(WellFormedKeydConfig {}));
    v.push(Box::new(WellFormedCertdConfig {}));
    v.push(Box::new(WellFormedTpmdConfig {}));
    v.push(Box::new(WellFormedIdentitydConfig {}));

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

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        let daemon_cfg = match load_daemon_cfg(
            "keyd",
            "aziotks",
            Path::new("/etc/aziot/keyd/config.toml"),
            Some(Path::new("/etc/aziot/keyd/config.d")),
            shared,
        )
        .await
        {
            Ok(DaemonCfg::Cfg(daemon_cfg)) => daemon_cfg,
            Ok(DaemonCfg::PermissionDenied(e))
            | Ok(DaemonCfg::IncorrectPermissions(e))
            | Ok(DaemonCfg::IncorrectGroupId(e))
            | Ok(DaemonCfg::IncorrectUserID(e)) => return CheckResult::Fatal(e),
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

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        let daemon_cfg = match load_daemon_cfg(
            "certd",
            "aziotcs",
            Path::new("/etc/aziot/certd/config.toml"),
            Some(Path::new("/etc/aziot/certd/config.d")),
            shared,
        )
        .await
        {
            Ok(DaemonCfg::Cfg(daemon_cfg)) => daemon_cfg,
            Ok(DaemonCfg::PermissionDenied(e))
            | Ok(DaemonCfg::IncorrectPermissions(e))
            | Ok(DaemonCfg::IncorrectGroupId(e))
            | Ok(DaemonCfg::IncorrectUserID(e)) => return CheckResult::Fatal(e),
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

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        let daemon_cfg = match load_daemon_cfg(
            "tpmd",
            "aziottpm",
            Path::new("/etc/aziot/tpmd/config.toml"),
            Some(Path::new("/etc/aziot/tpmd/config.d")),
            shared,
        )
        .await
        {
            Ok(DaemonCfg::Cfg(daemon_cfg)) => daemon_cfg,
            Ok(DaemonCfg::PermissionDenied(e))
            | Ok(DaemonCfg::IncorrectPermissions(e))
            | Ok(DaemonCfg::IncorrectGroupId(e))
            | Ok(DaemonCfg::IncorrectUserID(e)) => return CheckResult::Fatal(e),
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

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        let daemon_cfg: aziot_identityd_config::Settings = match load_daemon_cfg(
            "identityd",
            "aziotid",
            Path::new("/etc/aziot/identityd/config.toml"),
            Some(Path::new("/etc/aziot/identityd/config.d")),
            shared,
        )
        .await
        {
            Ok(DaemonCfg::Cfg(daemon_cfg)) => daemon_cfg,
            Ok(DaemonCfg::PermissionDenied(e))
            | Ok(DaemonCfg::IncorrectPermissions(e))
            | Ok(DaemonCfg::IncorrectGroupId(e))
            | Ok(DaemonCfg::IncorrectUserID(e)) => return CheckResult::Fatal(e),
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
            "aziotid",
            Path::new("/var/lib/aziot/identityd/prev_state"),
            None,
            shared,
        )
        .await
        {
            Ok(DaemonCfg::Cfg(daemon_cfg)) => {
                if let Ok(daemon_cfg) = daemon_cfg.check() {
                    cache.cfg.identityd_prev = Some(daemon_cfg);
                }
            }
            Ok(_) | Err(_) => {}
        };

        CheckResult::Ok
    }
}

enum DaemonCfg<T> {
    Cfg(T),
    PermissionDenied(Error),
    IncorrectPermissions(Error),
    IncorrectGroupId(Error),
    IncorrectUserID(Error),
}

async fn load_daemon_cfg<T: serde::de::DeserializeOwned>(
    daemon: &str,
    uid: &str,
    config_path: &Path,
    config_directory_path: Option<&Path>,
    shared: &CheckerShared,
) -> Result<DaemonCfg<T>> {
    use std::os::linux::fs::MetadataExt;
    if let Ok(metadata) = fs::metadata(config_path) {
        if !metadata.permissions().readonly() {
            return Ok(DaemonCfg::IncorrectPermissions(anyhow::anyhow!(
                "The file {} must be read only. Please run 'sudo chmod 0444 {}'",
                config_path.to_string_lossy(),
                config_path.to_string_lossy()
            )));
        }

        let user = match User::from_uid(Uid::from_raw(metadata.st_uid())) {
            Ok(Some(user)) => user.name,
            Err(_) | Ok(None) => {
                return Err(anyhow::anyhow!(format!(
                    "Could not find user assigned to {}",
                    config_path.to_string_lossy()
                )))
            }
        };

        let group = match Group::from_gid(Gid::from_raw(metadata.st_gid())) {
            Ok(Some(group)) => group.name,
            Err(_) | Ok(None) => {
                return Err(anyhow::anyhow!(format!(
                    "Could not find user group assigned to {}.",
                    config_path.to_string_lossy()
                )))
            }
        };

        if !user.eq(uid) {
            return Ok(DaemonCfg::IncorrectUserID(anyhow::anyhow!(
                "The file {} has user {}, expected {}. Please run 'sudo chown {} {}'",
                config_path.to_string_lossy(),
                user,
                uid,
                uid,
                config_path.to_string_lossy()
            )));
        }

        if !group.eq(uid) {
            return Ok(DaemonCfg::IncorrectGroupId(anyhow::anyhow!(
                "The file {} has group {}, expected {}. Please run 'sudo chgrp {} {}' ",
                config_path.to_string_lossy(),
                group,
                uid,
                uid,
                config_path.to_string_lossy()
            )));
        }
    }

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
