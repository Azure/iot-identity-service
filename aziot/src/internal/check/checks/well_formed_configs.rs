// Copyright (c) Microsoft. All rights reserved.

use super::prelude::*;

use std::path::Path;

use tokio::fs;
use tokio::io;

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
            id: "keyd-config-toml-well-formed",
            description: "keyd config toml file is well-formed",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        let daemon_cfg =
            match load_daemon_cfg("keyd", Path::new("/etc/aziot/keyd/config.toml"), shared).await {
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
            id: "certd-config-toml-well-formed",
            description: "certd config toml file is well-formed",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        let daemon_cfg =
            match load_daemon_cfg("certd", Path::new("/etc/aziot/certd/config.toml"), shared).await
            {
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
            id: "tpmd-config-toml-well-formed",
            description: "tpmd config toml file is well-formed",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        let daemon_cfg =
            match load_daemon_cfg("tpmd", Path::new("/etc/aziot/tpmd/config.toml"), shared).await {
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
            id: "identityd-config-toml-well-formed",
            description: "identityd config toml file is well-formed",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        use aziot_identityd::configext::check;

        let daemon_cfg: aziot_identityd_config::Settings = match load_daemon_cfg(
            "identityd",
            Path::new("/etc/aziot/identityd/config.toml"),
            shared,
        )
        .await
        {
            Ok(DaemonCfg::Cfg(daemon_cfg)) => daemon_cfg,
            Ok(DaemonCfg::PermissionDenied(e)) => return CheckResult::Fatal(e),
            Err(e) => return CheckResult::Failed(e),
        };

        let daemon_cfg = match check(daemon_cfg) {
            Ok(daemon_cfg) => daemon_cfg,
            Err(e) => return CheckResult::Failed(e.into()),
        };

        cache.cfg.identityd = Some(daemon_cfg);
        CheckResult::Ok
    }
}

enum DaemonCfg<T> {
    Cfg(T),
    PermissionDenied(Error),
}

async fn load_daemon_cfg<T: serde::de::DeserializeOwned>(
    daemon: &str,
    path: &Path,
    shared: &CheckerShared,
) -> Result<DaemonCfg<T>> {
    let file_ctx = format!("error in file {}", path.display());

    let mut file = match fs::File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            return Ok(DaemonCfg::PermissionDenied(
                Error::from(e)
                    .context(file_ctx)
                    .context("Could not open file. You might need to run this command as root."),
            ));
        }
        Err(e) => return Err(e).context(file_ctx).context("Could not open file."),
    };

    let mut data = Vec::new();
    if let Err(e) = file.read_to_end(&mut data).await {
        return Err(e).context(file_ctx).context("Could not read file.");
    }

    let daemon_cfg = match toml::from_slice(&data) {
        Ok(daemon_cfg) => daemon_cfg,
        Err(e) => {
            let message = if shared.cfg.verbose {
                format!(
                    "{}'s configuration file is not well-formed.\n\
                     Note: In case of syntax errors, the error may not be exactly at the reported line number and position.",
                    daemon,
                )
            } else {
                format!("{}'s configuration file is not well-formed.", daemon)
            };
            return Err(e).context(file_ctx).context(message);
        }
    };

    Ok(DaemonCfg::Cfg(daemon_cfg))
}
