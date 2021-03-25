// Copyright (c) Microsoft. All rights reserved.

use anyhow::{anyhow, Context};
use serde::Serialize;

use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};

pub fn daemons_running() -> impl Iterator<Item = Box<dyn Checker>> {
    let v: Vec<Box<dyn Checker>> = vec![
        Box::new(DaemonRunningKeyd {}),
        Box::new(DaemonRunningCertd {}),
        Box::new(DaemonRunningTpmd {}),
        Box::new(DaemonRunningIdentityd {}),
    ];
    v.into_iter()
}

#[derive(Serialize)]
struct DaemonRunningKeyd {}

#[async_trait::async_trait]
impl Checker for DaemonRunningKeyd {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "keyd-running",
            description: "keyd is running",
        }
    }

    async fn execute(&mut self, _shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        use hyper::service::Service;

        let mut connector = aziot_identityd_config::Endpoints::default().aziot_keyd;
        let res = connector
            .call("keyd.sock".parse().unwrap())
            .await
            .with_context(|| anyhow!("Could not connect to keyd on {}", connector));

        match res {
            Ok(_) => {
                cache.daemons_running.keyd = true;
                CheckResult::Ok
            }
            Err(e) => CheckResult::Failed(e),
        }
    }
}

#[derive(Serialize)]
struct DaemonRunningCertd {}

#[async_trait::async_trait]
impl Checker for DaemonRunningCertd {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "certd-running",
            description: "certd is running",
        }
    }

    async fn execute(&mut self, _shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        use hyper::service::Service;

        let mut connector = aziot_identityd_config::Endpoints::default().aziot_certd;
        let res = connector
            .call("certd.sock".parse().unwrap())
            .await
            .with_context(|| anyhow!("Could not connect to certd on {}", connector));

        match res {
            Ok(_) => {
                cache.daemons_running.certd = true;
                CheckResult::Ok
            }
            Err(e) => CheckResult::Failed(e),
        }
    }
}

#[derive(Serialize)]
struct DaemonRunningTpmd {}

#[async_trait::async_trait]
impl Checker for DaemonRunningTpmd {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "tpmd-running",
            description: "tpmd is running",
        }
    }

    async fn execute(&mut self, _shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        use hyper::service::Service;

        use aziot_identityd_config::{DpsAttestationMethod, ProvisioningType};

        // Only try to connect to the tpmd when using DPS-TPM provisioning
        #[allow(clippy::clippy::match_like_matches_macro)]
        let using_tpmd = match &cache.cfg.identityd {
            Some(config) => match &config.provisioning.provisioning {
                ProvisioningType::Dps {
                    attestation: DpsAttestationMethod::Tpm { .. },
                    ..
                } => true,
                _ => false,
            },
            None => {
                // Check if the prev config happens to use DPS-TPM provisioning
                match &cache.cfg.identityd_prev {
                    Some(cfg) => match &cfg.provisioning.provisioning {
                        ProvisioningType::Dps {
                            attestation: DpsAttestationMethod::Tpm { .. },
                            ..
                        } => true,
                        _ => false,
                    },
                    // there's no way to tell whether or not the user is using tpmd
                    // in this case, let's play it safe and try to connect to tpmd
                    None => true,
                }
            }
        };

        if !using_tpmd {
            return CheckResult::Ignored;
        }

        let mut connector = aziot_identityd_config::Endpoints::default().aziot_tpmd;
        let res = connector
            .call("tpmd.sock".parse().unwrap())
            .await
            .with_context(|| anyhow!("Could not connect to tpmd on {}", connector));

        match res {
            Ok(_) => {
                cache.daemons_running.tpmd = true;
                CheckResult::Ok
            }
            Err(e) => CheckResult::Failed(e),
        }
    }
}

#[derive(Serialize)]
struct DaemonRunningIdentityd {}

#[async_trait::async_trait]
impl Checker for DaemonRunningIdentityd {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "identityd-running",
            description: "identityd is running",
        }
    }

    async fn execute(&mut self, _shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        use hyper::service::Service;

        let mut connector = aziot_identityd_config::Endpoints::default().aziot_identityd;
        let res = connector
            .call("identityd.sock".parse().unwrap())
            .await
            .with_context(|| anyhow!("Could not connect to identityd on {}", connector));

        match res {
            Ok(_) => {
                cache.daemons_running.identityd = true;
                CheckResult::Ok
            }
            Err(e) => CheckResult::Failed(e),
        }
    }
}
