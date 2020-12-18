// Copyright (c) Microsoft. All rights reserved.

use super::prelude::*;

#[derive(Serialize, Default)]
pub struct HostConnectDpsEndpoint {
    dps_endpoint: Option<String>,
    dps_hostname: Option<String>,
    proxy: Option<String>,
}

#[async_trait::async_trait]
impl Checker for HostConnectDpsEndpoint {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "host-connect-dps-endpoint",
            description: "host can connect to and perform TLS handshake with DPS endpoint",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        self.inner_execute(shared, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl HostConnectDpsEndpoint {
    async fn inner_execute(
        &mut self,
        _shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        use aziot_identityd_config::ProvisioningType;

        let dps_endpoint = match &unwrap_or_skip!(&cache.cfg.identityd)
            .provisioning
            .provisioning
        {
            ProvisioningType::Dps {
                global_endpoint, ..
            } => global_endpoint,
            _ => return Ok(CheckResult::Ignored),
        };

        self.dps_endpoint = Some(dps_endpoint.clone());

        let dps_endpoint = dps_endpoint
            .parse::<hyper::Uri>()
            .context("Invalid URL specified in provisioning.global_endpoint")?;

        let dps_hostname = dps_endpoint
            .host()
            .ok_or_else(|| {
                anyhow!("URL specified in provisioning.global_endpoint does not have a host")
            })?
            .to_owned();
        self.dps_hostname = Some(dps_hostname.clone());

        // TODO: add proxy support once is supported in identityd
        crate::internal::common::resolve_and_tls_handshake(dps_endpoint, &dps_hostname).await?;

        Ok(CheckResult::Ok)
    }
}
