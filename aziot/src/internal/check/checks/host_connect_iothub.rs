// Copyright (c) Microsoft. All rights reserved.

use anyhow::{Context, Result};
use serde::Serialize;

use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};

pub fn host_connect_iothub_checks() -> impl Iterator<Item = Box<dyn Checker>> {
    let mut v: Vec<Box<dyn Checker>> = Vec::new();

    v.push(Box::new(HostConnectIotHub::new(
        "host-connect-iothub-amqp",
        "host can connect to and perform TLS handshake with iothub AMQP port",
        5671,
    )));
    v.push(Box::new(HostConnectIotHub::new(
        "host-connect-iothub-https",
        "host can connect to and perform TLS handshake with iothub HTTPS / WebSockets port",
        443,
    )));
    v.push(Box::new(HostConnectIotHub::new(
        "host-connect-iothub-mqtt",
        "host can connect to and perform TLS handshake with iothub MQTT port",
        8883,
    )));

    v.into_iter()
}

#[derive(Serialize)]
pub struct HostConnectIotHub {
    port_number: u16,
    iothub_hostname: Option<String>,
    proxy: Option<String>,

    #[serde(skip)]
    meta: CheckerMeta,
}

impl HostConnectIotHub {
    fn new(id: &'static str, description: &'static str, port_number: u16) -> HostConnectIotHub {
        HostConnectIotHub {
            port_number,
            iothub_hostname: None,
            proxy: None,
            meta: CheckerMeta { id, description },
        }
    }
}

#[async_trait::async_trait]
impl Checker for HostConnectIotHub {
    fn meta(&self) -> CheckerMeta {
        self.meta
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        self.inner_execute(shared, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl HostConnectIotHub {
    async fn inner_execute(
        &mut self,
        _shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        use aziot_identityd_config::ProvisioningType;

        let iothub_hostname = match &unwrap_or_skip!(&cache.cfg.identityd)
            .provisioning
            .provisioning
        {
            ProvisioningType::Manual {
                iothub_hostname, ..
            } => iothub_hostname,
            _ => return Ok(CheckResult::Ignored),
        };

        self.iothub_hostname = Some(iothub_hostname.clone());

        let iothub_hostname_url = format!("https://{}:{}", iothub_hostname, self.port_number)
            .parse::<hyper::Uri>()
            .context("Invalid URL specified in provisioning.iothub_hostname")?;

        // TODO: add proxy support once is supported in identityd
        crate::internal::common::resolve_and_tls_handshake(iothub_hostname_url, &iothub_hostname)
            .await?;

        Ok(CheckResult::Ok)
    }
}
