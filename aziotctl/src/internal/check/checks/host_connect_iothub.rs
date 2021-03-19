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
        shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        use aziot_identityd_config::ProvisioningType;

        let iothub_hostname = match &shared.cfg.iothub_hostname {
            Some(s) => s,
            None => {
                let iothub_hostname = match &unwrap_or_skip!(&cache.cfg.identityd)
                    .provisioning
                    .provisioning
                {
                    ProvisioningType::Manual {
                        iothub_hostname, ..
                    } => iothub_hostname,
                    ProvisioningType::Dps { .. } => {
                        // It's fine if the prev config doesn't exist, so `unwrap_or_skip` isn't
                        // appropriate here
                        let backup_hostname = match &cache.cfg.identityd_prev {
                            None => None,
                            // check if the backup config includes the iothub_hostname
                            Some(cfg) => match &cfg.provisioning.provisioning {
                                ProvisioningType::Manual {
                                    iothub_hostname, ..
                                } => Some(iothub_hostname),
                                _ => None,
                            },
                        };

                        if let Some(backup_hostname) = backup_hostname {
                            backup_hostname
                        } else {
                            // the user never manually provisioned, nor have they passed
                            // the `iothub-hostname` flag.
                            let reason = "Could not retrieve iothub_hostname from provisioning file.\n\
                            Please specify the backing IoT Hub name using --iothub-hostname switch if you have that information.\n\
                            Since no hostname is provided, all hub connectivity tests will be skipped.";
                            return Ok(CheckResult::Warning(anyhow::Error::msg(reason)));
                        }
                    }
                    _ => return Ok(CheckResult::Ignored),
                };

                self.iothub_hostname = Some(iothub_hostname.clone());
                iothub_hostname
            }
        };

        let iothub_hostname_url = format!("https://{}:{}", iothub_hostname, self.port_number)
            .parse::<hyper::Uri>()
            .context("Invalid URL specified in provisioning.iothub_hostname")?;

        crate::internal::common::resolve_and_tls_handshake(
            iothub_hostname_url,
            &iothub_hostname,
            shared.cfg.proxy_uri.clone(),
        )
        .await.map_err( |e| if iothub_hostname.ends_with(".azure-devices.net") {
            e
        }else
        {
            e.context("Make sure the parent device is reachable using 'curl https://parenthostname'. Make sure the the trust bundle has been added to the trusted store: sudo cp <path>/azure-iot-test-only.root.ca.cert.pem /usr/local/share/ca-certificates/azure-iot-test-only.root.ca.cert.pem.crt
            sudo update-ca-certificates")
        })?;

        Ok(CheckResult::Ok)
    }
}
