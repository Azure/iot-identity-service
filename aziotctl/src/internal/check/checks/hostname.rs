// Copyright (c) Microsoft. All rights reserved.

use anyhow::{anyhow, Result};
use serde::Serialize;

use aziotctl_common::{check_length_for_local_issuer, is_rfc_1035_valid};

use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};

#[derive(Serialize, Default)]
pub struct Hostname {
    config_hostname: Option<String>,
    machine_hostname: Option<String>,
}

#[async_trait::async_trait]
impl Checker for Hostname {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "hostname",
            description: "identityd config toml file specifies a valid hostname",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        self.execute_inner(shared, cache)
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl Hostname {
    fn execute_inner(
        &mut self,
        _shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        let config_hostname = &unwrap_or_skip!(&cache.cfg.identityd).hostname;
        self.config_hostname = Some(config_hostname.clone());

        if config_hostname.parse::<std::net::IpAddr>().is_ok() {
            self.machine_hostname = self.config_hostname.clone();
            // We can only check that it is a valid IP
            return Ok(CheckResult::Ok);
        }

        let machine_hostname = aziotctl_common::hostname()?;
        self.machine_hostname = Some(machine_hostname.clone());

        // Technically the value of config_hostname doesn't matter as long as it resolves to this device.
        // However determining that the value resolves to *this device* is not trivial.
        //
        // We could start a server and verify that we can connect to ourselves via that hostname, but starting a
        // publicly-available server is not something to be done trivially.
        //
        // We could enumerate the network interfaces of the device and verify that the IP that the hostname resolves to
        // belongs to one of them, but this requires non-trivial OS-specific code
        // (`getifaddrs` on Linux).
        //
        // Instead, we punt on this check and assume that everything's fine if config_hostname is identical to the device hostname,
        // or starts with it.
        {
            let config_hostname = config_hostname.to_lowercase();
            let machine_hostname = machine_hostname.to_lowercase();

            if config_hostname != machine_hostname
                && !config_hostname.starts_with(&format!("{machine_hostname}."))
            {
                return Err(anyhow!(
                    "identityd config has hostname {} but device reports hostname {}.\n\
                    Hostname in identityd config must either be identical to the device hostname \
                    or be a fully-qualified domain name that has the device hostname as the first component.",
                    config_hostname, machine_hostname,
                ));
            }
        }

        // Some software like the IoT Hub SDKs for downstream clients require the device hostname to follow RFC 1035.
        // For example, the IoT Hub C# SDK cannot connect to a hostname that contains an `_`.
        if !is_rfc_1035_valid(config_hostname) {
            return Ok(CheckResult::Warning(anyhow!(
                "identityd config has hostname {} which does not comply with RFC 1035.\n\
                 \n\
                 - Hostname must be between 1 and 255 octets inclusive.\n\
                 - Each label in the hostname (component separated by \".\") must be between 1 and 63 octets inclusive.\n\
                 - Each label must start with an ASCII alphabet character (a-z, A-Z), end with an ASCII alphanumeric character (a-z, A-Z, 0-9), \
                   and must contain only ASCII alphanumeric characters or hyphens (a-z, A-Z, 0-9, \"-\").\n\
                 \n\
                 Not complying with RFC 1035 may cause errors during the TLS handshake with modules and downstream devices.",
                config_hostname,
            )));
        }

        if !check_length_for_local_issuer(config_hostname) {
            return Ok(CheckResult::Warning(anyhow!(
                "identityd config hostname {} is too long to be used as a certificate issuer",
                config_hostname,
            )));
        }

        Ok(CheckResult::Ok)
    }
}
