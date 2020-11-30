use super::prelude::*;

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

    async fn execute(&mut self, checker_cfg: &CheckerCfg, cache: &mut CheckerCache) -> CheckResult {
        self.execute_inner(checker_cfg, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl Hostname {
    async fn execute_inner(
        &mut self,
        _checker_cfg: &CheckerCfg,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        let config_hostname = &cache.cfg.unwrap().identityd.hostname;
        self.config_hostname = Some(config_hostname.clone());

        if config_hostname.parse::<std::net::IpAddr>().is_ok() {
            self.machine_hostname = self.config_hostname.clone();
            // We can only check that it is a valid IP
            return Ok(CheckResult::Ok);
        }

        let machine_hostname = crate::internal::common::get_hostname()?;
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
        if config_hostname != &machine_hostname
            && !config_hostname.starts_with(&format!("{}.", machine_hostname))
        {
            return Err(anyhow!(
                "config.yaml has hostname {} but device reports hostname {}.\n\
                 Hostname in config.yaml must either be identical to the device hostname \
                 or be a fully-qualified domain name that has the device hostname as the first component.",
                config_hostname, machine_hostname,
            ));
        }

        // Some software like the IoT Hub SDKs for downstream clients require the device hostname to follow RFC 1035.
        // For example, the IoT Hub C# SDK cannot connect to a hostname that contains an `_`.
        if !is_rfc_1035_valid(config_hostname) {
            return Ok(CheckResult::Warning(anyhow!(
                "config.yaml has hostname {} which does not comply with RFC 1035.\n\
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
                "config.yaml hostname {} is too long to be used as a certificate issuer",
                config_hostname,
            )));
        }

        Ok(CheckResult::Ok)
    }
}

/// DEVNOTE: duplicated from `iotedge/src/check/hostname_checks_common`
fn is_rfc_1035_valid(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }

    let mut labels = name.split('.');

    let all_labels_valid = labels.all(|label| {
        if label.len() > 63 {
            return false;
        }

        let first_char = match label.chars().next() {
            Some(c) => c,
            None => return false,
        };
        if !first_char.is_ascii_alphabetic() {
            return false;
        }

        if label
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() && c != '-')
        {
            return false;
        }

        let last_char = label
            .chars()
            .last()
            .expect("label has at least one character");
        if !last_char.is_ascii_alphanumeric() {
            return false;
        }

        true
    });
    if !all_labels_valid {
        return false;
    }

    true
}

/// DEVNOTE: duplicated from `iotedge/src/check/hostname_checks_common`
fn check_length_for_local_issuer(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }

    true
}

/// DEVNOTE: duplicated from `iotedge/src/check/hostname_checks_common`
#[cfg(test)]
mod tests {
    use super::check_length_for_local_issuer;
    use super::is_rfc_1035_valid;

    #[test]
    fn test_check_length_for_local_issuer() {
        let longest_valid_label = "a".repeat(64);
        assert!(check_length_for_local_issuer(&longest_valid_label));

        let invalid_label = "a".repeat(65);
        assert!(!check_length_for_local_issuer(&invalid_label));
    }

    #[test]
    fn test_is_rfc_1035_valid() {
        let longest_valid_label = "a".repeat(63);
        let longest_valid_name = format!(
            "{label}.{label}.{label}.{label_rest}",
            label = longest_valid_label,
            label_rest = "a".repeat(255 - 63 * 3 - 3)
        );
        assert_eq!(longest_valid_name.len(), 255);

        assert!(is_rfc_1035_valid("foobar"));
        assert!(is_rfc_1035_valid("foobar.baz"));
        assert!(is_rfc_1035_valid(&longest_valid_label));
        assert!(is_rfc_1035_valid(&format!(
            "{label}.{label}.{label}",
            label = longest_valid_label
        )));
        assert!(is_rfc_1035_valid(&longest_valid_name));
        assert!(is_rfc_1035_valid("xn--v9ju72g90p.com"));
        assert!(is_rfc_1035_valid("xn--a-kz6a.xn--b-kn6b.xn--c-ibu"));

        assert!(is_rfc_1035_valid("FOOBAR"));
        assert!(is_rfc_1035_valid("FOOBAR.BAZ"));
        assert!(is_rfc_1035_valid("FoObAr01.bAz"));

        assert!(!is_rfc_1035_valid(&format!("{}a", longest_valid_label)));
        assert!(!is_rfc_1035_valid(&format!("{}a", longest_valid_name)));
        assert!(!is_rfc_1035_valid("01.org"));
        assert!(!is_rfc_1035_valid("\u{4eca}\u{65e5}\u{306f}"));
        assert!(!is_rfc_1035_valid("\u{4eca}\u{65e5}\u{306f}.com"));
        assert!(!is_rfc_1035_valid("a\u{4eca}.b\u{65e5}.c\u{306f}"));
        assert!(!is_rfc_1035_valid("FoObAr01.bAz-"));
    }
}
