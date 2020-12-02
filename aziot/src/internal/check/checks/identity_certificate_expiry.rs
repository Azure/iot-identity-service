use super::prelude::*;

#[derive(Serialize, Default)]
pub struct IdentityCertificateExpiry {
    provisioning_mode: Option<&'static str>,
    certificate_info: Option<CertificateValidity>,
}

#[async_trait::async_trait]
impl Checker for IdentityCertificateExpiry {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "host-local-time",
            description: "host time is close to reference time",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        self.inner_execute(shared, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl IdentityCertificateExpiry {
    async fn inner_execute(
        &mut self,
        shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        use aziot_identityd::settings::{DpsAttestationMethod, ManualAuthMethod, ProvisioningType};

        let provisioning = &cache.cfg.unwrap().identityd.provisioning.provisioning;
        match provisioning {
            ProvisioningType::Dps {
                attestation: DpsAttestationMethod::X509 { identity_cert, .. },
                ..
            } => {
                self.provisioning_mode = Some("dps-x509");
                let cert_info = CertificateValidity::new(
                    &shared.cert_client,
                    "DPS identity certificate",
                    identity_cert,
                )
                .await?;
                self.certificate_info = Some(cert_info.clone());
                return cert_info.to_check_result();
            }
            ProvisioningType::Manual {
                authentication: ManualAuthMethod::X509 { identity_cert, .. },
                ..
            } => {
                self.provisioning_mode = Some("manual-x509");
                let cert_info = CertificateValidity::new(
                    &shared.cert_client,
                    "Manual authentication identity certificate",
                    identity_cert,
                )
                .await?;
                self.certificate_info = Some(cert_info.clone());
                return cert_info.to_check_result();
            }
            ProvisioningType::Dps { .. } => self.provisioning_mode = Some("dps-other"),
            ProvisioningType::Manual { .. } => self.provisioning_mode = Some("manual-other"),
            ProvisioningType::None => self.provisioning_mode = Some("none"),
        }

        Ok(CheckResult::Ignored)
    }
}

#[derive(Debug, Serialize, Clone)]
pub(crate) struct CertificateValidity {
    cert_name: String,
    cert_id: String,
    pub(crate) not_after: chrono::DateTime<chrono::Utc>,
    not_before: chrono::DateTime<chrono::Utc>,
}

impl CertificateValidity {
    pub(crate) async fn new(
        cert_client: &aziot_cert_client_async::Client,
        cert_name: &str,
        cert_id: &str,
    ) -> Result<CertificateValidity> {
        fn parse_openssl_time(
            time: &openssl::asn1::Asn1TimeRef,
        ) -> chrono::ParseResult<chrono::DateTime<chrono::Utc>> {
            // openssl::asn1::Asn1TimeRef does not expose any way to convert the ASN1_TIME to a Rust-friendly type
            //
            // Its Display impl uses ASN1_TIME_print, so we convert it into a String and parse it back
            // into a chrono::DateTime<chrono::Utc>
            let time = time.to_string();
            let time = chrono::NaiveDateTime::parse_from_str(&time, "%b %e %H:%M:%S %Y GMT")?;
            Ok(chrono::DateTime::<chrono::Utc>::from_utc(time, chrono::Utc))
        }

        let device_ca_cert = cert_client
            .get_cert(cert_id)
            .await
            .with_context(|| format!("Could not fetch {} from certd", cert_id))?;
        let device_ca_cert = openssl::x509::X509::stack_from_pem(&device_ca_cert)?;
        let device_ca_cert = &device_ca_cert[0];

        let not_after = parse_openssl_time(device_ca_cert.not_after())?;
        let not_before = parse_openssl_time(device_ca_cert.not_before())?;

        Ok(CertificateValidity {
            cert_name: cert_name.to_string(),
            cert_id: cert_id.to_string(),
            not_after,
            not_before,
        })
    }

    fn to_check_result(&self) -> Result<CheckResult> {
        let now = chrono::Utc::now();
        if self.not_before > now {
            Err(anyhow!(
                "{} '{}' has not-before time {} which is in the future",
                self.cert_name,
                self.cert_id,
                self.not_before,
            ))
        } else if self.not_after < now {
            Err(anyhow!(
                "{} '{}' expired at {}",
                self.cert_name,
                self.cert_id,
                self.not_after,
            ))
        } else if self.not_after < now + chrono::Duration::days(7) {
            Ok(CheckResult::Warning(anyhow!(
                "{} '{}' will expire soon ({}, in {} days)",
                self.cert_name,
                self.cert_id,
                self.not_after,
                (self.not_after - now).num_days(),
            )))
        } else {
            Ok(CheckResult::Ok)
        }
    }
}
