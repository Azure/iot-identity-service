use super::prelude::*;

use crate::internal::common::CertificateValidity;

#[derive(Serialize, Default)]
pub struct IdentityCertificateExpiry {
    provisioning_mode: Option<&'static str>,
    certificate_info: Option<CertificateValidity>,
}

#[async_trait::async_trait]
impl Checker for IdentityCertificateExpiry {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "identity-certificate-expiry",
            description: "production readiness: identity certificates expiry",
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
        _shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        use aziot_identityd::settings::{DpsAttestationMethod, ManualAuthMethod, ProvisioningType};

        let provisioning = &cache
            .cfg
            .unwrap()
            .identityd
            .provisioning
            .provisioning
            .clone();

        match provisioning {
            ProvisioningType::Dps {
                attestation: DpsAttestationMethod::X509 { identity_cert, .. },
                ..
            } => {
                self.provisioning_mode = Some("dps-x509");
                let cert_info = CertificateValidity::new(
                    cache.cert_path(identity_cert)?,
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
                    cache.cert_path(identity_cert)?,
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
