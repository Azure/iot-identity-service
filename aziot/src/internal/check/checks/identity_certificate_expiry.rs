// Copyright (c) Microsoft. All rights reserved.

use anyhow::{anyhow, Result};
use serde::Serialize;

use crate::internal::check::util::CertificateValidityExt;
use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};
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
        use aziot_identityd_config::{DpsAttestationMethod, ManualAuthMethod, ProvisioningType};

        let provisioning = &unwrap_or_skip!(&cache.cfg.identityd)
            .provisioning
            .provisioning
            .clone();

        let mut cert = None;
        match provisioning {
            ProvisioningType::Dps {
                attestation: DpsAttestationMethod::X509 { identity_cert, .. },
                ..
            } => {
                self.provisioning_mode = Some("dps-x509");
                cert = Some((identity_cert, "DPS identity certificate"));
            }
            ProvisioningType::Manual {
                authentication: ManualAuthMethod::X509 { identity_cert, .. },
                ..
            } => {
                self.provisioning_mode = Some("manual-x509");
                cert = Some((identity_cert, "Manual identity certificate"));
            }
            ProvisioningType::Dps { .. } => self.provisioning_mode = Some("dps-other"),
            ProvisioningType::Manual { .. } => self.provisioning_mode = Some("manual-other"),
            ProvisioningType::None => self.provisioning_mode = Some("none"),
        };

        if let Some((identity_cert, identity_cert_name)) = cert {
            let certd_config = unwrap_or_skip!(&cache.cfg.certd);

            let path = aziot_certd_config::util::get_path(
                &certd_config.homedir_path,
                &certd_config.preloaded_certs,
                identity_cert,
                false,
            )
            .map_err(|e| anyhow!("{}", e))?;

            if path.exists() {
                let cert_info =
                    CertificateValidity::new(path, identity_cert_name, &identity_cert).await?;
                self.certificate_info = Some(cert_info.clone());
                cert_info.to_check_result()
            } else if !certd_config.preloaded_certs.contains_key(identity_cert)
                && !certd_config.cert_issuance.certs.contains_key(identity_cert)
            {
                Err(anyhow!(
                    "identity cert is not manually specified, nor is it dynamically issued"
                ))
            } else {
                Ok(CheckResult::Ok)
            }
        } else {
            Ok(CheckResult::Ignored)
        }
    }
}
