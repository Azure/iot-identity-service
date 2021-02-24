// Copyright (c) Microsoft. All rights reserved.

use anyhow::{anyhow, Result};
use serde::Serialize;

use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};
use crate::internal::common::load_cert_from_disk;

#[derive(Serialize, Default)]
pub struct RegistrationIdCertCnMatch {
    provisioning_mode: Option<&'static str>,
    registration_id: Option<String>,
    cert_id: Option<String>,
    cert_cn: Option<String>,
}

#[async_trait::async_trait]
impl Checker for RegistrationIdCertCnMatch {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "x509-registration-id-cert-cn-match",
            description:
                "registration_id and certificate CN should match when using x509 provisioning",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        self.inner_execute(shared, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl RegistrationIdCertCnMatch {
    async fn inner_execute(
        &mut self,
        _shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        use aziot_identityd_config::{DpsAttestationMethod, ProvisioningType};

        let certd_config = unwrap_or_skip!(&cache.cfg.certd);
        let identityd_config = unwrap_or_skip!(&cache.cfg.identityd);

        let provisioning = &identityd_config.provisioning.provisioning.clone();

        let (cert_id, registration_id) = match provisioning {
            ProvisioningType::Dps {
                attestation:
                    DpsAttestationMethod::X509 {
                        identity_cert,
                        registration_id,
                        ..
                    },
                ..
            } => {
                self.provisioning_mode = Some("dps-x509");
                (identity_cert, registration_id)
            }
            _ => return Ok(CheckResult::Ignored),
        };

        self.cert_id = Some(cert_id.clone());

        let path = aziot_certd_config::util::get_path(
            &certd_config.homedir_path,
            &certd_config.preloaded_certs,
            cert_id,
            false,
        )
        .map_err(|e| anyhow!("{}", e))?;

        if !path.exists() {
            if !certd_config.preloaded_certs.contains_key(cert_id)
                && !certd_config.cert_issuance.certs.contains_key(cert_id)
            {
                return Ok(CheckResult::Failed(anyhow!(
                    "x509 identity certificate is neither preloaded nor configured to be dynamically issued.",
                )));
            }

            // certificate will be dynamically issued using the provided registration_id
            return Ok(CheckResult::Ok);
        }

        let cert = load_cert_from_disk(path).await?;
        let cn = extract_cn(&cert)?;

        self.cert_cn = Some(cn.clone());

        if &cn != registration_id {
            return Ok(CheckResult::Warning(anyhow!(
                "The x509 identity certificate Common Name (CN) and the provided `registration_id` parameter do not match\n\
                {:?} != {:?}",
                cn, registration_id
            )));
        }

        Ok(CheckResult::Ok)
    }
}

pub fn extract_cn(cert: &openssl::x509::X509) -> anyhow::Result<String> {
    cert.subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .ok_or_else(|| anyhow!("certificate is missing CN"))?
        .data()
        .as_utf8()
        .map(|openssl_str| AsRef::<str>::as_ref(&openssl_str).to_owned())
        .map_err(Into::into)
}
