// Copyright (c) Microsoft. All rights reserved.

use anyhow::{anyhow, Result};
use serde::Serialize;

use crate::internal::check::util::CertificateValidityExt;
use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};
use crate::internal::common::CertificateValidity;

pub fn cert_expirations() -> impl Iterator<Item = Box<dyn Checker>> {
    let v: Vec<Box<dyn Checker>> = vec![
        Box::new(IdentityCert::default()),
        Box::new(EstIdentityBootstrapCerts::default()),
        Box::new(LocalCaCert::default()),
    ];
    v.into_iter()
}

#[derive(Serialize, Default)]
struct IdentityCert {
    provisioning_mode: Option<&'static str>,
    certificate_info: Option<CertificateValidity>,
}

#[async_trait::async_trait]
impl Checker for IdentityCert {
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

impl IdentityCert {
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
                cert = Some((identity_cert, "DPS identity"));
            }
            ProvisioningType::Manual {
                authentication: ManualAuthMethod::X509 { identity_cert, .. },
                ..
            } => {
                self.provisioning_mode = Some("manual-x509");
                cert = Some((identity_cert, "Manual identity"));
            }
            ProvisioningType::Dps { .. } => self.provisioning_mode = Some("dps-other"),
            ProvisioningType::Manual { .. } => self.provisioning_mode = Some("manual-other"),
            ProvisioningType::None => self.provisioning_mode = Some("none"),
        };

        if let Some((identity_cert, identity_cert_name)) = cert {
            let certd_config = unwrap_or_skip!(&cache.cfg.certd);

            let (res, cert_info) =
                validate_cert(certd_config, identity_cert, identity_cert_name).await?;
            self.certificate_info = cert_info;
            Ok(res)
        } else {
            Ok(CheckResult::Ignored)
        }
    }
}

#[derive(Serialize, Default)]
struct EstIdentityBootstrapCerts {
    identity_certificate_info: Option<CertificateValidity>,
    bootstrap_certificate_info: Option<CertificateValidity>,
}

#[async_trait::async_trait]
impl Checker for EstIdentityBootstrapCerts {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "est-identity-and-bootstrap-certificate-expiry",
            description: "production readiness: EST identity and bootstrap certificates expiry",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        self.inner_execute(shared, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl EstIdentityBootstrapCerts {
    async fn inner_execute(
        &mut self,
        _shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        let certd_config = unwrap_or_skip!(&cache.cfg.certd);

        let certs = certd_config
            .cert_issuance
            .est
            .as_ref()
            .and_then(|est| est.auth.x509.as_ref())
            .map(|x509| {
                (
                    (&x509.identity.cert, "x509 identity"),
                    x509.bootstrap_identity
                        .as_ref()
                        .map(|aziot_certd_config::CertificateWithPrivateKey { cert, .. }|
                            (cert, "x509 bootstrap")
                        ),
                )
            });

        match certs {
            Some((identity, bootstrap)) => {
                let (identity_cert_id, identity_cert_name) = identity;

                let (identity_cert_res, identity_certificate_info) =
                    validate_cert(certd_config, identity_cert_id, identity_cert_name).await?;
                self.identity_certificate_info = identity_certificate_info;

                // TODO: clean this up if a checks ever get the ability to return multiple results
                if !matches!(identity_cert_res, CheckResult::Ok) {
                    return Ok(identity_cert_res);
                }

                if let Some((bootstrap_cert_id, bootstrap_cert_name)) = bootstrap {
                    let (bootstrap_cert_res, bootstrap_certificate_info) =
                        validate_cert(certd_config, bootstrap_cert_id, bootstrap_cert_name).await?;
                    self.bootstrap_certificate_info = bootstrap_certificate_info;

                    if !matches!(bootstrap_cert_res, CheckResult::Ok) {
                        return Ok(bootstrap_cert_res);
                    }
                }

                Ok(CheckResult::Ok)
            }
            None => Ok(CheckResult::Ignored),
        }
    }
}

#[derive(Serialize, Default)]
struct LocalCaCert {
    certificate_info: Option<CertificateValidity>,
}

#[async_trait::async_trait]
impl Checker for LocalCaCert {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "local-ca-certificate-expiry",
            description: "production readiness: Local CA certificates expiry",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        self.inner_execute(shared, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl LocalCaCert {
    async fn inner_execute(
        &mut self,
        _shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        let certd_config = unwrap_or_skip!(&cache.cfg.certd);

        let cert_id = certd_config
            .cert_issuance
            .local_ca
            .as_ref()
            .map(|local_ca| &local_ca.cert);
        let cert_id = match cert_id {
            Some(id) => id,
            None => return Ok(CheckResult::Ignored),
        };

        let (res, cert_info) = validate_cert(certd_config, cert_id, "Local CA").await?;
        self.certificate_info = cert_info;
        Ok(res)
    }
}

/// Validate the certificate is valid, returning `CheckResult::Ok` if the
/// certificate is configured to be dynamically issued, but hasn't been issued
/// yet (i.e: doesn't correspond to a file on-disk yet).
///
/// `cert_name` is only used for friendly error messages.
async fn validate_cert(
    certd_config: &aziot_certd_config::Config,
    cert_id: &str,
    cert_name: &str,
) -> anyhow::Result<(CheckResult, Option<CertificateValidity>)> {
    let path = aziot_certd_config::util::get_path(
        &certd_config.homedir_path,
        &certd_config.preloaded_certs,
        cert_id,
        false,
    )
    .map_err(|e| anyhow!("{}", e))?;

    if path.exists() {
        let cert_info = CertificateValidity::new(path, cert_name, cert_id).await?;
        cert_info
            .to_check_result()
            .map(|res| (res, Some(cert_info)))
    } else if !certd_config.preloaded_certs.contains_key(cert_id)
        && !certd_config.cert_issuance.certs.contains_key(cert_id)
    {
        Err(anyhow!(
            "{} certificate is neither preloaded nor configured to be dynamically issued, and thus cannot be used.",
            cert_name
        ))
    } else {
        Ok((CheckResult::Ok, None))
    }
}
