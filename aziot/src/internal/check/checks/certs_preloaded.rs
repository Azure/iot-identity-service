use super::prelude::*;

use aziot_certd::PreloadedCert;

use crate::internal::common::CertificateValidity;

#[derive(Serialize, Default)]
pub struct CertsPreloaded {}

#[async_trait::async_trait]
impl Checker for CertsPreloaded {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "certs-preloaded",
            description: "preloaded certificates are valid",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        self.inner_execute(shared, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl CertsPreloaded {
    async fn inner_execute(
        &mut self,
        _shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        let preloaded_certs = &cache.cfg.unwrap().certd.preloaded_certs;

        for (id, cert) in preloaded_certs {
            let cert_path = match cert {
                // IDs point to other preloaded certs, so there's no need to double-validate
                PreloadedCert::Ids(_) => continue,
                PreloadedCert::Uri(uri) => {
                    if uri.scheme() != "file" {
                        return Err(anyhow!(
                            "only file:// schemes are supported for preloaded certs."
                        ));
                    }
                    uri.path()
                }
            };

            // TODO?: support returning multiple check results from a single check
            // this will require some non-trivial changes to the checker framework, as currently
            // there isn't any way to return a _dynamic_ number of results from a single check.
            match CertificateValidity::new(cert_path, "", &id)
                .await?
                .to_check_result()?
            {
                CheckResult::Ok => {}
                res => return Ok(res),
            }
        }

        Ok(CheckResult::Ok)
    }
}
