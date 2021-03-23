// Copyright (c) Microsoft. All rights reserved.

use anyhow::{anyhow, Context, Result};
use serde::Serialize;

use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};

#[derive(Serialize, Default)]
pub struct ReadCerts {}

#[async_trait::async_trait]
impl Checker for ReadCerts {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "certs-read",
            description: "read all preloaded certificates from the Certificates Service",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        self.inner_execute(shared, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl ReadCerts {
    async fn inner_execute(
        &mut self,
        _shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        let aziot_certd_config::Config {
            endpoints: aziot_certd_config::Endpoints { aziot_certd, .. },
            preloaded_certs,
            ..
        } = unwrap_or_skip!(&cache.cfg.certd);
        let () = unwrap_or_skip!(&cache.certd_running);

        let cert_client = aziot_cert_client_async::Client::new(
            aziot_cert_common_http::ApiVersion::V2020_09_01,
            aziot_certd.clone(),
        );

        let mut err_aggregated = String::new();

        for id in preloaded_certs.keys() {
            let cert = || async {
                let cert = cert_client
                    .get_cert(id)
                    .await
                    .with_context(|| format!("could not load cert with ID {:?}", id))?;

                // PEM blob might have multiple certs, but we only care about the first one.
                // However we still use `openssl::x509::X509::stack_from_pem` so that all the certs in the PEM
                // are parsed and thus verified to be correct.
                let cert = openssl::x509::X509::stack_from_pem(&cert)
                    .with_context(|| format!("could not load cert with ID {:?}", id))?
                    .into_iter()
                    .next()
                    .with_context(|| {
                        format!("could not load cert with ID {:?}: cert is empty", id)
                    })?;
                Ok::<_, anyhow::Error>(cert)
            };
            match cert().await {
                Ok(cert) => {
                    cache.certs.insert(id.clone(), cert);
                }
                Err(err) => {
                    if !err_aggregated.is_empty() {
                        err_aggregated.push('\n');
                    }
                    err_aggregated.push_str(&format!("{:?}", err));
                }
            }
        }

        if err_aggregated.is_empty() {
            Ok(CheckResult::Ok)
        } else {
            Err(anyhow!("{}", err_aggregated))
        }
    }
}
