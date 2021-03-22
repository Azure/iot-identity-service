// Copyright (c) Microsoft. All rights reserved.

use anyhow::{Context, Result};
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

        let cert_client = aziot_cert_client_async::Client::new(
            aziot_cert_common_http::ApiVersion::V2020_09_01,
            aziot_certd.clone(),
        );

        for id in preloaded_certs.keys() {
            let cert = cert_client
                .get_cert(id)
                .await
                .with_context(|| format!("could not load cert with ID {:?}", id))?;

            // PEM blob might have multiple certs, but we only care about the first one,
            // so we use `openssl::x509::X509::from_pem` instead of `stack_from_pem`
            let cert = openssl::x509::X509::from_pem(&cert)
                .with_context(|| format!("could not load cert with ID {:?}", id))?;

            cache.certs.insert(id.clone(), cert);
        }

        Ok(CheckResult::Ok)
    }
}
