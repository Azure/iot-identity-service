// Copyright (c) Microsoft. All rights reserved.

use anyhow::{anyhow, Result};
use serde::Serialize;

use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};

#[derive(Default, Serialize)]
pub struct EstServerHttps {}

#[async_trait::async_trait]
impl Checker for EstServerHttps {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "est-server-https",
            description: "check all EST server URLs utilize HTTPS",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        self.inner_execute(shared, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl EstServerHttps {
    async fn inner_execute(
        &mut self,
        _shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        let aziot_certd_config::Config { cert_issuance, .. } = unwrap_or_skip!(&cache.cfg.certd);

        if !cache.daemons_running.certd {
            return Ok(CheckResult::Skipped);
        }

        let aziot_certd_config::CertIssuance { est, certs, .. } = cert_issuance;

        let mut warn_aggregated = vec![];

        if let Some(est) = est {
            for url in est.urls.values() {
                if url.scheme() != "https" {
                    warn_aggregated.push(format!(
                        "EST server URL {:?} is configured with unencrypted HTTP, which may expose device to man-in-the-middle attacks.", url.as_str()
                    ));
                    warn_aggregated.push(
                        "To clear this warning, configure HTTPS for your EST server and update the URL.".to_owned()
                    );
                }
            }
        }

        for options in certs.values() {
            if let aziot_certd_config::CertIssuanceMethod::Est {
                url: Some(url),
                auth: _,
            } = &options.method
            {
                if url.scheme() != "https" {
                    warn_aggregated.push(format!(
                        "EST server URL {:?} is configured with unencrypted HTTP, which may expose device to man-in-the-middle attacks.", url.as_str()
                    ));
                    warn_aggregated.push(
                        "To clear this warning, configure HTTPS for your EST server and update the URL.".to_owned()
                    );
                }
            }
        }

        if warn_aggregated.is_empty() {
            Ok(CheckResult::Ok)
        } else {
            Ok(CheckResult::Warning(anyhow!(
                "{}",
                warn_aggregated.join("\n")
            )))
        }
    }
}
