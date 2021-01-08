// Copyright (c) Microsoft. All rights reserved.

use anyhow::{anyhow, Result};
use serde::Serialize;

use crate::internal::check::util::CertificateValidityExt;
use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};
use crate::internal::common::CertificateValidity;

use aziot_certd_config::PreloadedCert;

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
        let preloaded_certs = &unwrap_or_skip!(&cache.cfg.certd).preloaded_certs;

        // TODO?: support returning multiple check results from a single check
        // this will require some non-trivial changes to the checker framework, as currently
        // there isn't any way to return a _dynamic_ number of results from a single check.
        for (id, cert) in preloaded_certs {
            match cert {
                PreloadedCert::Ids(ids) => {
                    // validate that the ids correspond to other preloaded certs
                    for inner_id in ids {
                        if preloaded_certs.get(inner_id).is_none() {
                            return Err(anyhow!(
                                "id '{}' in '{}' does not point to a valid cert",
                                inner_id,
                                id
                            ));
                        };
                    }
                }
                PreloadedCert::Uri(uri) => {
                    if uri.scheme() != "file" {
                        return Err(anyhow!(
                            "only file:// schemes are supported for preloaded certs."
                        ));
                    }

                    match CertificateValidity::new(uri.path(), "", &id)
                        .await?
                        .to_check_result()?
                    {
                        CheckResult::Ok => {}
                        res => return Ok(res),
                    }
                }
            };
        }

        Ok(CheckResult::Ok)
    }
}
