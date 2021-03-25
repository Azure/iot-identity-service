// Copyright (c) Microsoft. All rights reserved.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};

#[derive(Default, Serialize)]
pub struct AziotVersion {
    expected_version: Option<String>,
    actual_version: Option<String>,
}

#[async_trait::async_trait]
impl Checker for AziotVersion {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "aziot-version",
            description: "aziot-identity-service package is up-to-date",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        self.inner_execute(shared, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl AziotVersion {
    async fn inner_execute(
        &mut self,
        shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        let expected_version = if let Some(expected_aziot_version) =
            &shared.cfg.expected_aziot_version
        {
            expected_aziot_version.clone()
        } else {
            let local_gateway_hostname = &unwrap_or_skip!(&cache.cfg.identityd)
                .provisioning
                .local_gateway_hostname;
            if local_gateway_hostname.is_some() {
                // This is a nested deployment device so it may not be able to access aka.ms or github.com.
                // In the best case the request would be blocked immediately, but in the worst case it may take a long time to time out.
                // The user didn't provide the `expected_aziot_version` param on the CLI either, so we just ignore this check.
                return Ok(CheckResult::Ignored);
            }

            let connector =
                http_common::MaybeProxyConnector::new(shared.cfg.proxy_uri.clone(), None, &[])
                    .context("could not initialize HTTP connector")?;
            let client: hyper::Client<_, hyper::Body> = hyper::Client::builder().build(connector);

            let mut uri: hyper::Uri = "https://aka.ms/latest-aziot-stable-non-lts"
                .parse()
                .expect("hard-coded URI cannot fail to parse");
            let LatestVersions { aziot } = loop {
                let req = {
                    let mut req = hyper::Request::new(Default::default());
                    *req.uri_mut() = uri.clone();
                    req
                };

                let res = client.request(req).await.with_context(|| {
                    format!("could not query {} for latest available version", uri)
                })?;
                match res.status() {
                    status_code if status_code.is_redirection() => {
                        uri = res
                            .headers()
                            .get(hyper::header::LOCATION)
                            .context("received HTTP redirect response without location header")?
                            .to_str()
                            .context(
                                "received HTTP redirect response with malformed location header",
                            )?
                            .parse()
                            .context(
                                "received HTTP redirect response with malformed location header",
                            )?;
                    }

                    hyper::StatusCode::OK => {
                        let body = hyper::body::aggregate(res.into_body())
                            .await
                            .context("could not read HTTP response")?;
                        let body = serde_json::from_reader(hyper::body::Buf::reader(body))
                            .context("could not read HTTP response")?;
                        break body;
                    }

                    status_code => {
                        return Err(anyhow!("received unexpected response {}", status_code))
                    }
                }
            };
            aziot
        };
        self.expected_version = Some(expected_version.clone());

        let actual_version = env!("CARGO_PKG_VERSION");
        self.actual_version = Some(actual_version.to_owned());

        if expected_version != actual_version {
            return Ok(CheckResult::Warning(
                anyhow!(
                    "Installed aziot-identity-service package has version {} but {} is the latest stable version available.\n\
                    Please see https://aka.ms/aziot-update-runtime for update instructions.",
                    actual_version, expected_version,
                ),
            ));
        }

        Ok(CheckResult::Ok)
    }
}

#[derive(Debug, Deserialize)]
struct LatestVersions {
    aziot: String,
}
