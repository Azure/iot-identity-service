// Copyright (c) Microsoft. All rights reserved.

use anyhow::{anyhow, Context, Result};
use serde::Serialize;

use crate::internal::check::{CheckResult, Checker, CheckerCache, CheckerMeta, CheckerShared};

#[derive(Serialize, Default)]
pub struct ReadKeyPairs {}

const RSA_RECOMMENDED_MIN_BITS: u32 = 2048;

#[async_trait::async_trait]
impl Checker for ReadKeyPairs {
    fn meta(&self) -> CheckerMeta {
        CheckerMeta {
            id: "key-pairs-read",
            description: "read all preloaded key pairs from the Keys Service",
        }
    }

    async fn execute(&mut self, shared: &CheckerShared, cache: &mut CheckerCache) -> CheckResult {
        self.inner_execute(shared, cache)
            .await
            .unwrap_or_else(CheckResult::Failed)
    }
}

impl ReadKeyPairs {
    async fn inner_execute(
        &mut self,
        _shared: &CheckerShared,
        cache: &mut CheckerCache,
    ) -> Result<CheckResult> {
        let aziot_keyd_config::Config {
            endpoints: aziot_keyd_config::Endpoints { aziot_keyd },
            preloaded_keys,
            ..
        } = unwrap_or_skip!(&cache.cfg.keyd);

        if !cache.daemons_running.keyd {
            return Ok(CheckResult::Skipped);
        }

        let key_client = aziot_key_client_async::Client::new(
            aziot_key_common_http::ApiVersion::V2021_05_01,
            aziot_keyd.clone(),
            0,
        );

        let mut key_engine = {
            let key_client = aziot_key_client::Client::new(
                aziot_key_common_http::ApiVersion::V2021_05_01,
                aziot_keyd.clone(),
            );
            let key_client = std::sync::Arc::new(key_client);
            let key_engine = aziot_key_openssl_engine::load(key_client)
                .context("could not load OpenSSL engine")?;
            key_engine
        };

        let mut err_aggregated = vec![];
        let mut warn_aggregated = vec![];

        // Check every preloaded key at a file:// URI is readable by the aziotks user and report errors when they aren't.
        let aziotks_user = crate::internal::common::get_system_user("aziotks")?;

        for (id, path) in preloaded_keys {
            let mut readable = true;
            if let Ok(aziot_keys_common::PreloadedKeyLocation::Filesystem { path }) = path.parse() {
                if let Err(err) =
                    aziotctl_common::config::check_readable(&path, &aziotks_user, false)
                {
                    err_aggregated.push(format!("{:?}", err));
                    readable = false;
                }
            }

            if readable {
                // Load the key through the keyd API and collect any errors.
                //
                // We don't know whether `id` is a symmetric or asymmetric key,
                // and the `load_key_pair` error doesn't tell us whether it failed because it's a symmetric key
                // or because of some other reason.
                //
                // We also can't go behind keyd's back and load the keys ourselves, because the point of this check
                // is to test keyd's ability to load the keys, but also because only keyd is allowed to load PKCS#11 keys
                // since PKCS#11 implementations are generally not cross-process-safe.
                //
                // So as a best effort, ignore errors from loading key pairs entirely.
                let key_handle = if let Ok(key_handle) = key_client.load_key_pair(id).await {
                    key_handle
                } else {
                    continue;
                };

                let key = || {
                    let key_handle = std::ffi::CString::new(key_handle.0)
                        .context("internal error: key handle is malformed")?;
                    let key = key_engine.load_private_key(&key_handle).with_context(|| {
                        format!("could not load preloaded private key with ID {:?}", id)
                    })?;
                    Ok::<_, anyhow::Error>(key)
                };

                match key() {
                    Ok(key) => {
                        if let Ok(rsa) = key.rsa() {
                            let key_length = rsa.size() * 8;

                            if key_length < RSA_RECOMMENDED_MIN_BITS {
                                warn_aggregated.push(format!(
                                    "RSA key {} has length {} (min recommended: {})",
                                    id, key_length, RSA_RECOMMENDED_MIN_BITS
                                ));
                            }
                        } else if let Ok(ec_key) = key.ec_key() {
                            if ec_key.group().curve_name()
                                != Some(openssl::nid::Nid::X9_62_PRIME256V1)
                            {
                                warn_aggregated.push(format!(
                                    "EC key {} not using recommended curve (recommended: P-256)",
                                    id
                                ));
                            }
                        } else {
                            warn_aggregated.push(format!(
                                "Key {} not using recommended algorithm (recommended: RSA, EC)",
                                id
                            ));
                        }

                        cache.private_keys.insert(id.clone(), key);
                    }
                    Err(err) => {
                        err_aggregated.push(format!("{:?}", err));
                    }
                }
            }
        }

        #[allow(clippy::if_not_else)]
        if !err_aggregated.is_empty() {
            Err(anyhow!("{}", err_aggregated.join("\n")))
        } else if !warn_aggregated.is_empty() {
            Ok(CheckResult::Warning(anyhow!(
                "{}",
                warn_aggregated.join("\n")
            )))
        } else {
            Ok(CheckResult::Ok)
        }
    }
}
