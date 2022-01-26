// Copyright (c) Microsoft. All rights reserved.

pub mod dps;
pub mod hub;

pub use dps::Client as DpsClient;
pub use hub::Client as HubClient;

type KeyClient = std::sync::Arc<aziot_key_client_async::Client>;
type KeyEngine = std::sync::Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>;
type CertClient = std::sync::Arc<aziot_cert_client_async::Client>;
type TpmClient = std::sync::Arc<aziot_tpm_client_async::Client>;
