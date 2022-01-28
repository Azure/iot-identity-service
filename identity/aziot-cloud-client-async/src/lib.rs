// Copyright (c) Microsoft. All rights reserved.

mod connector;
mod request;

pub mod dps;
pub use dps::schema::request as DpsRequest;
pub use dps::schema::response as DpsResponse;
pub use dps::Client as DpsClient;

pub mod hub;
pub use hub::Client as HubClient;

type KeyClient = std::sync::Arc<aziot_key_client_async::Client>;
type KeyEngine = std::sync::Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>;
type CertClient = std::sync::Arc<aziot_cert_client_async::Client>;
type TpmClient = std::sync::Arc<aziot_tpm_client_async::Client>;

type CloudConnector =
    http_common::MaybeProxyConnector<hyper_openssl::HttpsConnector<hyper::client::HttpConnector>>;
