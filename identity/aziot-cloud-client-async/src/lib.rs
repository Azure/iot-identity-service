// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

mod connector;

pub mod dps;
pub use dps::schema::request as DpsRequest;
pub use dps::schema::response as DpsResponse;
pub use dps::Client as DpsClient;

pub mod hub;
pub use hub::Client as HubClient;

type KeyClient = std::sync::Arc<aziot_key_client_async::Client>;
type TpmClient = std::sync::Arc<aziot_tpm_client_async::Client>;

type CloudConnector =
    http_common::MaybeProxyConnector<hyper_openssl::HttpsConnector<hyper::client::HttpConnector>>;

const ENCODE_SET: &percent_encoding::AsciiSet = &http_common::PATH_SEGMENT_ENCODE_SET.add(b'=');
