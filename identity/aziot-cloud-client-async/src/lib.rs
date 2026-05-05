// Copyright (c) Microsoft. All rights reserved.

mod connector;

pub mod dps;
pub use dps::Client as DpsClient;
pub use dps::schema::request as DpsRequest;
pub use dps::schema::response as DpsResponse;

pub mod hub;
pub use hub::Client as HubClient;

type KeyClient = std::sync::Arc<aziot_key_client_async::Client>;
type TpmClient = std::sync::Arc<aziot_tpm_client_async::Client>;

type CloudConnector = http_common::MaybeProxyConnector<
    hyper_openssl::client::legacy::HttpsConnector<
        hyper_util::client::legacy::connect::HttpConnector,
    >,
>;

const ENCODE_SET: &percent_encoding::AsciiSet = &http_common::PATH_SEGMENT_ENCODE_SET.add(b'=');
