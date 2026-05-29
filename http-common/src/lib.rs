// Copyright (c) Microsoft. All rights reserved.

mod dynrange;
pub use dynrange::DynRangeBounds;

mod connector;
pub use connector::AsyncStream;
pub use connector::SOCKET_DEFAULT_PERMISSION;
pub use connector::{Connector, ConnectorError, Incoming, Stream};

mod proxy;
pub use proxy::{MaybeProxyConnector, get_proxy_uri};

mod request;
pub use request::{HttpRequest, HttpResponse};

pub mod server;

mod backoff;

mod uid;

/// Ref <https://url.spec.whatwg.org/#path-percent-encode-set>
pub const PATH_SEGMENT_ENCODE_SET: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`') // fragment percent-encode set
    .add(b'#')
    .add(b'?')
    .add(b'{')
    .add(b'}'); // path percent-encode set

#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct ByteString(pub Vec<u8>);

impl<'de> serde::Deserialize<'de> for ByteString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = ByteString;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "a base64-encoded string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let engine = base64::engine::general_purpose::STANDARD;

                Ok(ByteString(
                    base64::Engine::decode(&engine, v).map_err(serde::de::Error::custom)?,
                ))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

impl serde::Serialize for ByteString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let engine = base64::engine::general_purpose::STANDARD;

        base64::Engine::encode(&engine, &self.0).serialize(serializer)
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ErrorBody<'a> {
    pub message: std::borrow::Cow<'a, str>,
}

impl std::convert::From<ErrorBody<'_>> for std::io::Error {
    fn from(err: ErrorBody<'_>) -> Self {
        std::io::Error::other(err.message)
    }
}

// Used by `make_service!` expansion.
pub use bytes;
pub use futures_util;
pub use http;
pub use http_body_util;
pub use hyper;
pub use log;
pub use serde_json;
pub use tokio;
pub use url;
