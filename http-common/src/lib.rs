// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_and_return,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::type_complexity
)]

mod dynrange;
pub use dynrange::DynRangeBounds;

mod connector;
#[cfg(feature = "tokio1")]
pub use connector::AsyncStream;
pub use connector::{Connector, ConnectorError, Stream};

#[cfg(feature = "tokio1")]
mod proxy;
#[cfg(feature = "tokio1")]
pub use proxy::{get_proxy_uri, MaybeProxyConnector};

pub mod server;

#[cfg(feature = "tokio1")]
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

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ByteString;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "a base64-encoded string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ByteString(
                    base64::decode_config(v, base64::STANDARD).map_err(serde::de::Error::custom)?,
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
        base64::encode_config(&self.0, base64::STANDARD).serialize(serializer)
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ErrorBody<'a> {
    pub message: std::borrow::Cow<'a, str>,
}
