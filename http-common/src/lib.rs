// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::missing_errors_doc,
	clippy::module_name_repetitions,
	clippy::similar_names,
	clippy::type_complexity,
)]

mod connector;
pub use connector::{ AsyncStream, Connector, ConnectorError, Stream };

/// Ref <https://url.spec.whatwg.org/#path-percent-encode-set>
pub const PATH_SEGMENT_ENCODE_SET: &percent_encoding::AsciiSet =
	&percent_encoding::CONTROLS
	.add(b' ').add(b'"').add(b'<').add(b'>').add(b'`') // fragment percent-encode set
	.add(b'#').add(b'?').add(b'{').add(b'}'); // path percent-encode set


#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct ByteString(pub Vec<u8>);

impl<'de> serde::Deserialize<'de> for ByteString {
	fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error> where D: serde::Deserializer<'de> {
		struct Visitor;

		impl<'de> serde::de::Visitor<'de> for Visitor {
			type Value = ByteString;

			fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				write!(formatter, "a base64-encoded string")
			}

			fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: serde::de::Error {
				Ok(ByteString(base64::decode_config(v, base64::STANDARD).map_err(serde::de::Error::custom)?))
			}
		}

		deserializer.deserialize_str(Visitor)
	}
}

impl serde::Serialize for ByteString {
	fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> where S: serde::Serializer {
		base64::encode_config(&self.0, base64::STANDARD).serialize(serializer)
	}
}
