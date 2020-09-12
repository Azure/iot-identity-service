// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApiVersion {
	V2020_09_01,
	Max,
}

impl std::fmt::Display for ApiVersion {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			ApiVersion::V2020_09_01 => "2020-09-01",
			ApiVersion::Max => "MAX",
		})
	}
}

impl std::str::FromStr for ApiVersion {
	type Err = ();

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"2020-09-01" => Ok(ApiVersion::V2020_09_01),
			_ => Err(()),
		}
	}
}

#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Pem(pub Vec<u8>);

impl<'de> serde::Deserialize<'de> for Pem {
	fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error> where D: serde::Deserializer<'de> {
		struct Visitor;

		impl<'de> serde::de::Visitor<'de> for Visitor {
			type Value = Pem;

			fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				write!(formatter, "a base64-encoded string")
			}

			fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: serde::de::Error {
				Ok(Pem(v.as_bytes().to_owned()))
			}

			fn visit_string<E>(self, v: String) -> Result<Self::Value, E> where E: serde::de::Error {
				Ok(Pem(v.into_bytes()))
			}
		}

		deserializer.deserialize_str(Visitor)
	}
}

impl serde::Serialize for Pem {
	fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> where S: serde::Serializer {
		let s = std::str::from_utf8(&self.0).map_err(serde::ser::Error::custom)?;
		s.serialize(serializer)
	}
}

pub mod create_cert {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Request {
		#[serde(rename = "certId")]
		pub cert_id: String,

		pub csr: crate::Pem,

		pub issuer: Option<Issuer>,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Issuer {
		#[serde(rename = "certId")]
		pub cert_id: String,

		#[serde(rename = "privateKeyHandle")]
		pub private_key_handle: aziot_key_common::KeyHandle,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		pub pem: crate::Pem,
	}
}

pub mod get_cert {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		pub pem: crate::Pem,
	}
}

pub mod import_cert {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Request {
		pub pem: crate::Pem,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		pub pem: crate::Pem,
	}
}
