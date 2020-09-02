// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug, PartialEq, serde::Deserialize)]
pub struct Config {
	/// Path of home directory.
	pub homedir_path: std::path::PathBuf,

	/// Configuration of how new certificates should be issued.
	pub cert_issuance: CertIssuance,

	/// Map of preloaded certs from their ID to their location.
	#[serde(default)]
	pub preloaded_certs: std::collections::BTreeMap<String, PreloadedCert>,

	/// Map of service names to endpoint URIs.
	pub endpoints: Endpoints,
}

/// Configuration of how new certificates should be issued.
#[derive(Debug, PartialEq, serde::Deserialize)]
pub struct CertIssuance {
	/// Configuration of parameters for issuing certs via EST.
	pub(crate) est: Option<Est>,

	/// Configuration of parameters for issuing certs via a local CA cert.
	pub(crate) local_ca: Option<LocalCa>,

	/// Map of certificate IDs to the details used to issue them.
	#[serde(flatten)]
	pub(crate) certs: std::collections::BTreeMap<String, CertIssuanceOptions>,
}

/// Configuration of parameters for issuing certs via EST.
#[derive(Debug, PartialEq)]
pub(crate) struct Est {
	/// Authentication parameters for the EST server.
	pub(crate) auth: EstAuth,

	/// List of certs that should be treated as trusted roots for validating the EST server's TLS certificate.
	pub(crate) trusted_certs: Vec<String>,

	/// Map of certificate IDs to EST endpoint URLs.
	///
	/// The special key "default" is used as a fallback for certs whose ID is not explicitly listed in this map.
	pub(crate) urls: std::collections::BTreeMap<String, url::Url>,
}

/// Authentication parameters for the EST server.
///
/// Note that EST servers may be configured to have only basic auth, only TLS client cert auth, or both.
#[derive(Debug, PartialEq)]
pub(crate) struct EstAuth {
	/// Authentication parameters when using basic HTTP authentication.
	pub(crate) basic: Option<EstAuthBasic>,

	/// Authentication parameters when using TLS client cert authentication.
	pub(crate) x509: Option<EstAuthX509>,
}

/// Authentication parameters when using basic HTTP authentication.
#[derive(Debug, PartialEq)]
pub(crate) struct EstAuthBasic {
	pub(crate) username: String,
	pub(crate) password: String,
}

/// Authentication parameters when using TLS client cert authentication.
#[derive(Debug, PartialEq)]
pub(crate) struct EstAuthX509 {
	/// Cert ID and private key ID for the identity cert.
	///
	/// If this cert does not exist, it will be requested from the EST server,
	/// with the bootstrap identity cert used as the initial TLS client cert.
	pub(crate) identity: (String, String),

	/// Cert ID and private key ID for the bootstrap identity cert.
	///
	/// This is needed if the cert indicated by `identity` does not exist
	/// and thus also needs to be requested from the EST server.
	pub(crate) bootstrap_identity: Option<(String, String)>,
}

impl<'de> serde::Deserialize<'de> for Est {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: serde::de::Deserializer<'de> {
		#[derive(Debug, serde::Deserialize)]
		pub(crate) struct EstInner {
			username: Option<String>,
			password: Option<String>,

			identity_cert: Option<String>,
			identity_pk: Option<String>,
			bootstrap_identity_cert: Option<String>,
			bootstrap_identity_pk: Option<String>,

			#[serde(default)]
			trusted_certs: Vec<String>,

			urls: std::collections::BTreeMap<String, url::Url>,
		}

		let inner: EstInner = serde::Deserialize::deserialize(deserializer)?;

		let auth_basic = match (inner.username, inner.password) {
			(Some(username), Some(password)) => Some(EstAuthBasic {
				username,
				password,
			}),

			(Some(_), None) => return Err(serde::de::Error::missing_field("password")),

			(None, Some(_)) => return Err(serde::de::Error::missing_field("username")),

			(None, None) => None,
		};

		let auth_x509 = match (inner.identity_cert, inner.identity_pk) {
			(Some(identity_cert), Some(identity_pk)) => {
				let identity = (identity_cert, identity_pk);

				let bootstrap_identity = match (inner.bootstrap_identity_cert, inner.bootstrap_identity_pk) {
					(Some(bootstrap_identity_cert), Some(bootstrap_identity_pk)) => Some((bootstrap_identity_cert, bootstrap_identity_pk)),
					(Some(_), None) => return Err(serde::de::Error::missing_field("bootstrap_identity_pk")),
					(None, Some(_)) => return Err(serde::de::Error::missing_field("bootstrap_identity_cert")),
					(None, None) => None,
				};

				Some(EstAuthX509 {
					identity,
					bootstrap_identity,
				})
			},

			(Some(_), None) => return Err(serde::de::Error::missing_field("identity_pk")),

			(None, Some(_)) => return Err(serde::de::Error::missing_field("identity_cert")),

			(None, None) => None,
		};

		let trusted_certs = inner.trusted_certs;

		let urls = inner.urls;

		Ok(Est {
			auth: EstAuth {
				basic: auth_basic,
				x509: auth_x509,
			},
			trusted_certs,
			urls,
		})
	}
}

/// Configuration of parameters for issuing certs via a local CA cert.
#[derive(Debug, PartialEq, serde::Deserialize)]
pub(crate) struct LocalCa {
	/// Certificate ID.
	pub(crate) cert: String,

	/// Private key ID.
	pub(crate) pk: String,
}

/// Details for issuing a single cert.
#[derive(Clone, Debug, PartialEq, serde::Deserialize)]
pub(crate) struct CertIssuanceOptions {
	/// The method used to issue a certificate.
	pub(crate) method: CertIssuanceMethod,

	/// Common name for the issued certificate. Defaults to the common name specified in CSR if not provided.
	pub(crate) common_name: Option<String>,

	/// Number of days between cert issuance and expiry. Applies to local_ca and self_signed issuance methods.
	/// If not provided, defaults to 30.
	#[serde(default, deserialize_with = "deserialize_expiry_days")]
	pub(crate) expiry_days: Option<u32>,
}

fn deserialize_expiry_days<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
	where D: serde::de::Deserializer<'de> {
	let result: Option<u32> = serde::Deserialize::deserialize(deserializer)?;

	if result == Some(0) {
		return Err(serde::de::Error::custom("expiry_days must be greater than 0"));
	}

	Ok(result)
}

/// The method used to issue a certificate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum CertIssuanceMethod {
	/// The certificate is to be issued via EST.
	Est,

	/// The certificate is to be issued via a local CA cert.
	LocalCa,

	/// The certificate is to be self-signed.
	SelfSigned,
}

impl<'de> serde::Deserialize<'de> for CertIssuanceMethod {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: serde::de::Deserializer<'de> {
		struct Visitor;

		impl<'de> serde::de::Visitor<'de> for Visitor {
			type Value = CertIssuanceMethod;

			fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				f.write_str(stringify!(CertIssuanceMethod))
			}

			fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: serde::de::Error {
				match v {
					"est" => Ok(CertIssuanceMethod::Est),
					"local_ca" => Ok(CertIssuanceMethod::LocalCa),
					"self_signed" => Ok(CertIssuanceMethod::SelfSigned),
					v => Err(serde::de::Error::invalid_value(serde::de::Unexpected::Str(v), &r#"one of "est" or "local_ca" or "self_signed""#)),
				}
			}
		}

		deserializer.deserialize_str(Visitor)
	}
}

/// The location of a preloaded cert.
#[derive(Debug, PartialEq, serde::Deserialize)]
#[serde(untagged)]
pub enum PreloadedCert {
	/// A URI for the location.
	///
	/// Only `file://` URIs are supported.
	Uri(url::Url),

	/// A list of IDs of other certs, preloaded or otherwise.
	///
	/// If an element of the list references a preloaded cert's ID, that preloaded cert must be a URI rather than another list.
	Ids(Vec<String>),
}

/// Map of service names to endpoint URIs.
#[derive(Debug, PartialEq, serde::Deserialize)]
pub struct Endpoints {
	/// The endpoint that the certd service binds to.
	pub aziot_certd: http_common::Connector,

	/// The endpoint that the keyd service binds to.
	pub aziot_keyd: http_common::Connector,
}

#[cfg(test)]
mod tests {
	#[test]
	fn parse_config() {
		let actual = r#"
homedir_path = "/var/lib/aziot/certd"

[cert_issuance]
device-ca = { method = "est", common_name = "custom-name" }
device-id = { method = "est" }
module-id = { method = "self_signed", expiry_days = 90, common_name = "custom-name"}
module-server = { method = "local_ca" }

[cert_issuance.est]
method = "x509"
identity_cert = "est-id"
identity_pk = "est-id"
bootstrap_identity_cert = "bootstrap"
bootstrap_identity_pk = "bootstrap"
trusted_certs = [
	"est-ca",
]

[cert_issuance.est.urls]
default = "https://estendpoint.com/.well-known/est/simpleenroll"
est-id = "https://estendpoint.com/.well-known/est/est-id/simpleenroll"
device-id = "https://estendpoint.com/.well-known/est/device-id/simpleenroll"
device-ca = "https://estendpoint.com/.well-known/est/device-ca/simpleenroll"

[preloaded_certs]
bootstrap = "file:///var/secrets/bootstrap.cer"
est-ca = "file:///var/secrets/est-ca.cer"
trust-bundle = [
	"est-ca",
]

[endpoints]
aziot_keyd = "unix:///var/run/aziot/keyd.sock"
aziot_certd = "unix:///var/run/aziot/certd.sock"
"#;

		let actual: super::Config = toml::from_str(actual).unwrap();
		assert_eq!(actual, super::Config {
			homedir_path: "/var/lib/aziot/certd".into(),

			cert_issuance: super::CertIssuance {
				est: Some(super::Est {
					auth: super::EstAuth {
						basic: None,
						x509: Some(super::EstAuthX509 {
							identity: ("est-id".to_owned(), "est-id".to_owned()),
							bootstrap_identity: Some(("bootstrap".to_owned(), "bootstrap".to_owned())),
						}),
					},
					trusted_certs: vec![
						"est-ca".to_owned(),
					],
					urls: vec![
						("default".to_owned(), "https://estendpoint.com/.well-known/est/simpleenroll".parse().unwrap()),
						("est-id".to_owned(), "https://estendpoint.com/.well-known/est/est-id/simpleenroll".parse().unwrap()),
						("device-id".to_owned(), "https://estendpoint.com/.well-known/est/device-id/simpleenroll".parse().unwrap()),
						("device-ca".to_owned(), "https://estendpoint.com/.well-known/est/device-ca/simpleenroll".parse().unwrap()),
					].into_iter().collect(),
				}),

				local_ca: None,

				certs: [
					("device-ca", super::CertIssuanceOptions {
						method: super::CertIssuanceMethod::Est,
						common_name: Some("custom-name".to_owned()),
						expiry_days: None,}
					),
					("device-id", super::CertIssuanceOptions {
						method: super::CertIssuanceMethod::Est,
						common_name: None,
						expiry_days: None,}
					),
					("module-id", super::CertIssuanceOptions {
						method: super::CertIssuanceMethod::SelfSigned,
						common_name: Some("custom-name".to_owned()),
						expiry_days: Some(90),}
					),
					("module-server", super::CertIssuanceOptions {
						method: super::CertIssuanceMethod::LocalCa,
						common_name: None,
						expiry_days: None,}
					),
				].iter().map(|(id, options)| ((*id).to_owned(), options.clone())).collect(),
			},

			preloaded_certs: vec![
				("bootstrap".to_owned(), super::PreloadedCert::Uri("file:///var/secrets/bootstrap.cer".parse().unwrap())),
				("est-ca".to_owned(), super::PreloadedCert::Uri("file:///var/secrets/est-ca.cer".parse().unwrap())),
				("trust-bundle".to_owned(), super::PreloadedCert::Ids(vec!["est-ca".to_owned()])),
			].into_iter().collect(),

			endpoints: super::Endpoints {
				aziot_certd: http_common::Connector::new(&"unix:///var/run/aziot/certd.sock".parse().unwrap()).unwrap(),
				aziot_keyd: http_common::Connector::new(&"unix:///var/run/aziot/keyd.sock".parse().unwrap()).unwrap(),
			},
		});
	}
}
