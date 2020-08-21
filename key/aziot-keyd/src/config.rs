// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug, PartialEq, serde::Deserialize)]
pub struct Config {
	/// Parameters passed down to libaziot-keys. The allowed names and values are determined by the libaziot-keys implementation.
	pub(crate) aziot_keys: std::collections::BTreeMap<String, String>,

	/// Map of preloaded keys from their ID to their location. The location is in a format that the libaziot-keys implementation understands.
	#[serde(default)]
	pub(crate) preloaded_keys: std::collections::BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
	#[test]
	fn parse_config() {
		let actual = r#"
[aziot_keys]
homedir_path = "/var/lib/aziot/keyd"
pkcs11_lib_path = "/usr/lib64/pkcs11/libsofthsm2.so"
pkcs11_base_slot = "pkcs11:token=Key pairs?pin-value=1234"

[preloaded_keys]
bootstrap = "file:///var/secrets/bootstrap.key"
device-id = "pkcs11:token=Key pairs;object=device-id?pin-value=1234"
"#;

		let actual: super::Config = toml::from_str(actual).unwrap();
		assert_eq!(actual, super::Config {
			aziot_keys: [
				("homedir_path", "/var/lib/aziot/keyd"),
				("pkcs11_lib_path", "/usr/lib64/pkcs11/libsofthsm2.so"),
				("pkcs11_base_slot", "pkcs11:token=Key pairs?pin-value=1234"),
			].iter().map(|&(name, value)| (name.to_owned(), value.to_owned())).collect(),

			preloaded_keys: [
				("bootstrap", "file:///var/secrets/bootstrap.key"),
				("device-id", "pkcs11:token=Key pairs;object=device-id?pin-value=1234"),
			].iter().map(|&(name, value)| (name.to_owned(), value.to_owned())).collect(),
		});
	}
}
