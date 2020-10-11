// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::let_unit_value,
	clippy::type_complexity,
)]

mod http;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	run().await?;

	Ok(())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
	let config_file = aziot_identityd::app::init()?;

	let settings = aziot_identityd::settings::Settings::new(&config_file)?;
	let homedir_path = &settings.homedir.to_owned();
	let connector = settings.endpoints.aziot_identityd.clone();

	let mut prev_settings_path = homedir_path.clone();
	prev_settings_path.push("prev_state");

	let mut prev_device_info_path = homedir_path.clone();
	prev_device_info_path.push("device_info");

	if !homedir_path.exists() {
			let () = std::fs::create_dir_all(&homedir_path).map_err(aziot_identityd::error::InternalError::CreateHomeDir)?;
	}

	let (_pmap, module_set) = convert_to_map(&settings.principal);

	let authenticator = Box::new(|_| Ok(aziot_identityd::auth::AuthId::Unknown));

	// TODO: Enable SettingsAuthorizer once Unix Domain Sockets is ported over.
	// let authorizer = aziot_identityd::SettingsAuthorizer { pmap };
	// let authorizer = Box::new(authorizer);
	let authorizer = Box::new(|_| Ok(true));

	let server = aziot_identityd::Server::new(settings, authenticator, authorizer)?;
	let server = std::sync::Arc::new(futures_util::lock::Mutex::new(server));
	{
		let mut server_ = server.lock().await;

		log::info!("Provisioning starting..");
		let provisioning = server_.provision_device().await?;
		log::info!("Provisioning complete.");

		let device_status = if let aziot_identity_common::ProvisioningStatus::Provisioned(device) = provisioning {
			let curr_hub_device_info = aziot_identityd::settings::HubDeviceInfo {
				hub_name: device.iothub_hostname,
				device_id: device.device_id
			};

			if prev_device_info_path.exists() {
				let prev_hub_device_info = aziot_identityd::settings::HubDeviceInfo::new(&prev_device_info_path)?;

				if let Some(prev_state) = prev_hub_device_info {
					let mut prev_module_set: std::collections::BTreeSet<aziot_identity_common::ModuleId> = std::collections::BTreeSet::default();
					if prev_state.eq(&curr_hub_device_info) && prev_settings_path.exists() {
						let settings = aziot_identityd::settings::Settings::new(&prev_settings_path)?;
						let (_, p) = convert_to_map(&settings.principal);
						prev_module_set = p;
					}

					let () = server_.init_identities(prev_module_set, module_set).await?;
				}
			}

			log::info!("Identity reconciliation with IoT Hub complete.");

			toml::to_string(&curr_hub_device_info)?
		}
		else {
			aziot_identityd::settings::HubDeviceInfo::unprovisioned()
		};

		std::fs::write(prev_device_info_path, device_status).map_err(aziot_identityd::error::InternalError::SaveDeviceInfo)?;
		std::fs::copy(config_file, prev_settings_path).map_err(aziot_identityd::error::InternalError::SaveSettings)?;
	}

	let incoming = connector.incoming().await?;
	log::info!("Identity Service started.");

	let server =
	hyper::Server::builder(incoming)
	.serve(hyper::service::make_service_fn(|_| {
		let server = http::Server { inner: server.clone() };
		futures_util::future::ok::<_, std::convert::Infallible>(server)
	}));
	let () = server.await?;

	log::info!("Identity Service stopped.");

	Ok(())
}

fn convert_to_map(principal: &Option<Vec<aziot_identityd::settings::Principal>>)
	-> (std::collections::BTreeMap<aziot_identityd::auth::Uid, aziot_identityd::settings::Principal>,
		std::collections::BTreeSet<aziot_identity_common::ModuleId>)
{
	let mset: std::collections::BTreeSet<aziot_identity_common::ModuleId> =
		principal.as_ref().map_or(
			std::collections::BTreeSet::new(),
			|v| v.iter().filter_map( |p|
				if p.id_type.clone().map_or(false, |t| t.contains(&aziot_identity_common::IdType::Module)) {
					Some(p.name.clone())
				} else {
					None
				}
			).collect()
		);

	let pmap: std::collections::BTreeMap<aziot_identityd::auth::Uid, aziot_identityd::settings::Principal> =
		principal.as_ref().map_or(
			std::collections::BTreeMap::new(),
			|v| v.iter()
				.map(|p| (p.uid, p.clone())).collect::<std::collections::BTreeMap<_,_>>()
	);

	(pmap, mset)
}

#[cfg(test)]
mod tests {
	use aziot_identityd::auth::{Operation, OperationType, AuthId, Uid};
	use aziot_identityd::SettingsAuthorizer;
	use aziot_identityd::settings::{Principal, Settings, LocalId};
	use crate::convert_to_map;
	use aziot_identityd::auth::authorization::Authorizer;
	use aziot_identity_common::{IdType, ModuleId};
	use std::path::Path;

	#[test]
	fn convert_to_map_creates_principal_lookup() {
		let p: Principal = Principal{uid: Uid(1001), name: ModuleId(String::from("module1")), id_type: Some(vec![IdType::Module])};
		let v = vec![p.clone()];
		let (map, _) = convert_to_map(&Some(v));

		assert!(map.contains_key(&Uid(1001)));
		assert_eq!(map.get(&Uid(1001)).unwrap(), &p);
	}

	#[test]
	fn settings_test() {
		let settings = Settings::new(Path::new("test/good_auth_settings.toml")).unwrap();

		let localid = settings.localid.unwrap();
		assert_eq!(localid, LocalId {
			domain: "example.com".to_owned(),
		});

		let (map, _) = convert_to_map(&settings.principal);
		assert_eq!(map.len(), 3);
		assert!(map.contains_key(&Uid(1003)));
		assert_eq!(map.get(&Uid(1003)).unwrap().uid, Uid(1003));
		assert_eq!(map.get(&Uid(1003)).unwrap().name, ModuleId(String::from("hostprocess2")));
		assert_eq!(map.get(&Uid(1003)).unwrap().id_type, Some(vec![IdType::Module, IdType::Local]));
	}

	#[test]
	fn empty_auth_settings_deny_any_action() {
		let (pmap, mset) = convert_to_map(&None);
		let auth = SettingsAuthorizer {pmap, mset};
		let operation = Operation { auth_id: AuthId::Unknown, op_type: OperationType::CreateModule(String::default()) };

		let res = auth.authorize(operation);

		match res {
			Ok(false) => (),
			_ => panic!("incorrect authorization returned"),
		}
	}
}
