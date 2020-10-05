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

	let (_pmap, hub_mset, local_mset) = convert_to_map(&settings.principal);

	let authenticator = Box::new(|_| Ok(aziot_identityd::auth::AuthId::Unknown));

	// TODO: Enable SettingsAuthorizer once Unix Domain Sockets is ported over.
	// let authorizer = aziot_identityd::SettingsAuthorizer { pmap };
	// let authorizer = Box::new(authorizer);
	let authorizer = Box::new(|_| Ok(true));

	let server = aziot_identityd::Server::new(settings, authenticator, authorizer)?;
	let server = std::sync::Arc::new(futures_util::lock::Mutex::new(server));
	{
		let (prev_hub_mset, prev_local_mset) =
			if prev_settings_path.exists() {
				let prev_settings = aziot_identityd::settings::Settings::new(&prev_settings_path)?;
				let (_, h, l) = convert_to_map(&prev_settings.principal);
				(h, l)
			}
			else {
				(std::collections::BTreeSet::default(), std::collections::BTreeSet::default())
			};

		let mut server_ = server.lock().await;

		log::info!("Provisioning starting.");
		let provisioning = server_.provision_device().await?;
		log::info!("Provisioning complete.");

		let device_status = if let aziot_identity_common::ProvisioningStatus::Provisioned(device) = provisioning {
			let curr_hub_device_info = aziot_identityd::settings::HubDeviceInfo {
				hub_name: device.iothub_hostname,
				device_id: device.device_id
			};

			if prev_device_info_path.exists() {
				let prev_hub_device_info = aziot_identityd::settings::HubDeviceInfo::new(&prev_device_info_path)?;

				if let Some(prev_device) = prev_hub_device_info {
					if prev_device == curr_hub_device_info {
						let () = server_.init_hub_identities(prev_hub_mset, hub_mset).await?;
						log::info!("Identity reconciliation with IoT Hub complete.");
					}
				}
			}

			toml::to_string(&curr_hub_device_info)?
		}
		else {
			aziot_identityd::settings::HubDeviceInfo::unprovisioned()
		};

		let () = server_.init_local_identities(prev_local_mset, local_mset).await?;
		log::info!("Local identity reconciliation complete.");

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
		std::collections::BTreeSet<aziot_identity_common::ModuleId>,
		std::collections::BTreeSet<aziot_identity_common::ModuleId>,)
{
	let mut local_mset: std::collections::BTreeSet<aziot_identity_common::ModuleId> = std::collections::BTreeSet::new();
	let mut module_mset: std::collections::BTreeSet<aziot_identity_common::ModuleId> = std::collections::BTreeSet::new();
	let mut pmap: std::collections::BTreeMap<aziot_identityd::auth::Uid, aziot_identityd::settings::Principal> = std::collections::BTreeMap::new();

	let principal = principal.iter().flat_map(|p| p.iter());

	for p in principal {
		if let Some(id_type) = &p.id_type {
			for i in id_type {
				match i {
					aziot_identity_common::IdType::Module => module_mset.insert(p.name.clone()),
					aziot_identity_common::IdType::Local => local_mset.insert(p.name.clone()),
					_ => true,
				};
			}
		}

		pmap.insert(p.uid, p.clone());
	}

	(pmap, module_mset, local_mset)
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
		let local_p: Principal = Principal{uid: Uid(1000), name: ModuleId(String::from("local1")), id_type: Some(vec![IdType::Local])};
		let module_p: Principal = Principal{uid: Uid(1001), name: ModuleId(String::from("module1")), id_type: Some(vec![IdType::Module])};
		let v = vec![module_p.clone(), local_p.clone()];
		let (map, _, _) = convert_to_map(&Some(v));

		assert!(map.contains_key(&Uid(1000)));
		assert_eq!(map.get(&Uid(1000)).unwrap(), &local_p);
		assert!(map.contains_key(&Uid(1001)));
		assert_eq!(map.get(&Uid(1001)).unwrap(), &module_p);
	}

	#[test]
	fn convert_to_map_module_sets() {
		let v = vec![
			Principal { uid: Uid(1000), name: ModuleId("hubmodule".to_owned()), id_type: Some(vec![IdType::Module]) },
			Principal { uid: Uid(1001), name: ModuleId("localmodule".to_owned()), id_type: Some(vec![IdType::Local]) },
			Principal { uid: Uid(1002), name: ModuleId("globalmodule".to_owned()), id_type: Some(vec![IdType::Module, IdType::Local]) },
		];

		let (_, hub_modules, local_modules) = convert_to_map(&Some(v));

		assert!(hub_modules.contains(&ModuleId("hubmodule".to_owned())));
		assert!(hub_modules.contains(&ModuleId("globalmodule".to_owned())));
		assert!(!hub_modules.contains(&ModuleId("localmodule".to_owned())));

		assert!(local_modules.contains(&ModuleId("localmodule".to_owned())));
		assert!(local_modules.contains(&ModuleId("globalmodule".to_owned())));
		assert!(!local_modules.contains(&ModuleId("hubmodule".to_owned())));
	}

	#[test]
	fn settings_test() {
		let settings = Settings::new(Path::new("test/good_auth_settings.toml")).unwrap();

		let localid = settings.localid.unwrap();
		assert_eq!(localid, LocalId {
			domain: "example.com".to_owned(),
		});

		let (map, _, _) = convert_to_map(&settings.principal);
		assert_eq!(map.len(), 3);
		assert!(map.contains_key(&Uid(1003)));
		assert_eq!(map.get(&Uid(1003)).unwrap().uid, Uid(1003));
		assert_eq!(map.get(&Uid(1003)).unwrap().name, ModuleId(String::from("hostprocess2")));
		assert_eq!(map.get(&Uid(1003)).unwrap().id_type, Some(vec![IdType::Module, IdType::Local]));
	}

	#[test]
	fn empty_auth_settings_deny_any_action() {
		let (pmap, mset, _) = convert_to_map(&None);
		let auth = SettingsAuthorizer {pmap, mset};
		let operation = Operation { auth_id: AuthId::Unknown, op_type: OperationType::CreateModule(String::default()) };

		let res = auth.authorize(operation);

		match res {
			Ok(false) => (),
			_ => panic!("incorrect authorization returned"),
		}
	}
}
