// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::default_trait_access,
	clippy::missing_errors_doc,
	clippy::module_name_repetitions,
	clippy::must_use_candidate,
	clippy::too_many_lines,
	clippy::let_and_return,
	clippy::type_complexity,
)]
#![allow(dead_code)]

pub mod auth;
pub mod app;
pub mod error;
pub mod identity;
mod logging;
pub mod settings;

pub use error::{Error, InternalError};

/// This is the interval at which to poll DPS for registration assignment status
const DPS_ASSIGNMENT_RETRY_INTERVAL_SECS: u64 = 10;

/// This is the number of seconds to wait for DPS to complete assignment to a hub
const DPS_ASSIGNMENT_TIMEOUT_SECS: u64 = 120;

pub struct Server {
	pub settings: settings::Settings,
	pub authenticator: Box<dyn auth::authentication::Authenticator<Error = Error>  + Send + Sync>,
	pub authorizer: Box<dyn auth::authorization::Authorizer<Error = Error>  + Send + Sync>,
	pub id_manager: identity::IdentityManager,

	key_client: std::sync::Arc<aziot_key_client_async::Client>,
	key_engine: std::sync::Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
	cert_client: std::sync::Arc<aziot_cert_client_async::Client>,
}

impl Server {
	pub fn new(
		settings: settings::Settings,
		authenticator: Box<dyn auth::authentication::Authenticator<Error = Error> + Send + Sync>,
		authorizer: Box<dyn auth::authorization::Authorizer<Error = Error>  + Send + Sync>,
	) -> Result<Self, Error> {
		let key_service_connector = settings.endpoints.aziot_keyd.clone();

		let key_client = {
			let key_client = aziot_key_client_async::Client::new(key_service_connector.clone());
			let key_client = std::sync::Arc::new(key_client);
			key_client
		};

		let key_engine = {
			let key_client = aziot_key_client::Client::new(key_service_connector);
			let key_client = std::sync::Arc::new(key_client);
			let key_engine =
				aziot_key_openssl_engine::load(key_client)
				.map_err(|err| Error::Internal(InternalError::LoadKeyOpenslEngine(err)))?;
			let key_engine = std::sync::Arc::new(futures_util::lock::Mutex::new(key_engine));
			key_engine
		};

		let cert_client = {
			let cert_service_connector = settings.endpoints.aziot_certd.clone();
			let cert_client = aziot_cert_client_async::Client::new(cert_service_connector);
			let cert_client = std::sync::Arc::new(cert_client);
			cert_client
		};

		let id_manager = identity::IdentityManager::new(key_client.clone(), key_engine.clone(), cert_client.clone(), None);

		Ok(Server {
			settings,
			authenticator,
			authorizer,
			id_manager,

			key_client,
			key_engine,
			cert_client,
		})
	}

	pub async fn get_caller_identity(&self, auth_id: auth::AuthId) -> Result<aziot_identity_common::Identity, Error> {

		if !self.authorizer.authorize(auth::Operation{auth_id, op_type: auth::OperationType::GetDevice })? {
			return Err(Error::Authorization);
		}

		self.id_manager.get_device_identity().await
	}
	pub async fn get_identity(&self, auth_id: auth::AuthId, _idtype: &str, module_id: &str) -> Result<aziot_identity_common::Identity, Error> {

		if !self.authorizer.authorize(auth::Operation{auth_id, op_type: auth::OperationType::GetModule(String::from(module_id)) })? {
			return Err(Error::Authorization);
		}

		self.id_manager.get_module_identity(module_id).await
	}

	pub async fn get_identities(&self, auth_id: auth::AuthId, id_type: &str) -> Result<Vec<aziot_identity_common::Identity>, Error> {

		if !self.authorizer.authorize(auth::Operation{auth_id, op_type: auth::OperationType::GetAllHubModules })? {
			return Err(Error::Authorization);
		}

		if id_type.eq("aziot") {
			self.id_manager.get_module_identities().await
		}
		else {
			Err(Error::invalid_parameter("id_type", "invalid id_type"))
		}
	}

	pub async fn get_device_identity(&self, auth_id: auth::AuthId, _idtype: &str) -> Result<aziot_identity_common::Identity, Error> {

		if !self.authorizer.authorize(auth::Operation{auth_id, op_type: auth::OperationType::GetDevice })? {
			return Err(Error::Authorization);
		}

		self.id_manager.get_device_identity().await
	}

	pub async fn create_identity(&self, auth_id: auth::AuthId, _idtype: &str, module_id: &str) -> Result<aziot_identity_common::Identity, Error> {

		if !self.authorizer.authorize(auth::Operation{auth_id, op_type: auth::OperationType::CreateModule(String::from(module_id)) })? {
			return Err(Error::Authorization);
		}

		//TODO: match identity type based on uid configuration and create and get identity from appropriate identity manager (Hub or local)
		self.id_manager.create_module_identity(module_id).await
	}

	pub async fn delete_identity(&self, auth_id: auth::AuthId, _idtype: &str, module_id: &str) -> Result<(), Error> {

		if !self.authorizer.authorize(auth::Operation{auth_id, op_type: auth::OperationType::DeleteModule(String::from(module_id)) })? {
			return Err(Error::Authorization);
		}

		//TODO: match identity type based on uid configuration and create and get identity from appropriate identity manager (Hub or local)
		self.id_manager.delete_module_identity(module_id).await
	}

	pub async fn get_trust_bundle(&self, auth_id: auth::AuthId) -> Result<aziot_cert_common_http::Pem, Error> {

		if !self.authorizer.authorize(auth::Operation{auth_id, op_type: auth::OperationType::GetTrustBundle })? {
			return Err(Error::Authorization);
		}

		//TODO: invoke get trust bundle
		Ok(aziot_cert_common_http::Pem { 0: std::vec::Vec::default() })
	}

	pub async fn reprovision_device(&mut self, auth_id: auth::AuthId) -> Result<(), Error> {

		if !self.authorizer.authorize(auth::Operation{auth_id, op_type: auth::OperationType::ReprovisionDevice })? {
			return Err(Error::Authorization);
		}

		let _ = self.provision_device().await?;
		Ok(())
	}

	pub async fn init_identities(&self, prev_module_set: std::collections::BTreeSet<aziot_identity_common::ModuleId>, mut current_module_set: std::collections::BTreeSet<aziot_identity_common::ModuleId>) -> Result<(), Error> {
		let hub_module_ids = self.id_manager.get_module_identities().await?;
		for m in hub_module_ids {
			match m {
				aziot_identity_common::Identity::Aziot(m) => {
					if let Some(m) = m.module_id {
						if !current_module_set.contains(&m) && prev_module_set.contains(&m) {
							self.id_manager.delete_module_identity(&m.0).await?;
							log::info!("identity {:?} removed", &m.0);
						}
						else if current_module_set.contains(&m) {
							current_module_set.remove(&m);
							log::info!("identity {:?} already exists", &m.0);
						}
					}
					else {
						log::warn!("invalid identity type returned by get_module_identities");
					}
				}
			}
		}

		for m in current_module_set {
			self.id_manager.create_module_identity(&m.0).await?;
			log::info!("identity {:?} added", &m.0);
		}

		Ok(())
	}

	pub async fn provision_device(&mut self) -> Result<aziot_identity_common::IoTHubDevice, Error> {
		let device = match self.settings.clone().provisioning.provisioning {
			settings::ProvisioningType::Manual { iothub_hostname, device_id, authentication } => {
				
				let credentials = match authentication {
					settings::ManualAuthMethod::SharedPrivateKey { device_id_pk } => {
						aziot_identity_common::Credentials::SharedPrivateKey(device_id_pk)
					},
					settings::ManualAuthMethod::X509 { identity_cert, identity_pk } => { 
						aziot_identity_common::Credentials::X509{identity_cert, identity_pk}
					}
				};
				let device = aziot_identity_common::IoTHubDevice { iothub_hostname, device_id, credentials };
				self.id_manager.set_device(&device);
				device
			},
			settings::ProvisioningType::Dps { global_endpoint, scope_id, attestation} => {
				let device = match attestation {
					settings::DpsAttestationMethod::SymmetricKey { registration_id, symmetric_key } => {
						let result = {
							let mut key_engine = self.key_engine.lock().await;
							aziot_dps_client_async::register(
								global_endpoint.as_str(), 
								&scope_id, 
								&registration_id,
								Some(symmetric_key.clone()),
								None,
								None,
								&self.key_client,
								&mut *key_engine,
								&self.cert_client,
							).await
						};
						let device = match result
						{
							Ok(operation) => {
								let mut retry_count = (DPS_ASSIGNMENT_TIMEOUT_SECS / DPS_ASSIGNMENT_RETRY_INTERVAL_SECS) + 1;
								let credential = aziot_identity_common::Credentials::SharedPrivateKey(symmetric_key.clone());
								loop {
									if retry_count == 0 {
										return Err(Error::DeviceNotFound);
									}
									let credential_clone = credential.clone();
									let result = {
										let mut key_engine = self.key_engine.lock().await;
										aziot_dps_client_async::get_operation_status(
											global_endpoint.as_str(), 
											&scope_id, 
											&registration_id,
											&operation.operation_id,
											Some(symmetric_key.clone()),
											None,
											None,
											&self.key_client,
											&mut *key_engine,
											&self.cert_client,
										).await
									};

									match result {
										Ok(reg_status) => {
											match reg_status.status {
												Some(status) => {
													if !status.eq_ignore_ascii_case("assigning") {
														let mut state = reg_status.registration_state.ok_or(Error::DeviceNotFound)?;
															let iothub_hostname = state.assigned_hub.get_or_insert("".into());
															let device_id = state.device_id.get_or_insert("".into());
															let device = aziot_identity_common::IoTHubDevice { 
																iothub_hostname: iothub_hostname.clone(), 
																device_id: device_id.clone(),
																credentials: credential_clone };
														
														break device;
													}
												}
												None => { return Err(Error::DeviceNotFound) }
											};
										},
										Err(err) => { return Err(Error::DPSClient(err)) }
									}
									retry_count -= 1;
									tokio::time::delay_for(tokio::time::Duration::from_secs(DPS_ASSIGNMENT_RETRY_INTERVAL_SECS)).await;
								}
							},
							Err(err) => return Err(Error::DPSClient(err)) 
						};
						
						self.id_manager.set_device(&device);
						device
					},
					settings::DpsAttestationMethod::X509 { registration_id, identity_cert, identity_pk } => {
						let result = {
							let mut key_engine = self.key_engine.lock().await;
							aziot_dps_client_async::register(
								global_endpoint.as_str(), 
								&scope_id, 
								&registration_id,
								None,
								Some(identity_cert.clone()),
								Some(identity_pk.clone()),
								&self.key_client,
								&mut *key_engine,
								&self.cert_client,
							).await
						};

						let device = match result
						{
							Ok(operation) => {
								let mut retry_count = (DPS_ASSIGNMENT_TIMEOUT_SECS / DPS_ASSIGNMENT_RETRY_INTERVAL_SECS) + 1;
								let credential = aziot_identity_common::Credentials::X509{identity_cert: identity_cert.clone(), identity_pk: identity_pk.clone()};
								loop {
									if retry_count == 0 {
										return Err(Error::DeviceNotFound);
									}
									let credential_clone = credential.clone();
									let result = {
										let mut key_engine = self.key_engine.lock().await;
										aziot_dps_client_async::get_operation_status(
											global_endpoint.as_str(), 
											&scope_id, 
											&registration_id,
											&operation.operation_id,
											None,
											Some(identity_cert.clone()),
											Some(identity_pk.clone()),
											&self.key_client,
											&mut *key_engine,
											&self.cert_client,
										).await
									};

									match result {
										Ok(reg_status) => {
											match reg_status.status {
												Some(status) => {
													if !status.eq_ignore_ascii_case("assigning") {
														let mut state = reg_status.registration_state.ok_or(Error::DeviceNotFound)?;
															let iothub_hostname = state.assigned_hub.get_or_insert("".into());
															let device_id = state.device_id.get_or_insert("".into());
															let device = aziot_identity_common::IoTHubDevice { 
																iothub_hostname: iothub_hostname.clone(), 
																device_id: device_id.clone(),
																credentials: credential_clone };
														
														break device;
													}
												}
												None => { return Err(Error::DeviceNotFound) }
											};
										},
										Err(_) => {return Err(Error::DeviceNotFound) }
									}
									retry_count -= 1;
									tokio::time::delay_for(tokio::time::Duration::from_secs(DPS_ASSIGNMENT_RETRY_INTERVAL_SECS)).await;
								}
							},
							Err(_) => return Err(Error::DeviceNotFound)
						};
						
						self.id_manager.set_device(&device);
						device
					}
				};
				device
			}
		};
		Ok(device)
	}
}

pub struct SettingsAuthorizer {
	pub pmap: std::collections::BTreeMap<crate::auth::Uid, crate::settings::Principal>,
	pub mset: std::collections::BTreeSet<aziot_identity_common::ModuleId>,
}

impl auth::authorization::Authorizer for SettingsAuthorizer
{
	type Error = Error;

	fn authorize(&self, o: auth::Operation) -> Result<bool, Self::Error> {
		match o.op_type {
			crate::auth::OperationType::GetModule(m) => {
				if let crate::auth::AuthId::LocalPrincipal(creds) = o.auth_id {
					if let Some(p) = self.pmap.get(&crate::auth::Uid(creds.0)) {
						return Ok(p.name.0 == m && p.id_type == Some(aziot_identity_common::IdType::Module))
					}
				}
			},
			crate::auth::OperationType::GetDevice => {
				if let crate::auth::AuthId::LocalPrincipal(creds) = o.auth_id {
					if let Some(p) = self.pmap.get(&crate::auth::Uid(creds.0)) {
						return Ok(p.id_type == None || p.id_type == Some(aziot_identity_common::IdType::Device))
					}
				}
			},
			crate::auth::OperationType::CreateModule(m) |
			crate::auth::OperationType::DeleteModule(m) => {
				if let crate::auth::AuthId::LocalPrincipal(creds) = o.auth_id {
					if let Some(p) = self.pmap.get(&crate::auth::Uid(creds.0)) {
						return Ok(p.id_type == None && !self.mset.contains(&aziot_identity_common::ModuleId(m)))
					}
				}
			},
			crate::auth::OperationType::GetTrustBundle => {
				return Ok(true)
			},
			crate::auth::OperationType::GetAllHubModules |
			crate::auth::OperationType::ReprovisionDevice => {
				if let crate::auth::AuthId::LocalPrincipal(creds) = o.auth_id {
					if let Some(p) = self.pmap.get(&crate::auth::Uid(creds.0)) {
						return Ok(p.id_type == None)
					}
				}
			},
		}
		Ok(false)
	}
}
