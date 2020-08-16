// Copyright (c) Microsoft. All rights reserved.

use crate::error::Error;

const IOTHUB_ENCODE_SET: &percent_encoding::AsciiSet =
	&http_common::PATH_SEGMENT_ENCODE_SET
	.add(b'=');

#[derive(Default)]
pub struct IdentityManager {
	locks: std::sync::Mutex<std::collections::BTreeMap<String, std::sync::Arc<std::sync::Mutex<()>>>>,
	iot_hub_device: Option<aziot_identity_common::IoTHubDevice>,
}

impl IdentityManager {
	pub fn new(iot_hub_device: Option<aziot_identity_common::IoTHubDevice>) -> Self {
		IdentityManager {
			locks: Default::default(),
			iot_hub_device, //set by Server over futures channel
		}
	}

	pub fn set_device(&mut self, device: aziot_identity_common::IoTHubDevice) {
		self.iot_hub_device = Some(device);
	}

	pub async fn create_module_identity(&self, module_id: &str) -> Result<aziot_identity_common::Identity, Error> {		
		if module_id.trim().is_empty() {
			return Err(Error::invalid_parameter("module_id", "module name cannot be empty"));
		}
		
		match &self.iot_hub_device {
			Some(device) => {
				let client = aziot_hub_client_async::Client::new(device.clone());
				let new_module  = client.create_module(&*module_id, None, None).await
					.map_err(Error::HubClient)?;
				
				let master_id_key_handle = crate::identity::IdentityManager::get_master_identity_key().await?;
				let (primary_key_handle, _, primary_key, secondary_key) = 
					crate::identity::IdentityManager::get_module_derived_keys(master_id_key_handle,new_module.clone()).await?;
				let module_credentials = aziot_identity_common::Credentials::SharedPrivateKey(primary_key_handle.0);

				let response  = client.update_module(
					&*new_module.module_id,
						Some(aziot_identity_common::hub::AuthMechanism {
							symmetric_key: Some(aziot_identity_common::hub::SymmetricKey { 
								primary_key: Some(http_common::ByteString(primary_key)), 
								secondary_key: Some(http_common::ByteString(secondary_key)),
							}),
							x509_thumbprint: None, 
							type_: Some(aziot_identity_common::hub::AuthType::Sas),
						}),
		None).await
					.map_err(Error::HubClient)?;
					
				let identity = aziot_identity_common::Identity::Aziot(aziot_identity_common::AzureIoTSpec {
					hub_name: device.iothub_hostname.clone(),
					device_id: aziot_identity_common::DeviceId(response.device_id),
					module_id: Some(aziot_identity_common::ModuleId(response.module_id)),
					gen_id: response.generation_id.map(aziot_identity_common::GenId),
					auth: Some(aziot_identity_common::AuthenticationInfo::from(module_credentials)),
					});	
				Ok(identity)
			},
			None => Err(Error::DeviceNotFound)
		}
	}
	
	pub async fn get_device_identity(&self) -> Result<aziot_identity_common::Identity, Error> {
		match &self.iot_hub_device {
			Some(device) => Ok(aziot_identity_common::Identity::Aziot(
				aziot_identity_common::AzureIoTSpec {
					hub_name: device.iothub_hostname.clone(),
					device_id: aziot_identity_common::DeviceId(device.device_id.clone()),
					module_id: None,
					gen_id: None,
					auth: Some(aziot_identity_common::AuthenticationInfo::from(device.credentials.clone())),
					}
			)),
			None => Err(Error::DeviceNotFound)
		}
		
	}

	pub async fn get_module_identity(&self, module_id: &str) -> Result<aziot_identity_common::Identity, Error> {		
		if module_id.trim().is_empty() {
			return Err(Error::invalid_parameter("module_id", "module name cannot be empty"));
		}
		
		match &self.iot_hub_device {
			Some(device) => {
				let client = aziot_hub_client_async::Client::new(device.clone());
				let module  = client.get_module(&*module_id).await
					.map_err(Error::HubClient)?;

				let master_id_key_handle = crate::identity::IdentityManager::get_master_identity_key().await?;
				let (primary_key_handle, _, _, _) = 
					crate::identity::IdentityManager::get_module_derived_keys(master_id_key_handle,module.clone()).await?;
				let module_credentials = aziot_identity_common::Credentials::SharedPrivateKey(primary_key_handle.0);
				
				let identity = aziot_identity_common::Identity::Aziot(aziot_identity_common::AzureIoTSpec {
					hub_name: device.iothub_hostname.clone(),
					device_id: aziot_identity_common::DeviceId(module.device_id),
					module_id: Some(aziot_identity_common::ModuleId(module.module_id)),
					gen_id: module.generation_id.map(aziot_identity_common::GenId),
					auth: Some(aziot_identity_common::AuthenticationInfo::from(module_credentials)),
					});
				
				Ok(identity)
			},
			None => Err(Error::DeviceNotFound)
		}
	}

	pub async fn get_module_identities(&self) -> Result<Vec<aziot_identity_common::Identity>, Error> {		
		match &self.iot_hub_device {
			Some(device) => {
				let client = aziot_hub_client_async::Client::new(device.clone());
				let response  = client.get_modules().await
					.map_err(Error::HubClient)?;

				let identities = response.into_iter().map(|module| {
					aziot_identity_common::Identity::Aziot(aziot_identity_common::AzureIoTSpec {
						hub_name: device.iothub_hostname.clone(),
						device_id: aziot_identity_common::DeviceId(module.device_id),
						module_id: Some(aziot_identity_common::ModuleId(module.module_id)),
						gen_id: module.generation_id.map(aziot_identity_common::GenId),
						auth: None, //Auth information can be requested via get_module_identity
					})}).collect();
				Ok(identities)
			},
			None => Err(Error::DeviceNotFound)
		}
	}

	pub async fn delete_module_identity(&self, module_id: &str) -> Result<(), Error> {		
		if module_id.trim().is_empty() {
			return Err(Error::invalid_parameter("module_id", "module name cannot be empty"));
		}
		
		match &self.iot_hub_device {
			Some(device) => {
				let client = aziot_hub_client_async::Client::new(device.clone());
				client.delete_module(&*module_id).await.map_err(Error::HubClient)
			},
			None => Err(Error::DeviceNotFound)
		}
	}

	async fn get_master_identity_key() -> Result<aziot_key_common::KeyHandle, Error> {
		let key_client = {
			#[derive(Clone, Copy)]
			struct Connector;
	
			impl hyper::service::Service<hyper::Uri> for Connector {
				type Response = tokio::net::TcpStream;
				type Error = std::io::Error;
				type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;
	
				fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
					std::task::Poll::Ready(Ok(()))
				}
	
				fn call(&mut self, _req: hyper::Uri) -> Self::Future {
					let f = async {
						let stream: tokio::net::TcpStream = tokio::net::TcpStream::connect(("localhost", 8888)).await?;
						Ok(stream)
					};
					Box::pin(f)
				}
			}
	
			let key_client = aziot_key_client_async::Client::new(Connector);
			let key_client = std::sync::Arc::new(key_client);
			key_client
		};
		
		let result = key_client.load_key("aziot_identityd_master_id").await;
		match result {
			Ok(key_handle) => Ok(key_handle),
			Err(_) => {
				key_client.create_key_if_not_exists("aziot_identityd_master_id", aziot_key_common::CreateKeyValue::Generate { length: 32 }).await
					.map_err(|err| Error::Internal(crate::error::InternalError::MasterIdentityKey(err)))
			}
		}
	}

	async fn get_module_derived_keys(master_id: aziot_key_common::KeyHandle, module: aziot_identity_common::hub::Module) -> Result<(aziot_key_common::KeyHandle, aziot_key_common::KeyHandle, Vec<u8>, Vec<u8>), Error> {
		let key_client = {
			#[derive(Clone, Copy)]
			struct Connector;
	
			impl hyper::service::Service<hyper::Uri> for Connector {
				type Response = tokio::net::TcpStream;
				type Error = std::io::Error;
				type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;
	
				fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
					std::task::Poll::Ready(Ok(()))
				}
	
				fn call(&mut self, _req: hyper::Uri) -> Self::Future {
					let f = async {
						let stream: tokio::net::TcpStream = tokio::net::TcpStream::connect(("localhost", 8888)).await?;
						Ok(stream)
					};
					Box::pin(f)
				}
			}
	
			let key_client = aziot_key_client_async::Client::new(Connector);
			let key_client = std::sync::Arc::new(key_client);
			key_client
		};
		
		let mut module_derived_name = module.module_id;
		module_derived_name.push_str(":");
		module_derived_name.push_str(&module.generation_id.ok_or(Error::ModuleNotFound)?);

		let mut primary_derived_name = module_derived_name.clone();
		primary_derived_name.push_str(":");
		primary_derived_name.push_str("primary");

		let mut secondary_derived_name = module_derived_name;
		secondary_derived_name.push_str(":");
		secondary_derived_name.push_str("secondary");

		let primary_key_handle = key_client.create_derived_key(&master_id, &primary_derived_name.into_bytes()).await
		.map_err(|err| Error::Internal(crate::error::InternalError::MasterIdentityKey(err)))?;
		let primary_key = key_client.export_derived_key(&primary_key_handle.clone()).await
		.map_err(|err| Error::Internal(crate::error::InternalError::MasterIdentityKey(err)))?;

		let secondary_key_handle = key_client.create_derived_key(&master_id, &secondary_derived_name.into_bytes()).await
		.map_err(|err| Error::Internal(crate::error::InternalError::MasterIdentityKey(err)))?;
		let secondary_key = key_client.export_derived_key(&secondary_key_handle.clone()).await
		.map_err(|err| Error::Internal(crate::error::InternalError::MasterIdentityKey(err)))?;

		Ok((primary_key_handle, secondary_key_handle, primary_key, secondary_key))

	}
}
