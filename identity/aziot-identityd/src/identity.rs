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
				let response  = client.create_module(&*module_id, None, None).await
					.map_err(Error::HubClient)?;
				
				//TODO: compute derived key (when KS API is available) after retrieving genid from server and update_module with new auth credentials
				let response  = client.update_module(
					&*response.module_id,
						Some(aziot_identity_common::hub::AuthMechanism {
							symmetric_key: Some(aziot_identity_common::hub::SymmetricKey { 
								primary_key: Some(String::from("primary")), 
								secondary_key: Some(String::from("secondary")),
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
					auth: Some(aziot_identity_common::AuthenticationInfo::from(device.credentials.clone())), //TODO: switch from temporary creds after create_derived_key is added to KS
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
				let response  = client.get_module(&*module_id).await
					.map_err(Error::HubClient)?;
				let identity = aziot_identity_common::Identity::Aziot(aziot_identity_common::AzureIoTSpec {
					hub_name: device.iothub_hostname.clone(),
					device_id: aziot_identity_common::DeviceId(response.device_id),
					module_id: Some(aziot_identity_common::ModuleId(response.module_id)),
					gen_id: response.generation_id.map(aziot_identity_common::GenId),
					auth: Some(aziot_identity_common::AuthenticationInfo::from(device.credentials.clone())), //TODO: switch from temporary creds after create_derived_key is added to KS
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
						auth: Some(aziot_identity_common::AuthenticationInfo::from(device.credentials.clone())), //TODO: switch from temporary creds after create_derived_key is added to KS
						})
				}).collect();
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
}
