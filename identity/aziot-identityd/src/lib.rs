// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::missing_errors_doc,
	clippy::module_name_repetitions,
)]
#![allow(dead_code)]

pub mod auth;
pub mod app;
pub mod error;
pub mod identity;
mod logging;
pub mod settings;

pub use error::Error;
use crate::auth::{Operation, OperationType};
use crate::auth::authentication::{Authenticator};
use crate::auth::authorization::{Authorizer};
use aziot_identity_common::ModuleId;

pub struct Server {
	pub authenticator: Box<dyn Authenticator<Error = Error>  + Send + Sync>,
	pub authorizer: Box<dyn Authorizer<Error = Error>  + Send + Sync>,
}

#[allow(clippy::unused_self)] // TODO: Remove when the stubs are filled out and `self` actually gets used.
impl Server {
	pub fn new(authenticator: Box<dyn Authenticator<Error = Error>  + Send + Sync>, authorizer: Box<dyn Authorizer<Error = Error>  + Send + Sync>) -> Result<Self, Error> {
		Ok(Server {
			authenticator,
			authorizer
		})
	}

	pub fn get_caller_identity(&self, auth_id: auth::AuthId) -> Result<aziot_identity_common::Identity, Error> {

		//TODO: Change authorization on get_identity or get_device_identity call, depending on caller's configuration
		if !self.authorizer.authorize(Operation{auth_id, op_type: OperationType::GetDevice })? {
			return Err(Error::Authorization);
		}

		Ok(test_module_identity())
	}
	pub fn get_identity(&self, auth_id: auth::AuthId, _idtype: &str, module_id: &str) -> Result<aziot_identity_common::Identity, Error> {

		if !self.authorizer.authorize(Operation{auth_id, op_type: OperationType::GetModule(String::from(module_id)) })? {
			return Err(Error::Authorization);
		}

		Ok(test_module_identity())
	}

	pub fn get_hub_identities(&self, auth_id: auth::AuthId, _idtype: &str) -> Result<Vec<aziot_identity_common::Identity>, Error> {

		if !self.authorizer.authorize(Operation{auth_id, op_type: OperationType::GetAllHubModules })? {
			return Err(Error::Authorization);
		}

		//TODO: get identity type and get identities from appropriate identity manager (Hub or local)
		Ok(vec![test_module_identity()])
	}

	pub fn get_device_identity(&self, auth_id: auth::AuthId, _idtype: &str) -> Result<aziot_identity_common::Identity, Error> {

		if !self.authorizer.authorize(Operation{auth_id, op_type: OperationType::GetDevice })? {
			return Err(Error::Authorization);
		}

		Ok(test_device_identity())
	}

	pub fn create_identity(&self, auth_id: auth::AuthId, _idtype: &str, module_id: &str) -> Result<aziot_identity_common::Identity, Error> {

		if !self.authorizer.authorize(Operation{auth_id, op_type: OperationType::CreateModule(String::from(module_id)) })? {
			return Err(Error::Authorization);
		}

		//TODO: match identity type based on uid configuration and create and get identity from appropriate identity manager (Hub or local)
		Ok(test_module_identity())
	}

	pub fn delete_identity(&self, auth_id: auth::AuthId, _idtype: &str, module_id: &str) -> Result<(), Error> {

		if !self.authorizer.authorize(Operation{auth_id, op_type: OperationType::DeleteModule(String::from(module_id)) })? {
			return Err(Error::Authorization);
		}

		//TODO: match identity type based on uid configuration and create and get identity from appropriate identity manager (Hub or local)
		Ok(())
	}

	pub fn get_trust_bundle(&self, auth_id: auth::AuthId) -> Result<aziot_cert_common_http::Pem, Error> {

		if !self.authorizer.authorize(Operation{auth_id, op_type: OperationType::GetTrustBundle })? {
			return Err(Error::Authorization);
		}

		//TODO: invoke get trust bundle
		Ok(aziot_cert_common_http::Pem { 0: std::vec::Vec::default() })
	}

	pub fn reprovision_device(&self, auth_id: auth::AuthId) -> Result<(), Error> {

		if !self.authorizer.authorize(Operation{auth_id, op_type: OperationType::ReprovisionDevice })? {
			return Err(Error::Authorization);
		}

		//TODO: invoke reprovision
		Ok(())
	}
}

pub struct SettingsAuthorizer {
	pub pmap: std::collections::BTreeMap<crate::auth::Uid, crate::settings::Principal>,
	pub mset: std::collections::BTreeSet<ModuleId>,
}

impl Authorizer for SettingsAuthorizer
{
	type Error = Error;

	fn authorize(&self, o: Operation) -> Result<bool, error::Error> {
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
						return Ok(p.id_type == None && !self.mset.contains(&ModuleId(m)))
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

fn test_device_identity() -> aziot_identity_common::Identity {
	aziot_identity_common::Identity::Aziot(
		aziot_identity_common::AzureIoTSpec {
			hub_name: "dummyHubName".to_string(),
			device_id: aziot_identity_common::DeviceId("dummyDeviceId".to_string()),
			module_id: None,
			gen_id: None,
			auth: aziot_identity_common::AuthenticationInfo {
				auth_type: aziot_identity_common::AuthenticationType::SaS,
				key_handle: aziot_key_common::KeyHandle("dummyKeyHandle".to_string()),
				cert_id: None,
			}})
}

fn test_module_identity() -> aziot_identity_common::Identity {
	aziot_identity_common::Identity::Aziot (
		aziot_identity_common::AzureIoTSpec {
			hub_name: "dummyHubName".to_string(),
			device_id: aziot_identity_common::DeviceId("dummyDeviceId".to_string()),
			module_id: Some(aziot_identity_common::ModuleId("dummyModuleId".to_string())),
			gen_id: Some(aziot_identity_common::GenId("dummyGenId".to_string())),
			auth: aziot_identity_common::AuthenticationInfo {
				auth_type: aziot_identity_common::AuthenticationType::SaS,
				key_handle: aziot_key_common::KeyHandle("dummyKeyHandle".to_string()),
				cert_id: None,
			}})
}
