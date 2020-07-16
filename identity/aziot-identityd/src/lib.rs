// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
)]

pub mod app;
pub mod error;
mod logging;
pub mod settings;

pub use error::Error;

pub struct Server {}

impl Server {
    pub fn new() -> Result<Self, Error> {
        Ok(Server {})
    }
}

#[allow(clippy::unused_self)] // TODO: Remove when the stubs are filled out and `self` actually gets used.
#[allow(clippy::needless_pass_by_value)] // TODO: Remove when the stubs are filled out if the parameters still need to be `String` and not `&str`,
                                         // otherwise change them to `&str`.
impl Server {
    pub fn get_module_identity(&self, _module_id: String) -> Result<aziot_identity_common::Identity, Error> {

        //TODO: match identity type based on uid configuration and get identity from appropriate identity manager (Hub or local)
        Ok(test_module_identity())
    }

    pub fn get_module_identities(&self, _idtype: String) -> Result<Vec<aziot_identity_common::Identity>, Error> {

        //TODO: get identity type and get identities from appropriate identity manager (Hub or local)
        Ok(vec![test_module_identity()])
    }

    pub fn get_device_identity(&self, _idtype: String) -> Result<aziot_identity_common::Identity, Error> {

        //TODO: validate identity type for device is always Hub and get identities from provisioning manager (Hub)
        Ok(test_device_identity())
    }

    pub fn create_identity(&self, _idtype: String, _module_id: String) -> Result<aziot_identity_common::Identity, Error> {

        //TODO: match identity type based on uid configuration and create and get identity from appropriate identity manager (Hub or local)
        Ok(test_module_identity())
    }

    pub fn delete_identity(&self, _module_id: String) -> Result<(), Error> {

        //TODO: match identity type based on uid configuration and create and get identity from appropriate identity manager (Hub or local)
        Ok(())
    }

    pub fn reprovision_device(&self) -> Result<(), Error> {

        //TODO: invoke reprovision
        Ok(())
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
