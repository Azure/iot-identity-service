// Copyright (c) Microsoft. All rights reserved.

use std::io::Error;

use aziot_identity_common::hub::{AuthMechanism, Module};

pub struct Client {}

impl Client {
    pub fn new(
        _device: &aziot_identity_common::IoTHubDevice,
        _key_client: crate::KeyClient,
        _key_engine: crate::KeyEngine,
        _cert_client: crate::CertClient,
    ) -> Self {
        todo!()
    }

    pub fn with_retry(self, _timeout: std::time::Duration, _retries: u32) -> Self {
        todo!()
    }

    pub fn with_proxy(self, _proxy: Option<hyper::Uri>) -> Self {
        todo!()
    }

    pub async fn create_module(
        &self,
        _module_id: &str,
        _authentication_type: Option<AuthMechanism>,
        _managed_by: Option<String>,
    ) -> Result<Module, Error> {
        todo!()
    }

    pub async fn update_module(
        &self,
        _module_id: &str,
        _authentication_type: Option<AuthMechanism>,
        _managed_by: Option<String>,
    ) -> Result<Module, Error> {
        todo!()
    }

    pub async fn get_module(&self, _module_id: &str) -> Result<Module, Error> {
        todo!()
    }

    pub async fn list_modules(&self) -> Result<Vec<Module>, Error> {
        todo!()
    }

    pub async fn delete_module(&self, _module_id: &str) -> Result<(), Error> {
        todo!()
    }
}
