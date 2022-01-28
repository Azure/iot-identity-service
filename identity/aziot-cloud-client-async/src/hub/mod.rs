// Copyright (c) Microsoft. All rights reserved.

use std::io::Error;

use aziot_identity_common::hub::{AuthMechanism, Module};

pub struct Client {
    auth: aziot_identity_common::Credentials,

    timeout: std::time::Duration,
    retries: u32,

    proxy: Option<hyper::Uri>,
}

impl Client {
    pub fn new(
        device: &aziot_identity_common::IoTHubDevice,
        _key_client: crate::KeyClient,
        _key_engine: crate::KeyEngine,
        _cert_client: crate::CertClient,
    ) -> Self {
        Client {
            auth: device.credentials.clone(),
            timeout: std::time::Duration::from_secs(30),
            retries: 0,
            proxy: None,
        }
    }

    pub fn with_retry(mut self, timeout: std::time::Duration, retries: u32) -> Self {
        self.timeout = timeout;
        self.retries = retries;

        self
    }

    pub fn with_proxy(mut self, proxy: Option<hyper::Uri>) -> Self {
        self.proxy = proxy;

        self
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
