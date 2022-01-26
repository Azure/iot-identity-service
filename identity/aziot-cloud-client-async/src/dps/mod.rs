// Copyright (c) Microsoft. All rights reserved.

pub mod response {
    pub struct DeviceRegistration {
        pub assigned_hub: String,
        pub device_id: String,
    }
}

pub struct Client {}

impl Client {
    pub fn new(
        _credentials: &aziot_identity_common::Credentials,
        _key_client: crate::KeyClient,
        _key_engine: crate::KeyEngine,
        _cert_client: crate::CertClient,
        _tpm_client: crate::TpmClient,
    ) -> Self {
        todo!()
    }

    pub fn with_endpoint(self, _endpoint: url::Url) -> Self {
        todo!()
    }

    pub fn with_retry(self, _timeout: std::time::Duration, _retries: u32) -> Self {
        todo!()
    }

    pub fn with_proxy(self, _proxy: Option<hyper::Uri>) -> Self {
        todo!()
    }

    pub async fn register(
        self,
        _scope_id: &str,
        _registration_id: &str,
    ) -> Result<response::DeviceRegistration, std::io::Error> {
        todo!()
    }
}
