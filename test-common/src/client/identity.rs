// Copyright (c) Microsoft. All rights reserved.

use aziot_identity_common::Identity;
use aziot_identity_common_http::get_provisioning_info::Response as ProvisioningInfo;

#[allow(clippy::struct_excessive_bools)]
pub struct IdentityClient {
    pub get_provisioning_info_ok: bool,
    pub create_identity_ok: bool,
    pub get_identities_ok: bool,
    pub get_identity_ok: bool,
    pub update_identity_ok: bool,
    pub delete_identity_ok: bool,

    pub provisioning_info: ProvisioningInfo,

    // Because the signatures of this test client must match the real client, the test client's
    // functions cannot use `mut self` as a parameter.
    //
    // The test client may need to mutate this map of identities, so the workaround is to place it in
    // a RefCell and use replace_with.
    pub identities:
        futures_util::lock::Mutex<std::cell::RefCell<std::collections::BTreeMap<String, Identity>>>,
}

impl Default for IdentityClient {
    fn default() -> Self {
        let mut identities = std::collections::BTreeMap::new();
        identities.insert("testModule".to_string(), test_identity("testModule"));

        let identities = futures_util::lock::Mutex::new(std::cell::RefCell::new(identities));

        IdentityClient {
            get_provisioning_info_ok: true,
            create_identity_ok: true,
            get_identities_ok: true,
            get_identity_ok: true,
            update_identity_ok: true,
            delete_identity_ok: true,

            provisioning_info: provisioning_info(),
            identities,
        }
    }
}

impl IdentityClient {
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(
        _api_version: aziot_identity_common_http::ApiVersion,
        _connector: http_common::Connector,
        _max_retries: u32,
    ) -> Self {
        Self::default()
    }

    pub async fn get_provisioning_info(&self) -> Result<ProvisioningInfo, std::io::Error> {
        if self.get_provisioning_info_ok {
            Ok(self.provisioning_info.clone())
        } else {
            Err(super::client_error())
        }
    }

    pub async fn create_module_identity(
        &self,
        module_name: &str,
    ) -> Result<Identity, std::io::Error> {
        if self.get_identity_ok {
            let identity = test_identity(module_name);

            let identities = self.identities.lock().await;

            identities.replace_with(|identities| {
                identities.insert(module_name.to_string(), identity.clone());

                identities.clone()
            });

            Ok(identity)
        } else {
            Err(super::client_error())
        }
    }

    pub async fn get_identities(&self) -> Result<Vec<Identity>, std::io::Error> {
        if self.get_identities_ok {
            let identities = {
                let identities = self.identities.lock().await;

                identities.replace_with(|identities| identities.clone())
            };

            let mut identities_list = vec![];

            for (_, identity) in identities {
                identities_list.push(identity.clone());
            }

            Ok(identities_list)
        } else {
            Err(super::client_error())
        }
    }

    pub async fn get_identity(&self, module_name: &str) -> Result<Identity, std::io::Error> {
        if self.get_identity_ok {
            let identities = {
                let identities = self.identities.lock().await;

                identities.replace_with(|identities| identities.clone())
            };

            match identities.get(module_name) {
                Some(identity) => Ok(identity.clone()),
                None => Err(super::client_error()),
            }
        } else {
            Err(super::client_error())
        }
    }

    pub async fn update_module_identity(
        &self,
        module_name: &str,
    ) -> Result<Identity, std::io::Error> {
        if self.update_identity_ok {
            // A real identity client would update the Idenitity in Hub. But this test
            // client can just return the existing Identity.
            self.get_identity(module_name).await
        } else {
            Err(super::client_error())
        }
    }

    pub async fn delete_identity(&self, module_name: &str) -> Result<(), std::io::Error> {
        if self.delete_identity_ok {
            let identities = self.identities.lock().await;

            identities.replace_with(|identities| {
                identities.remove(module_name);

                identities.clone()
            });

            Ok(())
        } else {
            Err(super::client_error())
        }
    }
}

/// Generates an Identity struct for a given module name.
fn test_identity(module_name: &str) -> Identity {
    Identity::Aziot(aziot_identity_common::AzureIoTSpec {
        hub_name: "test-hub.test.net".to_string(),
        gateway_host: "gateway-host.test.net".to_string(),
        device_id: aziot_identity_common::DeviceId("test-device".to_string()),
        module_id: Some(aziot_identity_common::ModuleId(module_name.to_string())),
        gen_id: Some(aziot_identity_common::GenId("test-gen-id".to_string())),
        auth: Some(aziot_identity_common::AuthenticationInfo {
            auth_type: aziot_identity_common::AuthenticationType::X509,
            key_handle: Some(aziot_key_common::KeyHandle(format!("{}-key", module_name))),
            cert_id: Some(format!("{}-cert", module_name)),
        }),
    })
}

/// Generate a ProvisioningInfo with CertIssuancePolicy.
fn provisioning_info() -> ProvisioningInfo {
    ProvisioningInfo::Dps {
        auth: "x509".to_string(),
        endpoint: "localhost".to_string(),
        scope_id: "scope".to_string(),
        registration_id: Some("registrationId".to_string()),
        certificate_issuance_policy: Some(aziot_identity_common::CertIssuancePolicy {
            end_point: "localhost".to_string(),
            certificate_issuance_type: aziot_identity_common::CertIssuanceType::ServerCertificate,
            key_length_in_bits: 2048,
            key_curve: None,
        }),
    }
}
