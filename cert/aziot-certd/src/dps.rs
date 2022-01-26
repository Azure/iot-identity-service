// Copyright (c) Microsoft. All rights reserved.

use aziot_identity_common_http::get_provisioning_info::Response as ProvisioningInfo;

#[cfg(not(test))]
use aziot_identity_client_async::Client as IdentityClient;

#[cfg(test)]
use test_common::client::IdentityClient;

pub(crate) async fn check_policy(
    client: &IdentityClient,
    csr: &openssl::x509::X509Req,
) -> Option<ProvisioningInfo> {
    let provisioning_info = match client.get_provisioning_info().await {
        Ok(provisioning_info) => provisioning_info,
        Err(err) => {
            log::warn!("Could not query provisioning info: {}", err);

            return None;
        }
    };

    // Check for issuance policy.
    // if lets cannot be collapsed because of dependency on certificate_issuance_policy.
    #[allow(clippy::collapsible_match)]
    let policy = if let ProvisioningInfo::Dps {
        certificate_issuance_policy,
        ..
    } = &provisioning_info
    {
        if let Some(policy) = certificate_issuance_policy {
            policy
        } else {
            return None;
        }
    } else {
        return None;
    };

    // Check CSR extended key usage against policy type.
    let extensions = csr.extensions().ok()?;

    match policy.certificate_issuance_type {
        aziot_identity_common::CertIssuanceType::ServerCertificate => {
            // Check that extended key usage has serverAuth set for server certificates.
            let mut has_server_auth = false;

            for extension in extensions {
                if let Some(ext_key_usage) = openssl2::extension::ExtKeyUsage::from_ext(&extension)
                {
                    has_server_auth = ext_key_usage.server_auth;

                    // extKeyUsage should only appear once in the list of extensions, so stop when
                    // it's found.
                    break;
                }
            }

            if !has_server_auth {
                return None;
            }
        }
        aziot_identity_common::CertIssuanceType::None => return None,
    }

    // Check CSR key against issuance policy.
    // TODO

    Some(provisioning_info)
}
