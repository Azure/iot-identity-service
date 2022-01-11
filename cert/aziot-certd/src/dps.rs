// Copyright (c) Microsoft. All rights reserved.

use aziot_identity_common_http::get_provisioning_info::Response as ProvisioningInfo;

pub(crate) async fn check_policy(
    client: &aziot_identity_client_async::Client,
    csr: &openssl::x509::X509Req,
) -> Option<ProvisioningInfo> {
    let provisioning_info = client.get_provisioning_info().await.ok()?;

    match &provisioning_info {
        ProvisioningInfo::Dps {
            auth: _,
            endpoint: _,
            scope_id: _,
            registration_id: _,
            certificate_issuance_policy,
        } => {
            let policy = match certificate_issuance_policy {
                Some(policy) => policy,
                None => return None,
            };

            Some(provisioning_info)
        }
        _ => None,
    }
}

pub(crate) async fn issue_cert(
    csr: &openssl::x509::X509Req,
    policy: ProvisioningInfo,
) -> Result<Vec<u8>, crate::Error> {
    todo!()
}
