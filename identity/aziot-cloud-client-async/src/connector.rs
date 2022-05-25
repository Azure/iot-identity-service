// Copyright (c) Microsoft. All rights reserved.

use std::io::{Error, ErrorKind};

pub(crate) fn from_auth(
    auth: &aziot_identity_common::Credentials,
    proxy_uri: Option<hyper::Uri>,
) -> Result<crate::CloudConnector, Error> {
    match auth {
        aziot_identity_common::Credentials::SharedPrivateKey(_)
        | aziot_identity_common::Credentials::Tpm => {
            crate::CloudConnector::new(proxy_uri, None, &[])
        }

        aziot_identity_common::Credentials::X509 {
            identity_cert,
            identity_pk,
        } => {
            if identity_cert.1.is_empty() {
                return Err(Error::new(ErrorKind::InvalidInput, "no certs in stack"));
            }

            let mut identity_cert_pem = Vec::new();

            for cert in &identity_cert.1 {
                let mut cert = cert
                    .to_pem()
                    .map_err(|_| Error::new(ErrorKind::Other, "bad cert"))?;

                identity_cert_pem.append(&mut cert);
            }

            crate::CloudConnector::new(proxy_uri, Some((&identity_cert_pem, &identity_pk.1)), &[])
        }
    }
}

pub(crate) enum Audience<'a> {
    Registration {
        scope_id: &'a str,
        registration_id: &'a str,
    },
    Hub {
        hub_hostname: &'a str,
        device_id: &'a str,
    },
}

pub(crate) async fn auth_header(
    audience: Audience<'_>,
    auth: &aziot_identity_common::Credentials,
    key_client: &crate::KeyClient,
    tpm_client: &crate::TpmClient,
) -> Result<Option<String>, Error> {
    let (audience, is_registration) = match audience {
        Audience::Registration {
            scope_id,
            registration_id,
        } => (
            format!("{}/registrations/{}", scope_id, registration_id),
            true,
        ),

        Audience::Hub {
            hub_hostname,
            device_id,
        } => (format!("{}/devices/{}", hub_hostname, device_id), false),
    };

    match auth {
        aziot_identity_common::Credentials::Tpm => {
            let token = generate_token(&audience, None, tpm_client, is_registration).await?;

            Ok(Some(token))
        }

        aziot_identity_common::Credentials::SharedPrivateKey(key_id) => {
            let key_handle = key_client.load_key(key_id).await?;

            let token =
                generate_token(&audience, Some(&key_handle), key_client, is_registration).await?;

            Ok(Some(token))
        }

        aziot_identity_common::Credentials::X509 { .. } => Ok(None),
    }
}

#[async_trait::async_trait]
trait SignData {
    async fn sign_data(
        &self,
        key_handle: Option<&aziot_key_common::KeyHandle>,
        data: &[u8],
    ) -> Result<Vec<u8>, Error>;
}

#[async_trait::async_trait]
impl SignData for crate::KeyClient {
    async fn sign_data(
        &self,
        key_handle: Option<&aziot_key_common::KeyHandle>,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let key_handle = key_handle.expect("missing key handle");

        self.sign(
            key_handle,
            aziot_key_common::SignMechanism::HmacSha256,
            data,
        )
        .await
    }
}

#[async_trait::async_trait]
impl SignData for crate::TpmClient {
    async fn sign_data(
        &self,
        _key_handle: Option<&aziot_key_common::KeyHandle>,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // We only store a single key in the TPM, so there isn't any need for distinct key handles.
        self.sign_with_auth_key(data).await
    }
}

async fn generate_token(
    audience: &str,
    key_handle: Option<&aziot_key_common::KeyHandle>,
    client: &impl SignData,
    is_registration: bool,
) -> Result<String, Error> {
    let expiry = chrono::Utc::now() + chrono::Duration::seconds(30);
    let expiry = expiry.timestamp().to_string();

    let audience = audience.to_lowercase();
    let resource_uri = percent_encoding::percent_encode(audience.as_bytes(), crate::ENCODE_SET);

    let sig_data = format!("{}\n{}", resource_uri, expiry);
    let signature = client.sign_data(key_handle, sig_data.as_bytes()).await?;
    let signature = base64::encode(&signature);

    let token = {
        let mut token = url::form_urlencoded::Serializer::new(format!("sr={}", resource_uri));

        token
            .append_pair("sig", &signature)
            .append_pair("se", &expiry);

        if is_registration {
            token.append_pair("skn", "registration");
        }

        token.finish()
    };

    Ok(format!("SharedAccessSignature {}", token))
}
