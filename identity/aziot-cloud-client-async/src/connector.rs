// Copyright (c) Microsoft. All rights reserved.

use std::io::{Error, ErrorKind};

pub(crate) async fn from_auth(
    auth: &aziot_identity_common::Credentials,
    proxy_uri: Option<hyper::Uri>,
    key_client: &crate::KeyClient,
    key_engine: &crate::KeyEngine,
    cert_client: &crate::CertClient,
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
            let private_key = {
                let key_handle = key_client.load_key_pair(identity_pk).await?;
                let key_handle = std::ffi::CString::new(key_handle.0)?;

                let mut key_engine = key_engine.lock().await;

                key_engine
                    .load_private_key(&key_handle)
                    .map_err(|err| Error::new(ErrorKind::Other, err))?
            };

            let cert = cert_client.get_cert(identity_cert).await?;

            crate::CloudConnector::new(proxy_uri, Some((&cert, &private_key)), &[])
        }
    }
}

#[async_trait::async_trait]
pub(crate) trait SignData {
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

pub(crate) async fn auth_header(
    audience: &str,
    key_handle: Option<&aziot_key_common::KeyHandle>,
    client: &impl SignData,
) -> Result<String, Error> {
    let expiry = chrono::Utc::now() + chrono::Duration::seconds(30);
    let expiry = expiry.timestamp().to_string();

    const ENCODE_SET: &percent_encoding::AsciiSet = &http_common::PATH_SEGMENT_ENCODE_SET.add(b'=');
    let resource_uri =
        percent_encoding::percent_encode(audience.to_lowercase().as_bytes(), ENCODE_SET)
            .to_string();

    let sig_data = format!("{}\n{}", &resource_uri, expiry);
    let signature = client.sign_data(key_handle, sig_data.as_bytes()).await?;
    let signature = base64::encode(&signature);

    let token = {
        let mut token = url::form_urlencoded::Serializer::new(format!("sr={}", resource_uri));

        token
            .append_pair("sig", &signature)
            .append_pair("se", &expiry);

        // Absence of a key handle means TPM registration.
        if key_handle.is_none() {
            token.append_pair("skn", "registration");
        }

        token.finish()
    };

    Ok(format!("SharedAccessSignature {}", token))
}
