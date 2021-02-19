// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::let_and_return, clippy::missing_errors_doc)]

use std::io;

use http_common::MaybeProxyConnector;

pub const ENCODE_SET: &percent_encoding::AsciiSet = &http_common::PATH_SEGMENT_ENCODE_SET.add(b'=');

/// `key_client` must be either an `aziot_key_client_async::Client` or an `aziot_tpm_client_async::Client`.
pub async fn get_sas_connector(
    audience: &str,
    key_handle: impl AsRef<[u8]>,
    key_client: &impl KeyClient,
    proxy_uri: Option<hyper::Uri>,
    is_tpm_registration: bool,
) -> io::Result<(
    MaybeProxyConnector<hyper_openssl::HttpsConnector<hyper::client::HttpConnector>>,
    String,
)> {
    let key_handle = key_client.insert_key(key_handle.as_ref()).await?;

    let token = {
        let expiry = chrono::Utc::now()
            + chrono::Duration::from_std(std::time::Duration::from_secs(30))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let expiry = expiry.timestamp().to_string();

        let resource_uri =
            percent_encoding::percent_encode(audience.to_lowercase().as_bytes(), ENCODE_SET)
                .to_string();
        let sig_data = format!("{}\n{}", &resource_uri, expiry);

        let signature = key_client
            .sign_with_key(&key_handle, sig_data.as_bytes())
            .await?;

        let signature = base64::encode(&signature);

        let mut token = url::form_urlencoded::Serializer::new(format!("sr={}", resource_uri));
        token
            .append_pair("sig", &signature)
            .append_pair("se", &expiry);
        if is_tpm_registration {
            token.append_pair("skn", "registration");
        }
        token.finish()
    };

    let token = format!("SharedAccessSignature {}", token);

    let proxy_connector = MaybeProxyConnector::new(proxy_uri, None)?;
    Ok((proxy_connector, token))
}

pub async fn get_x509_connector(
    identity_cert: &str,
    identity_pk: &str,
    key_client: &aziot_key_client_async::Client,
    key_engine: &mut openssl2::FunctionalEngineRef,
    cert_client: &aziot_cert_client_async::Client,
    proxy_uri: Option<hyper::Uri>,
) -> io::Result<MaybeProxyConnector<hyper_openssl::HttpsConnector<hyper::client::HttpConnector>>> {
    let device_id_private_key = {
        let device_id_key_handle = key_client.load_key_pair(&identity_pk).await?;
        let device_id_key_handle = std::ffi::CString::new(device_id_key_handle.0)?;
        let device_id_private_key = key_engine
            .load_private_key(&device_id_key_handle)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        device_id_private_key
    };

    let device_id_certs = cert_client.get_cert(&identity_cert).await?;

    let proxy_connector =
        MaybeProxyConnector::new(proxy_uri, Some((device_id_private_key, device_id_certs)))?;
    Ok(proxy_connector)
}

mod private {
    pub trait Sealed {}
    impl<T> Sealed for T where T: super::KeyClient {}
}

/// An abstraction over aziot_key_client_async::Client and aziot_tpm_client_async::Client.
///
/// This trait is sealed, and cannot be implemented by consumers of this crate.
#[async_trait::async_trait]
pub trait KeyClient: private::Sealed {
    type KeyHandle;

    async fn insert_key(&self, key_handle: &[u8]) -> io::Result<Self::KeyHandle>;
    async fn sign_with_key(&self, key_handle: &Self::KeyHandle, data: &[u8])
        -> io::Result<Vec<u8>>;
}

#[async_trait::async_trait]
impl KeyClient for aziot_key_client_async::Client {
    type KeyHandle = aziot_key_common::KeyHandle;

    async fn insert_key(&self, key: &[u8]) -> io::Result<Self::KeyHandle> {
        // HACK: the key server expects key handles to be strings, while the TPM
        // server does not. The lowest common denominator between the two is
        // `&[u8]`, so that's what the generic interface uses.
        //
        // as such, we expect this conversion to never fail.
        self.load_key(
            std::str::from_utf8(key)
                .expect("aziot_key_client_async::Client::load_key expects UTF-8 keys"),
        )
        .await
    }

    async fn sign_with_key(
        &self,
        key_handle: &aziot_key_common::KeyHandle,
        data: &[u8],
    ) -> io::Result<Vec<u8>> {
        self.sign(
            key_handle,
            aziot_key_common::SignMechanism::HmacSha256,
            data,
        )
        .await
    }
}

#[async_trait::async_trait]
impl KeyClient for aziot_tpm_client_async::Client {
    type KeyHandle = ();

    async fn insert_key(&self, key: &[u8]) -> io::Result<Self::KeyHandle> {
        self.import_auth_key(key).await
    }

    async fn sign_with_key(&self, _key_handle: &(), data: &[u8]) -> io::Result<Vec<u8>> {
        self.sign_with_auth_key(data).await
    }
}
