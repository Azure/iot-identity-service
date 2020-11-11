// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::let_and_return, clippy::missing_errors_doc)]

use std::io;

pub const ENCODE_SET: &percent_encoding::AsciiSet = &http_common::PATH_SEGMENT_ENCODE_SET.add(b'=');

pub async fn get_sas_connector(
    audience: &str,
    key_handle: &str,
    key_client: &aziot_key_client_async::Client,
) -> io::Result<(
    hyper_openssl::HttpsConnector<hyper::client::HttpConnector>,
    String,
)> {
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
            .sign(
                &aziot_key_common::KeyHandle(key_handle.to_string()),
                aziot_key_common::SignMechanism::HmacSha256,
                sig_data.as_bytes(),
            )
            .await?;

        let signature = base64::encode(&signature);

        let token = url::form_urlencoded::Serializer::new(format!("sr={}", resource_uri))
            .append_pair("sig", &signature)
            .append_pair("se", &expiry)
            .finish();
        token
    };

    let token = format!("SharedAccessSignature {}", token);

    let tls_connector = hyper_openssl::HttpsConnector::new()?;
    Ok((tls_connector, token))
}

pub async fn get_x509_connector(
    identity_cert: &str,
    identity_pk_handle: &str,
    key_engine: &mut openssl2::FunctionalEngineRef,
    cert_client: &aziot_cert_client_async::Client,
) -> io::Result<hyper_openssl::HttpsConnector<hyper::client::HttpConnector>> {
    let connector = {
        let mut tls_connector =
            openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())?;

        let device_id_private_key = {
            let device_id_key_handle = std::ffi::CString::new(identity_pk_handle)?;
            let device_id_private_key = key_engine
                .load_private_key(&device_id_key_handle)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            device_id_private_key
        };
        tls_connector.set_private_key(&device_id_private_key)?;

        let mut device_id_certs = {
            let device_id_certs = cert_client.get_cert(&identity_cert).await?;
            let device_id_certs =
                openssl::x509::X509::stack_from_pem(&device_id_certs)?.into_iter();
            device_id_certs
        };
        let client_cert = device_id_certs.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "device identity cert not found")
        })?;
        tls_connector.set_certificate(&client_cert)?;
        for cert in device_id_certs {
            tls_connector.add_extra_chain_cert(cert)?;
        }

        let mut http_connector = hyper::client::HttpConnector::new();
        http_connector.enforce_http(false);
        let tls_connector =
            hyper_openssl::HttpsConnector::with_connector(http_connector, tls_connector)?;
        tls_connector
    };
    Ok(connector)
}
