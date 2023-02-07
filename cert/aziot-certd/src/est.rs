// Copyright (c) Microsoft. All rights reserved.

use openssl::pkcs7::Pkcs7;
use openssl::pkey::{PKeyRef, Private};
use openssl::x509::X509;
use url::Url;

use aziot_certd_config::EstAuthBasic;
use http_common::MaybeProxyConnector;

pub(crate) struct EstConfig {
    pub renewal: cert_renewal::AutoRenewConfig,
    pub trusted_certs: Vec<X509>,
    pub proxy_uri: Option<hyper::Uri>,
}

impl EstConfig {
    /// Get the EST renewal policy and trusted certs, which are global for all EST issuance options.
    pub(crate) fn new(
        cert_issuance: &aziot_certd_config::CertIssuance,
        homedir_path: &std::path::Path,
        preloaded_certs: &std::collections::BTreeMap<String, aziot_certd_config::PreloadedCert>,
    ) -> Result<Self, crate::Error> {
        let (renewal, trusted_certs) = if let Some(est) = &cert_issuance.est {
            let mut trusted_certs = vec![];

            for cert in &est.trusted_certs {
                let pem = crate::get_cert_inner(homedir_path, preloaded_certs, cert)?.ok_or_else(
                    || {
                        crate::Error::Internal(crate::InternalError::ReadFile(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!(
                                "cert_issuance.est.trusted_certs contains unreadable cert {:?}",
                                cert
                            ),
                        )))
                    },
                )?;

                let x509 = X509::stack_from_pem(&pem).map_err(|err| {
                    crate::Error::Internal(crate::InternalError::ReadFile(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        err,
                    )))
                })?;

                trusted_certs.extend(x509);
            }

            (est.identity_auto_renew.clone(), trusted_certs)
        } else {
            (cert_renewal::AutoRenewConfig::default(), Vec::new())
        };

        let proxy_uri = http_common::get_proxy_uri(None).map_err(|err| {
            crate::Error::Internal(crate::InternalError::InvalidProxyUri(Box::new(err)))
        })?;

        Ok(EstConfig {
            renewal,
            trusted_certs,
            proxy_uri,
        })
    }
}

pub(crate) async fn create_cert(
    csr: Vec<u8>,
    url: &Url,
    basic_auth: Option<&EstAuthBasic>,
    client_cert: Option<(&[u8], &PKeyRef<Private>)>,
    trusted_certs: &[X509],
    proxy_uri: Option<hyper::Uri>,
) -> Result<Vec<u8>, crate::BoxedError> {
    let proxy_connector = MaybeProxyConnector::new(proxy_uri, client_cert, trusted_certs)?;

    let client: hyper::Client<_, hyper::Body> = hyper::Client::builder().build(proxy_connector);

    let (simple_enroll_uri, ca_certs_uri) = {
        let mut uri = url.to_string();
        if !uri.ends_with('/') {
            uri.push('/');
        }

        let mut simple_enroll_uri = uri.clone();
        simple_enroll_uri.push_str("simpleenroll");

        let mut ca_certs_uri = uri;
        ca_certs_uri.push_str("cacerts");

        (simple_enroll_uri, ca_certs_uri)
    };

    let simple_enroll_request = hyper::Request::post(&simple_enroll_uri);
    let ca_certs_request = hyper::Request::get(&ca_certs_uri);

    let (simple_enroll_request, ca_certs_request) =
        if let Some(EstAuthBasic { username, password }) = basic_auth {
            let authorization_header_value = format!("{}:{}", username, password);
            let engine = base64::engine::general_purpose::STANDARD;
            let authorization_header_value =
                base64::Engine::encode(&engine, authorization_header_value);
            let authorization_header_value = format!("Basic {}", authorization_header_value);

            let simple_enroll_request = simple_enroll_request
                .header(hyper::header::AUTHORIZATION, &authorization_header_value);
            let ca_certs_request =
                ca_certs_request.header(hyper::header::AUTHORIZATION, authorization_header_value);
            (simple_enroll_request, ca_certs_request)
        } else {
            (simple_enroll_request, ca_certs_request)
        };

    let simple_enroll_request = simple_enroll_request
        .header(hyper::header::CONTENT_TYPE, "application/pkcs10")
        .header("content-transfer-encoding", "base64")
        .body(csr.into());

    let ca_certs_request = ca_certs_request.body(Default::default());

    let (simple_enroll_response, ca_certs_response) = futures_util::future::try_join(
        get_pkcs7_response(&client, simple_enroll_request),
        get_pkcs7_response(&client, ca_certs_request),
    )
    .await?;

    let mut result = simple_enroll_response;
    result.extend_from_slice(&ca_certs_response);

    Ok(result)
}

async fn get_pkcs7_response(
    client: &hyper::Client<
        MaybeProxyConnector<hyper_openssl::HttpsConnector<hyper::client::HttpConnector>>,
    >,
    request: Result<hyper::Request<hyper::Body>, http::Error>,
) -> Result<Vec<u8>, crate::BoxedError> {
    let response = client.request(request?).await?;

    let (
        http::response::Parts {
            status, headers, ..
        },
        body,
    ) = response.into_parts();
    let body = hyper::body::to_bytes(body).await?;

    if status != hyper::StatusCode::OK {
        return Err(format!(
            "EST endpoint did not return successful response: {} {:?}",
            status, body,
        )
        .into());
    }

    let content_type = headers
        .get(hyper::header::CONTENT_TYPE)
        .ok_or("EST response does not contain content-type header")?
        .to_str()
        .map_err(|err| {
            format!(
                "EST response does not contain valid content-type header: {}",
                err
            )
        })?;
    if content_type != "application/pkcs7-mime"
        && !content_type.starts_with("application/pkcs7-mime;")
    {
        return Err(format!(
            "EST response has unexpected content-type header: {}",
            content_type
        )
        .into());
    }

    let pkcs7 = Pkcs7::from_pem(&body).or_else(|_| -> Result<_, crate::BoxedError> {
        let no_whitespace = body
            .into_iter()
            .filter(|c| !(*c as char).is_whitespace())
            .collect::<Vec<_>>();
        let engine = base64::engine::general_purpose::STANDARD;
        let bytes = base64::Engine::decode(&engine, &no_whitespace)?;
        Ok(Pkcs7::from_der(&bytes)?)
    })?;

    // Note: This borrows from pkcs7. Do not drop pkcs7 before this.
    let x509_stack = unsafe {
        let x509_stack =
            aziot_certd_pkcs7_to_x509(foreign_types_shared::ForeignType::as_ptr(&pkcs7));
        let x509_stack = x509_stack as *mut <X509 as openssl::stack::Stackable>::StackType;
        let x509_stack: &openssl::stack::StackRef<X509> =
            foreign_types_shared::ForeignTypeRef::from_ptr(x509_stack);
        x509_stack
    };

    let mut pem = vec![];

    for x509 in x509_stack {
        pem.extend_from_slice(&x509.to_pem()?);
    }

    Ok(pem)
}

extern "C" {
    fn aziot_certd_pkcs7_to_x509(
        pkcs7: *const openssl_sys::PKCS7,
    ) -> *const openssl_sys::stack_st_X509;
}
