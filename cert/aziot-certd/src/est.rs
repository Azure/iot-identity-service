// Copyright (c) Microsoft. All rights reserved.

pub(crate) async fn create_cert(
    csr: Vec<u8>,
    url: &url::Url,
    basic_auth: Option<(&str, &str)>,
    client_cert: Option<(&[u8], &openssl::pkey::PKeyRef<openssl::pkey::Private>)>,
    trusted_certs: Vec<openssl::x509::X509>,
) -> Result<Vec<u8>, crate::Error> {
    let mut tls_connector = openssl::ssl::SslConnector::builder(
        openssl::ssl::SslMethod::tls_client(),
    )
    .map_err(|err| crate::Error::Internal(crate::InternalError::CreateCert(Box::new(err))))?;

    {
        let cert_store = tls_connector.cert_store_mut();
        for trusted_cert in trusted_certs {
            cert_store.add_cert(trusted_cert).map_err(|err| {
                crate::Error::Internal(crate::InternalError::CreateCert(Box::new(err)))
            })?;
        }
    }

    if let Some((certs, private_key)) = client_cert {
        tls_connector.set_private_key(private_key).map_err(|err| {
            crate::Error::Internal(crate::InternalError::CreateCert(Box::new(err)))
        })?;

        let certs = openssl::x509::X509::stack_from_pem(certs).map_err(|err| {
            crate::Error::Internal(crate::InternalError::CreateCert(Box::new(err)))
        })?;
        let mut certs = certs.into_iter();
        let client_cert = certs.next().ok_or_else(|| {
            crate::Error::Internal(crate::InternalError::CreateCert("no client cert".into()))
        })?;
        tls_connector.set_certificate(&client_cert).map_err(|err| {
            crate::Error::Internal(crate::InternalError::CreateCert(Box::new(err)))
        })?;
        for chain_cert in certs {
            tls_connector
                .add_extra_chain_cert(chain_cert)
                .map_err(|err| {
                    crate::Error::Internal(crate::InternalError::CreateCert(Box::new(err)))
                })?;
        }
    }

    let mut http_connector = hyper::client::HttpConnector::new();
    http_connector.enforce_http(false);
    let tls_connector =
        hyper_openssl::HttpsConnector::with_connector(http_connector, tls_connector).map_err(
            |err| crate::Error::Internal(crate::InternalError::CreateCert(Box::new(err))),
        )?;

    let client: hyper::Client<_, hyper::Body> = hyper::Client::builder().build(tls_connector);

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

    let (simple_enroll_request, ca_certs_request) = if let Some((username, password)) = basic_auth {
        let authorization_header_value = format!("{}:{}", username, password);
        let authorization_header_value = base64::encode(authorization_header_value);
        let authorization_header_value = format!("Basic {}", authorization_header_value);

        let simple_enroll_request =
            simple_enroll_request.header(hyper::header::AUTHORIZATION, &authorization_header_value);
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

    let (simple_enroll_response, ca_certs_response) = futures_util::future::join(
        get_pkcs7_response(&client, simple_enroll_request),
        get_pkcs7_response(&client, ca_certs_request),
    )
    .await;
    let simple_enroll_response = simple_enroll_response
        .map_err(|err| crate::Error::Internal(crate::InternalError::CreateCert(Box::new(err))))?;
    let ca_certs_response = ca_certs_response
        .map_err(|err| crate::Error::Internal(crate::InternalError::CreateCert(Box::new(err))))?;

    let mut result = simple_enroll_response;
    result.extend_from_slice(&ca_certs_response);

    Ok(result)
}

async fn get_pkcs7_response(
    client: &hyper::Client<hyper_openssl::HttpsConnector<hyper::client::HttpConnector>>,
    request: Result<hyper::Request<hyper::Body>, http::Error>,
) -> Result<Vec<u8>, crate::Error> {
    let request = request
        .map_err(|err| crate::Error::Internal(crate::InternalError::CreateCert(Box::new(err))))?;

    let response = client
        .request(request)
        .await
        .map_err(|err| crate::Error::Internal(crate::InternalError::CreateCert(Box::new(err))))?;

    let (
        http::response::Parts {
            status, headers, ..
        },
        body,
    ) = response.into_parts();
    let body = hyper::body::to_bytes(body)
        .await
        .map_err(|err| crate::Error::Internal(crate::InternalError::CreateCert(Box::new(err))))?;

    if status != hyper::StatusCode::OK {
        return Err(crate::Error::Internal(crate::InternalError::CreateCert(
            format!(
                "EST endpoint did not return successful response: {} {:?}",
                status, body,
            )
            .into(),
        )));
    }

    let content_type = headers
        .get(hyper::header::CONTENT_TYPE)
        .ok_or_else(|| {
            crate::Error::Internal(crate::InternalError::CreateCert(
                "EST response does not contain content-type header".into(),
            ))
        })?
        .to_str()
        .map_err(|err| {
            crate::Error::Internal(crate::InternalError::CreateCert(
                format!(
                    "EST response does not contain valid content-type header: {}",
                    err
                )
                .into(),
            ))
        })?;
    if content_type != "application/pkcs7-mime"
        && !content_type.starts_with("application/pkcs7-mime;")
    {
        return Err(crate::Error::Internal(crate::InternalError::CreateCert(
            format!(
                "EST response has unexpected content-type header: {}",
                content_type
            )
            .into(),
        )));
    }

    // openssl::pkcs7::Pkcs7::from_pem requires the blob in PEM format, ie it must be wrapped in BEGIN/END PKCS7
    // but the EST server response does not contain this wrapper. Add it.
    let mut pkcs7 = b"-----BEGIN PKCS7-----\n"[..].to_owned();
    pkcs7.extend_from_slice(&body);
    pkcs7.extend_from_slice(b"-----END PKCS7-----\n");

    let pkcs7 = openssl::pkcs7::Pkcs7::from_pem(&pkcs7)
        .map_err(|err| crate::Error::Internal(crate::InternalError::CreateCert(Box::new(err))))?;
    // Note: This borrows from pkcs7. Do not drop pkcs7 before this.
    let x509_stack = unsafe {
        let x509_stack =
            aziot_certd_pkcs7_to_x509(foreign_types_shared::ForeignType::as_ptr(&pkcs7));
        let x509_stack =
            x509_stack as *mut <openssl::x509::X509 as openssl::stack::Stackable>::StackType;
        let x509_stack: &openssl::stack::StackRef<openssl::x509::X509> =
            foreign_types_shared::ForeignTypeRef::from_ptr(x509_stack);
        x509_stack
    };

    let mut result = vec![];
    for x509 in x509_stack {
        let x509 = x509.to_pem().map_err(|err| {
            crate::Error::Internal(crate::InternalError::CreateCert(Box::new(err)))
        })?;
        result.extend_from_slice(&x509);
        if !result.ends_with(b"\n") {
            result.extend_from_slice(b"\n");
        }
    }

    Ok(result)
}

extern "C" {
    fn aziot_certd_pkcs7_to_x509(
        pkcs7: *const openssl_sys::PKCS7,
    ) -> *const openssl_sys::stack_st_X509;
}
