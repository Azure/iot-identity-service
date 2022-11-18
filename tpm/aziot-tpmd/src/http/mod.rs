// Copyright (c) Microsoft. All rights reserved.

mod get_tpm_keys;
mod import_auth_key;
mod sign_with_auth_key;

#[derive(Clone)]
pub struct Service {
    pub(crate) api: std::sync::Arc<tokio::sync::Mutex<crate::Api>>,
}

http_common::make_service! {
    service: Service,
    api_version: aziot_tpm_common_http::ApiVersion,
    routes: [
        get_tpm_keys::Route,
        import_auth_key::Route,
        sign_with_auth_key::Route,
    ],
}

fn to_http_error(err: &crate::Error) -> http_common::server::Error {
    let error_message = http_common::server::error_to_message(err);

    // TODO: When we get distributed tracing, associate these logs with the tracing ID.
    for line in error_message.lines() {
        log::log!(
            match err {
                crate::Error::Internal(_) => log::Level::Error,
            },
            "!!! {}",
            line,
        );
    }

    match err {
        // Do not use error_message because we don't want to leak internal errors to the client.
        // Just return the top-level error, ie "internal error"
        crate::Error::Internal(_) => http_common::server::Error {
            status_code: hyper::StatusCode::INTERNAL_SERVER_ERROR,
            message: err.to_string().into(),
        },
    }
}
