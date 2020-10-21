// Copyright (c) Microsoft. All rights reserved.

mod create;
mod get_or_delete;
mod import;

pub(crate) struct Server {
    pub(crate) inner: std::sync::Arc<futures_util::lock::Mutex<aziot_certd::Server>>,
}

http_common::make_server! {
    server: Server,
    api_version: aziot_cert_common_http::ApiVersion,
    routes: [
        create::Route,
        get_or_delete::Route,
        import::Route,
    ],
}

fn to_http_error(err: &aziot_certd::Error) -> http_common::server::Error {
    let error_message = http_common::server::error_to_message(err);

    // TODO: When we get distributed tracing, associate these logs with the tracing ID.
    for line in error_message.split('\n') {
        eprintln!("!!! {}", line);
    }

    match err {
        // Do not use error_message because we don't want to leak internal errors to the client.
        // Just return the top-level error, ie "internal error"
        aziot_certd::Error::Internal(_) => http_common::server::Error {
            status_code: hyper::StatusCode::INTERNAL_SERVER_ERROR,
            message: err.to_string().into(),
        },

        aziot_certd::Error::InvalidParameter(_, _) => http_common::server::Error {
            status_code: hyper::StatusCode::BAD_REQUEST,
            message: error_message.into(),
        },
    }
}
