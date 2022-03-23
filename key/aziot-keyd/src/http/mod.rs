// Copyright (c) Microsoft. All rights reserved.

mod create_delete_key;
mod create_delete_key_pair;
mod create_derived_key;
mod decrypt;
mod encrypt;
mod export_derived_key;
mod get_key_pair_public_parameter;
mod load;
mod move_key_pair;
mod sign;

#[derive(Clone)]
pub struct Service {
    pub(crate) api: std::sync::Arc<futures_util::lock::Mutex<crate::Api>>,
}

http_common::make_service! {
    service: Service,
    api_version: aziot_key_common_http::ApiVersion,
    routes: [
        create_delete_key::Route,
        create_delete_key_pair::Route,
        create_derived_key::Route,
        decrypt::Route,
        encrypt::Route,
        export_derived_key::Route,
        get_key_pair_public_parameter::Route,
        load::Route,
        move_key_pair::Route,
        sign::Route,
    ],
}

fn to_http_error(err: &crate::Error) -> http_common::server::Error {
    let error_message = http_common::server::error_to_message(err);

    // TODO: When we get distributed tracing, associate these logs with the tracing ID.
    for line in error_message.lines() {
        log::log!(
            match err {
                crate::Error::Internal(_) => log::Level::Error,
                _ => log::Level::Info,
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

        crate::Error::InvalidParameter(_) => http_common::server::Error {
            status_code: hyper::StatusCode::BAD_REQUEST,
            message: error_message.into(),
        },

        crate::Error::Unauthorized(_, _) => http_common::server::Error {
            status_code: hyper::StatusCode::UNAUTHORIZED,
            message: err.to_string().into(),
        },
    }
}
