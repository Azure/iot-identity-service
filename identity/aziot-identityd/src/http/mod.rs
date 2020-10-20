// Copyright (c) Microsoft. All rights reserved.

mod create_or_list_module_identity;
mod get_caller_identity;
mod get_device_identity;
mod get_trust_bundle;
mod get_update_or_delete_module_identity;
mod reprovision_device;

pub(crate) struct Server {
    pub(crate) inner: std::sync::Arc<futures_util::lock::Mutex<aziot_identityd::Server>>,
}

http_common::make_server! {
    server: Server,
    api_version: aziot_identity_common_http::ApiVersion,
    routes: [
        create_or_list_module_identity::Route,
        get_caller_identity::Route,
        get_device_identity::Route,
        get_trust_bundle::Route,
        get_update_or_delete_module_identity::Route,
        reprovision_device::Route,
    ],
}

fn to_http_error(err: &aziot_identityd::Error) -> http_common::server::Error {
    let error_message = http_common::server::error_to_message(err);

    // TODO: When we get distributed tracing, associate these logs with the tracing ID.
    for line in error_message.split('\n') {
        eprintln!("!!! {}", line);
    }

    match err {
        // Do not use error_message because we don't want to leak internal errors to the client.
        // Just return the top-level error, ie "internal error"
        aziot_identityd::Error::Internal(_) => http_common::server::Error {
            status_code: hyper::StatusCode::INTERNAL_SERVER_ERROR,
            message: err.to_string().into(),
        },

        aziot_identityd::error::Error::InvalidParameter(_, _)
        | aziot_identityd::error::Error::DeviceNotFound
        | aziot_identityd::error::Error::ModuleNotFound => http_common::server::Error {
            status_code: hyper::StatusCode::BAD_REQUEST,
            message: error_message.into(),
        },

        aziot_identityd::error::Error::DPSClient(_)
        | aziot_identityd::error::Error::HubClient(_) => http_common::server::Error {
            status_code: hyper::StatusCode::NOT_FOUND,
            message: error_message.into(),
        },

        aziot_identityd::error::Error::Authentication
        | aziot_identityd::error::Error::Authorization => http_common::server::Error {
            status_code: hyper::StatusCode::UNAUTHORIZED,
            message: error_message.into(),
        },
    }
}
