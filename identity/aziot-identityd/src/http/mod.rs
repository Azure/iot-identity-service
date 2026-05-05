// Copyright (c) Microsoft. All rights reserved.

mod create_or_list_module_identity;
mod get_caller_identity;
mod get_device_identity;
mod get_provisioning_info;
mod get_trust_bundle;
mod get_update_or_delete_module_identity;
mod reprovision_device;

#[derive(Clone)]
pub struct Service {
    pub(crate) api: std::sync::Arc<tokio::sync::Mutex<crate::Api>>,
}

http_common::make_service! {
    service: Service,
    api_version: aziot_identity_common_http::ApiVersion,
    routes: [
        create_or_list_module_identity::Route,
        get_caller_identity::Route,
        get_device_identity::Route,
        get_provisioning_info::Route,
        get_trust_bundle::Route,
        get_update_or_delete_module_identity::Route,
        reprovision_device::Route,
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
            "!!! {line}",
        );
    }

    match err {
        // Do not use error_message because we don't want to leak internal errors to the client.
        // Just return the top-level error, ie "internal error"
        crate::Error::Internal(_) => http_common::server::Error {
            status_code: hyper::StatusCode::INTERNAL_SERVER_ERROR,
            message: err.to_string().into(),
        },

        crate::error::Error::InvalidParameter(_, _)
        | crate::error::Error::DeviceNotFound
        | crate::error::Error::ModuleNotFound => http_common::server::Error {
            status_code: hyper::StatusCode::BAD_REQUEST,
            message: error_message.into(),
        },

        crate::error::Error::DpsClient(_)
        | crate::error::Error::DpsNotSupportedInNestedMode
        | crate::error::Error::HubClient(_)
        | crate::error::Error::KeyClient(_) => http_common::server::Error {
            status_code: hyper::StatusCode::NOT_FOUND,
            message: error_message.into(),
        },

        crate::error::Error::Authentication | crate::error::Error::Authorization => {
            http_common::server::Error {
                status_code: hyper::StatusCode::UNAUTHORIZED,
                message: error_message.into(),
            }
        }
    }
}
