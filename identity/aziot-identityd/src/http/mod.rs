// Copyright (c) Microsoft. All rights reserved.

mod get_or_delete_module_identity;
mod get_trust_bundle;
mod create_or_list_module_identity;
mod get_device_identity;
mod get_caller_identity;
mod reprovision_device;

pub(crate) struct Server {
	pub(crate) inner: std::sync::Arc<futures_util::lock::Mutex<aziot_identityd::Server>>,
}

http_common::make_server! {
	server: Server,
	api_version: aziot_identity_common_http::ApiVersion,
	routes: [
		get_or_delete_module_identity::Route,
		get_trust_bundle::Route,
		create_or_list_module_identity::Route,
		get_device_identity::Route,
		get_caller_identity::Route,
		reprovision_device::Route,
	],
}

fn to_http_error(err: &aziot_identityd::Error) -> http_common::server::Error {
	match err {
		aziot_identityd::error::Error::Internal(_) => http_common::server::Error {
			status_code: hyper::StatusCode::INTERNAL_SERVER_ERROR,
			message: err.to_string().into(), // Do not use error_to_message for Error::Internal because we don't want to leak internal errors
		},

		err @ aziot_identityd::error::Error::InvalidParameter(_, _) |
		err @ aziot_identityd::error::Error::DeviceNotFound |
		err @ aziot_identityd::error::Error::ModuleNotFound => http_common::server::Error {
			status_code: hyper::StatusCode::BAD_REQUEST,
			message: http_common::server::error_to_message(err).into(),
		},

		err @ aziot_identityd::error::Error::DPSClient(_) |
		err @ aziot_identityd::error::Error::HubClient(_) => http_common::server::Error {
			status_code: hyper::StatusCode::NOT_FOUND, 
			message: http_common::server::error_to_message(err).into()
		},

		err @ aziot_identityd::error::Error::Authentication |
		err @ aziot_identityd::error::Error::Authorization => http_common::server::Error {
			status_code: hyper::StatusCode::UNAUTHORIZED,
			message: http_common::server::error_to_message(err).into(),
		},
	}
}
