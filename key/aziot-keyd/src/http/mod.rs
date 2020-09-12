// Copyright (c) Microsoft. All rights reserved.

mod create_derived_key;
mod create_key_if_not_exists;
mod create_key_pair_if_not_exists;
mod decrypt;
mod encrypt;
mod export_derived_key;
mod get_key_pair_public_parameter;
mod load;
mod sign;

pub(crate) struct Server {
	pub(crate) inner: std::sync::Arc<futures_util::lock::Mutex<aziot_keyd::Server>>,
}

http_common::make_server! {
	server: Server,
	api_version: aziot_key_common_http::ApiVersion,
	routes: [
		create_derived_key::Route,
		create_key_if_not_exists::Route,
		create_key_pair_if_not_exists::Route,
		decrypt::Route,
		encrypt::Route,
		export_derived_key::Route,
		get_key_pair_public_parameter::Route,
		load::Route,
		sign::Route,
	],
}

fn to_http_error(err: &aziot_keyd::Error) -> http_common::server::Error {
	match err {
		aziot_keyd::Error::Internal(_) => http_common::server::Error {
			status_code: hyper::StatusCode::INTERNAL_SERVER_ERROR,
			message: err.to_string().into(), // Do not use http_common::server::error_to_message for Error::Internal because we don't want to leak internal errors
		},

		err @ aziot_keyd::Error::InvalidParameter(_) => http_common::server::Error {
			status_code: hyper::StatusCode::BAD_REQUEST,
			message: http_common::server::error_to_message(err).into(),
		},
	}
}
