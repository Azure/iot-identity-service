mod get_module_identities;
mod get_module_identity;
mod delete_module_identity;
mod get_trust_bundle;
mod decrypt;
mod encrypt;
mod create_module_identity;
mod get_device_identity;
mod get_caller_identity;
mod reprovision_device;

pub(crate) struct Server {
	pub(crate) inner: std::sync::Arc<aziot_identityd::Server>,
}

/// A route is an async function that receives the hyper request and the `aziot_identityd::Server` value.
///
/// It returns `Ok(res)` if it successfully matched the incoming request, and `Err(req)` if it didn't.
type Route =
	fn(
		hyper::Request<hyper::Body>,
		std::sync::Arc<aziot_identityd::Server>,
	) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<hyper::Response<hyper::Body>, hyper::Request<hyper::Body>>> + Send>>;

impl hyper::service::Service<hyper::Request<hyper::Body>> for Server {
	type Response = hyper::Response<hyper::Body>;
	type Error = std::convert::Infallible;
	type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
		std::task::Poll::Ready(Ok(()))
	}

	fn call(&mut self, mut req: hyper::Request<hyper::Body>) -> Self::Future {
		let inner = self.inner.clone();

		Box::pin(async move {
			const ROUTES: &[Route] = &[
				get_module_identities::handle,
				get_module_identity::handle,
				delete_module_identity::handle,
				get_trust_bundle::handle,
				decrypt::handle,
				encrypt::handle,
				create_module_identity::handle,
				get_device_identity::handle,
				get_caller_identity::handle,
				reprovision_device::handle,
			];

			log::debug!("Received request {:?}", req);

			let mut res = None;
			for route in ROUTES {
				req = match route(req, inner.clone()).await {
					Ok(res_) => { res = Some(res_); break; },
					Err(req) => req,
				};
			}
			let res = res.unwrap_or_else(|| err_response(
				hyper::StatusCode::NOT_FOUND,
				None,
				"not found".into(),
			));

			log::debug!("Sending response {:?}", res);

			Ok(res)
		})
	}
}

fn error_to_message(err: &impl std::error::Error) -> String {
	let mut message = String::new();

	message.push_str(&err.to_string());

	let mut source = err.source();
	while let Some(err) = source {
		message.push_str("\ncaused by: ");
		message.push_str(&err.to_string());
		source = err.source();
	}

	message
}

fn json_response(status_code: hyper::StatusCode, body: &impl serde::Serialize) -> hyper::Response<hyper::Body> {
	let body = serde_json::to_string(body).expect("cannot fail to serialize response to JSON");
	let body = hyper::Body::from(body);

	hyper::Response::builder()
		.status(status_code)
		.header(hyper::header::CONTENT_TYPE, "application/json")
		.body(body)
		.expect("cannot fail to serialize hyper response")
}

fn err_response(
	status_code: hyper::StatusCode,
	extra_header: Option<(hyper::header::HeaderName, &'static str)>,
	message: std::borrow::Cow<'static, str>,
) -> hyper::Response<hyper::Body> {
	let body = aziot_identity_common_http::Error {
		message,
	};

	let mut res = json_response(status_code, &body);

	if let Some((header_name, header_value)) = extra_header {
		res.headers_mut().append(header_name, hyper::header::HeaderValue::from_static(header_value));
	}

	res
}

trait ToHttpResponse {
	fn to_http_response(&self) -> hyper::Response<hyper::Body>;
}

impl ToHttpResponse for aziot_identityd::error::Error {
	fn to_http_response(&self) -> hyper::Response<hyper::Body> {
		match self {
			aziot_identityd::error::Error::Internal(_) => err_response(
				hyper::StatusCode::INTERNAL_SERVER_ERROR,
				None,
				self.to_string().into(), // Do not use error_to_message for Error::Internal because we don't want to leak internal errors
			),

			err @ aziot_identityd::error::Error::InvalidParameter(_, _) => err_response(
				hyper::StatusCode::BAD_REQUEST,
				None,
				error_to_message(err).into(),
			),
		}
	}
}
