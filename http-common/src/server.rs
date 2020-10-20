// Copyright (c) Microsoft. All rights reserved.

use crate::DynRangeBounds;

#[macro_export]
macro_rules! make_server {
	(
		server: $server_ty:ty,
		api_version: $api_version_ty:ty,
		routes: [
			$($route:path ,)*
		],
	) => {
		impl hyper::service::Service<hyper::Request<hyper::Body>> for $server_ty {
			type Response = hyper::Response<hyper::Body>;
			type Error = std::convert::Infallible;
			type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

			fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
				std::task::Poll::Ready(Ok(()))
			}

			fn call(&mut self, req: hyper::Request<hyper::Body>) -> Self::Future {
				fn call_inner(
					this: &mut $server_ty,
					req: hyper::Request<hyper::Body>,
				) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<hyper::Response<hyper::Body>, std::convert::Infallible>> + Send>> {
					let (http::request::Parts { method, uri, headers, .. }, body) = req.into_parts();

					let path = uri.path();

					let (api_version, query_params) = {
						let mut api_version = None;
						let mut query_params = vec![];

						if let Some(query) = uri.query() {
							let mut params = url::form_urlencoded::parse(query.as_bytes());
							while let Some((name, value)) = params.next() {
								if name == "api-version" {
									api_version = Some(value);
								}
								else {
									query_params.push((name, value));
								}
							}
						}

						let api_version = match api_version {
							Some(api_version) => api_version,
							None => return Box::pin(futures_util::future::ok((http_common::server::Error {
								status_code: http::StatusCode::BAD_REQUEST,
								message: "api-version not specified".into(),
							}).to_http_response())),
						};
						let api_version: $api_version_ty = match api_version.parse() {
							Ok(api_version) => api_version,
							Err(()) => return Box::pin(futures_util::future::ok((http_common::server::Error {
								status_code: http::StatusCode::BAD_REQUEST,
								message: format!("invalid api-version {:?}", api_version).into(),
							}).to_http_response())),
						};
						(api_version, query_params)
					};

					$(
						let route_api_version_matches = <$route as http_common::server::Route>::api_version().contains(&api_version);
						if route_api_version_matches {
						let route: Option<$route> = http_common::server::Route::from_uri(&*this, path, &query_params);
							if let Some(route) = route {
								return Box::pin(async move {
									let response = match method {
										http::Method::DELETE => {
											let body = {
												let content_type = headers.get(hyper::header::CONTENT_TYPE).and_then(|value| value.to_str().ok());
												if content_type.as_deref() == Some("application/json") {
													let body = match hyper::body::to_bytes(body).await {
														Ok(body) => body,
														Err(err) => return Ok((http_common::server::Error {
															status_code: http::StatusCode::BAD_REQUEST,
															message: http_common::server::error_to_message(&err).into(),
														}).to_http_response()),
													};

													let body: <$route as http_common::server::Route>::DeleteBody = match serde_json::from_slice(&body) {
														Ok(body) => body,
														Err(err) => return Ok((http_common::server::Error {
															status_code: http::StatusCode::UNPROCESSABLE_ENTITY,
															message: http_common::server::error_to_message(&err).into(),
														}).to_http_response()),
													};

													Some(body)
												}
												else {
													None
												}
											};

											let (status_code, response) = match <$route as http_common::server::Route>::delete(route, body).await {
												Ok(result) => result,
												Err(err) => return Ok(err.to_http_response()),
											};
											http_common::server::json_response(status_code, response.as_ref())
										},

										http::Method::GET => {
											let (status_code, response) = match <$route as http_common::server::Route>::get(route).await {
												Ok(result) => result,
												Err(err) => return Ok(err.to_http_response()),
											};
											http_common::server::json_response(status_code, Some(&response))
										},

										http::Method::POST => {
											let body = {
												let content_type = headers.get(hyper::header::CONTENT_TYPE).and_then(|value| value.to_str().ok());
												if content_type.as_deref() == Some("application/json") {
													let body = match hyper::body::to_bytes(body).await {
														Ok(body) => body,
														Err(err) => return Ok((http_common::server::Error {
															status_code: http::StatusCode::BAD_REQUEST,
															message: http_common::server::error_to_message(&err).into(),
														}).to_http_response()),
													};

													let body: <$route as http_common::server::Route>::PostBody = match serde_json::from_slice(&body) {
														Ok(body) => body,
														Err(err) => return Ok((http_common::server::Error {
															status_code: http::StatusCode::UNPROCESSABLE_ENTITY,
															message: http_common::server::error_to_message(&err).into(),
														}).to_http_response()),
													};

													Some(body)
												}
												else {
													None
												}
											};

											let (status_code, response) = match <$route as http_common::server::Route>::post(route, body).await {
												Ok(result) => result,
												Err(err) => return Ok(err.to_http_response()),
											};
											http_common::server::json_response(status_code, response.as_ref())
										},

										http::Method::PUT => {
											let content_type = headers.get(hyper::header::CONTENT_TYPE).and_then(|value| value.to_str().ok());
											if content_type.as_deref() != Some("application/json") {
												return Ok((http_common::server::Error {
													status_code: http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
													message: "request body must be application/json".into(),
												}).to_http_response());
											}

											let body = match hyper::body::to_bytes(body).await {
												Ok(body) => body,
												Err(err) => return Ok((http_common::server::Error {
													status_code: http::StatusCode::BAD_REQUEST,
													message: http_common::server::error_to_message(&err).into(),
												}).to_http_response()),
											};

											let body: <$route as http_common::server::Route>::PutBody = match serde_json::from_slice(&body) {
												Ok(body) => body,
												Err(err) => return Ok((http_common::server::Error {
													status_code: http::StatusCode::UNPROCESSABLE_ENTITY,
													message: http_common::server::error_to_message(&err).into(),
												}).to_http_response()),
											};

											let (status_code, response) = match <$route as http_common::server::Route>::put(route, body).await {
												Ok(result) => result,
												Err(err) => return Ok(err.to_http_response()),
											};
											http_common::server::json_response(status_code, Some(&response))
										},

										_ => return Ok((http_common::server::Error {
											status_code: http::StatusCode::BAD_REQUEST,
											message: "method not allowed".into(),
										}).to_http_response()),
									};
									Ok(response)
								})
							}
						}
					)*

					let res = (http_common::server::Error {
						status_code: http::StatusCode::NOT_FOUND,
						message: "not found".into(),
					}).to_http_response();
					Box::pin(futures_util::future::ok(res))
				}

				// TODO: When we get distributed tracing, associate these two logs with the tracing ID.
				eprintln!("<-- {:?} {:?} {:?}", req.method(), req.uri(), req.headers());
				let res = call_inner(self, req);
				Box::pin(async move {
					let res = res.await;
					match &res {
						Ok(res) => eprintln!("--> {:?} {:?}", res.status(), res.headers()),
						Err(err) => eprintln!("-!> {:?}", err),
					}
					res
				})
			}
		}
	};
}

// DEVNOTE: Set *Body assoc type to `serde::de::IgnoredAny` if the corresponding method isn't overridden.
#[async_trait::async_trait]
pub trait Route: Sized {
    type ApiVersion: std::cmp::PartialOrd;
    fn api_version() -> &'static dyn DynRangeBounds<Self::ApiVersion>;

    type Server;
    fn from_uri(
        server: &Self::Server,
        path: &str,
        query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    ) -> Option<Self>;

    type DeleteBody: serde::de::DeserializeOwned + Send;
    type DeleteResponse: serde::Serialize + Send + 'static;
    async fn delete(
        self,
        _body: Option<Self::DeleteBody>,
    ) -> RouteResponse<Option<Self::DeleteResponse>> {
        Err(Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "method not allowed".into(),
        })
    }

    type GetResponse: serde::Serialize + Send + 'static;
    async fn get(self) -> RouteResponse<Self::GetResponse> {
        Err(Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "method not allowed".into(),
        })
    }

    type PostBody: serde::de::DeserializeOwned + Send;
    type PostResponse: serde::Serialize + Send + 'static;
    async fn post(
        self,
        _body: Option<Self::PostBody>,
    ) -> RouteResponse<Option<Self::PostResponse>> {
        Err(Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "method not allowed".into(),
        })
    }

    type PutBody: serde::de::DeserializeOwned + Send;
    type PutResponse: serde::Serialize + Send + 'static;
    async fn put(self, _body: Self::PutBody) -> RouteResponse<Self::PutResponse> {
        Err(Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "method not allowed".into(),
        })
    }
}

pub type RouteResponse<T> = Result<(http::StatusCode, T), Error>;

pub fn error_to_message(err: &impl std::error::Error) -> String {
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

#[derive(Debug)]
pub struct Error {
    pub status_code: http::StatusCode,
    pub message: std::borrow::Cow<'static, str>,
}

#[cfg(feature = "tokio02")]
impl Error {
    pub fn to_http_response(&self) -> hyper::Response<hyper::Body> {
        let body = crate::ErrorBody {
            message: std::borrow::Cow::Borrowed(std::borrow::Borrow::borrow(&self.message)),
        };
        let res = json_response(self.status_code, Some(&body));
        res
    }
}

#[cfg(feature = "tokio02")]
pub fn json_response(
    status_code: hyper::StatusCode,
    body: Option<&impl serde::Serialize>,
) -> hyper::Response<hyper::Body> {
    let res = hyper::Response::builder().status(status_code);
    // `res` is consumed by both branches, so this cannot be replaced with `Option::map_or_else`
    //
    // Ref: https://github.com/rust-lang/rust-clippy/issues/5822
    #[allow(clippy::option_if_let_else)]
    let res = if let Some(body) = body {
        let body = serde_json::to_string(body).expect("cannot fail to serialize response to JSON");
        let body = hyper::Body::from(body);
        res.header(hyper::header::CONTENT_TYPE, "application/json")
            .body(body)
    } else {
        res.body(Default::default())
    };
    let res = res.expect("cannot fail to build hyper response");
    res
}

/// This server is never actually used, but is useful to ensure that the macro
/// works as expected.
mod test_server {
    use crate as http_common;

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    enum ApiVersion {
        FAKE,
    }

    impl std::fmt::Display for ApiVersion {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(match self {
                ApiVersion::FAKE => "fake",
            })
        }
    }

    impl std::str::FromStr for ApiVersion {
        type Err = ();

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "fake" => Ok(ApiVersion::FAKE),
                _ => Err(()),
            }
        }
    }

    http_common::make_server! {
        server: Server,
        api_version: ApiVersion,
        routes: [
            test_route::Route,
        ],
    }

    struct Server;

    mod test_route {
        use crate as http_common;

        use super::ApiVersion;

        pub(super) struct Route;

        #[async_trait::async_trait]
        impl http_common::server::Route for Route {
            type ApiVersion = ApiVersion;
            fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
                &(..)
            }

            type Server = super::Server;
            fn from_uri(
                _server: &Self::Server,
                _path: &str,
                _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
            ) -> Option<Self> {
                Some(Route)
            }

            type DeleteBody = serde::de::IgnoredAny;
            type DeleteResponse = ();

            type GetResponse = ();

            type PostBody = serde::de::IgnoredAny;
            type PostResponse = ();

            type PutBody = serde::de::IgnoredAny;
            type PutResponse = ();
        }
    }
}
