// Copyright (c) Microsoft. All rights reserved.

use crate::DynRangeBounds;

#[macro_export]
macro_rules! make_service {
    (
        service: $service_ty:ty,
        api_version: $api_version_ty:ty,
        routes: [
            $($route:path ,)*
        ],
    ) => {
        http_common::make_service!{
            service: $service_ty,
            {}
            {}
            api_version: $api_version_ty,
            routes: [
                $($route ,)*
            ],
        }
    };
    (
        service: $service_ty:ty,
        { $($impl_generics:tt)* }
        { $($bounds:tt)* }
        api_version: $api_version_ty:ty,
        routes: [
            $($route:path ,)*
        ],
    ) => {
        impl $($impl_generics)* hyper::service::Service<hyper::Request<hyper::Body>> for $service_ty
        where
            $($bounds)*
        {
            type Response = hyper::Response<hyper::Body>;
            type Error = std::convert::Infallible;
            type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

            fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn call(&mut self, req: hyper::Request<hyper::Body>) -> Self::Future {
                fn call_inner $($impl_generics)* (
                    this: &mut $service_ty,
                    req: hyper::Request<hyper::Body>,
                ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<hyper::Response<hyper::Body>, std::convert::Infallible>> + Send>>
                where
                    $($bounds)*
                {
                    const HYPER_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
                    let (http::request::Parts { method, uri, headers, extensions, .. }, body) = req.into_parts();

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
                        let route: Option<$route> = http_common::server::Route::from_uri(&*this, path, &query_params, &extensions);
                            if let Some(route) = route {
                                return Box::pin(async move {
                                    let response = match method {
                                        http::Method::DELETE => {
                                            let body = match tokio::time::timeout(HYPER_REQUEST_TIMEOUT, hyper::body::to_bytes(body)).await {
                                                Ok(Ok(body)) => body,
                                                Ok(Err(err)) => return Ok((http_common::server::Error {
                                                    status_code: http::StatusCode::BAD_REQUEST,
                                                    message: http_common::server::error_to_message(&err).into(),
                                                }).to_http_response()),
                                                Err(timeout_err) => return Ok((http_common::server::Error {
                                                    status_code: http::StatusCode::REQUEST_TIMEOUT,
                                                    message: http_common::server::error_to_message(&timeout_err).into(),
                                                }).to_http_response()),
                                            };

                                            let body = if body.len() == 0 {
                                                None
                                            } else {
                                            let content_type = headers.get(hyper::header::CONTENT_TYPE).and_then(|value| value.to_str().ok());
                                            if content_type.as_deref().map_or(true, |content_type| content_type == "application/json" || content_type.starts_with("application/json;")) {
                                                let body: <$route as http_common::server::Route>::DeleteBody = match serde_json::from_slice(&body) {
                                                    Ok(body) => body,
                                                    Err(err) => return Ok((http_common::server::Error {
                                                        status_code: http::StatusCode::UNPROCESSABLE_ENTITY,
                                                        message: http_common::server::error_to_message(&err).into(),
                                                    }).to_http_response()),
                                                };
                                                Some(body)
                                            } else {
                                                None
                                            }
                                            };

                                            match <$route as http_common::server::Route>::delete(route, body).await {
                                                Ok(result) => result,
                                                Err(err) => return Ok(err.to_http_response()),
                                            }
                                        },

                                        http::Method::GET => {
                                            match <$route as http_common::server::Route>::get(route).await {
                                                Ok(result) => result,
                                                Err(err) => return Ok(err.to_http_response()),
                                            }
                                        },

                                        http::Method::POST => {
                                            let body = match tokio::time::timeout(HYPER_REQUEST_TIMEOUT, hyper::body::to_bytes(body)).await {
                                                Ok(Ok(body)) => body,
                                                Ok(Err(err)) => return Ok((http_common::server::Error {
                                                    status_code: http::StatusCode::BAD_REQUEST,
                                                    message: http_common::server::error_to_message(&err).into(),
                                                }).to_http_response()),
                                                Err(timeout_err) => return Ok((http_common::server::Error {
                                                    status_code: http::StatusCode::REQUEST_TIMEOUT,
                                                    message: http_common::server::error_to_message(&timeout_err).into(),
                                                }).to_http_response()),
                                            };

                                            let body = if body.len() == 0 {
                                                None
                                            } else {
                                                let content_type = headers.get(hyper::header::CONTENT_TYPE).and_then(|value| value.to_str().ok());
                                                if content_type.as_deref().map_or(true, |content_type| content_type == "application/json" || content_type.starts_with("application/json;")) {
                                                    let body: <$route as http_common::server::Route>::PostBody = match serde_json::from_slice(&body) {
                                                        Ok(body) => body,
                                                        Err(err) => return Ok((http_common::server::Error {
                                                            status_code: http::StatusCode::UNPROCESSABLE_ENTITY,
                                                            message: http_common::server::error_to_message(&err).into(),
                                                        }).to_http_response()),
                                                    };

                                                    Some(body)
                                                } else {
                                                    None
                                                }
                                            };

                                            match <$route as http_common::server::Route>::post(route, body).await {
                                                Ok(result) => result,
                                                Err(err) => return Ok(err.to_http_response()),
                                            }
                                        },

                                        http::Method::PUT => {
                                            let content_type = headers.get(hyper::header::CONTENT_TYPE).and_then(|value| value.to_str().ok());
                                            let body = if content_type.as_deref().map_or(true, |content_type| content_type == "application/json" || content_type.starts_with("application/json;")) {
                                                let body = match tokio::time::timeout(HYPER_REQUEST_TIMEOUT, hyper::body::to_bytes(body)).await {
                                                    Ok(Ok(body)) => body,
                                                    Ok(Err(err)) => return Ok((http_common::server::Error {
                                                        status_code: http::StatusCode::BAD_REQUEST,
                                                        message: http_common::server::error_to_message(&err).into(),
                                                    }).to_http_response()),
                                                    Err(timeout_err) => return Ok((http_common::server::Error {
                                                        status_code: http::StatusCode::REQUEST_TIMEOUT,
                                                        message: http_common::server::error_to_message(&timeout_err).into(),
                                                    }).to_http_response()),
                                                };

                                                let body: <$route as http_common::server::Route>::PutBody = match serde_json::from_slice(&body) {
                                                    Ok(body) => body,
                                                    Err(err) => return Ok((http_common::server::Error {
                                                        status_code: http::StatusCode::UNPROCESSABLE_ENTITY,
                                                        message: http_common::server::error_to_message(&err).into(),
                                                    }).to_http_response()),
                                                };

                                                body
                                            }
                                            else {
                                                return Ok((http_common::server::Error {
                                                    status_code: http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                                                    message: "request body must be application/json".into(),
                                                }).to_http_response());
                                            };


                                            match <$route as http_common::server::Route>::put(route, body).await {
                                                Ok(result) => result,
                                                Err(err) => return Ok(err.to_http_response()),
                                            }
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
                log::info!("<-- {:?} {:?} {:?}", req.method(), req.uri(), req.headers());
                let res = call_inner(self, req);
                Box::pin(async move {
                    let res = res.await;
                    match &res {
                        Ok(res) => log::info!("--> {:?} {:?}", res.status(), res.headers()),
                        Err(err) => log::error!("-!> {:?}", err),
                    }
                    res
                })
            }
        }
    };
}

// DEVNOTE: Set *Body assoc type to `serde::de::IgnoredAny` if the corresponding method isn't overridden.
#[async_trait::async_trait]
#[allow(clippy::unused_async)]
pub trait Route: Sized {
    type ApiVersion: std::cmp::PartialOrd;
    fn api_version() -> &'static dyn DynRangeBounds<Self::ApiVersion>;

    type Service;
    fn from_uri(
        service: &Self::Service,
        path: &str,
        query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
        _extensions: &http::Extensions,
    ) -> Option<Self>;

    type DeleteBody: serde::de::DeserializeOwned + Send;
    async fn delete(self, _body: Option<Self::DeleteBody>) -> RouteResponse {
        Err(Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "method not allowed".into(),
        })
    }

    async fn get(self) -> RouteResponse {
        Err(Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "method not allowed".into(),
        })
    }

    type PostBody: serde::de::DeserializeOwned + Send;
    async fn post(self, _body: Option<Self::PostBody>) -> RouteResponse {
        Err(Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "method not allowed".into(),
        })
    }

    type PutBody: serde::de::DeserializeOwned + Send;
    async fn put(self, _body: Self::PutBody) -> RouteResponse {
        Err(Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "method not allowed".into(),
        })
    }
}

pub type RouteResponse = Result<hyper::Response<hyper::Body>, Error>;

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

impl Error {
    pub fn to_http_response(&self) -> hyper::Response<hyper::Body> {
        let body = crate::ErrorBody {
            message: std::borrow::Cow::Borrowed(std::borrow::Borrow::borrow(&self.message)),
        };
        let res = response::json(self.status_code, &body);
        res
    }
}

pub mod response {
    pub fn no_content() -> hyper::Response<hyper::Body> {
        let res = hyper::Response::builder()
            .status(hyper::StatusCode::NO_CONTENT)
            .body(Default::default())
            .expect("cannot fail to build hyper response");

        res
    }

    pub fn chunked<S, O, E>(
        status_code: hyper::StatusCode,
        body: S,
        content_type: &'static str,
    ) -> hyper::Response<hyper::Body>
    where
        S: futures_util::stream::Stream<Item = Result<O, E>> + Send + 'static,
        O: Into<hyper::body::Bytes> + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    {
        let body = hyper::Body::wrap_stream(body);

        let res = hyper::Response::builder()
            .status(status_code)
            .header(hyper::header::CONTENT_TYPE, content_type)
            .body(body);

        let res = res.expect("cannot fail to build hyper response");
        res
    }

    pub fn json(
        status_code: hyper::StatusCode,
        body: &impl serde::Serialize,
    ) -> hyper::Response<hyper::Body> {
        let body = serde_json::to_string(body).expect("cannot fail to serialize response to JSON");
        let body = hyper::Body::from(body);

        let res = hyper::Response::builder()
            .status(status_code)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(body);

        let res = res.expect("cannot fail to build hyper response");
        res
    }

    pub fn zip<S, O, E>(
        status_code: hyper::StatusCode,
        size: usize,
        body: S,
    ) -> hyper::Response<hyper::Body>
    where
        S: futures_util::stream::Stream<Item = Result<O, E>> + Send + 'static,
        O: Into<hyper::body::Bytes> + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    {
        let body = hyper::Body::wrap_stream(body);
        let res = hyper::Response::builder().status(status_code);

        let res = res
            .header(hyper::header::CONTENT_ENCODING, "deflate")
            .header(hyper::header::CONTENT_LENGTH, size.to_string())
            .header(hyper::header::CONTENT_TYPE, "application/zip")
            .body(body);

        let res = res.expect("cannot fail to build hyper response");
        res
    }
}

/// This server is never actually used, but is useful to ensure that the macro
/// works as expected.
mod test_server {
    use crate as http_common;

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    enum ApiVersion {
        Fake,
    }

    impl std::fmt::Display for ApiVersion {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(match self {
                ApiVersion::Fake => "fake",
            })
        }
    }

    impl std::str::FromStr for ApiVersion {
        type Err = ();

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "fake" => Ok(ApiVersion::Fake),
                _ => Err(()),
            }
        }
    }

    http_common::make_service! {
        service: Service,
        api_version: ApiVersion,
        routes: [
            test_route::Route,
        ],
    }

    struct Service;

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

            type Service = super::Service;
            fn from_uri(
                _service: &Self::Service,
                _path: &str,
                _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
                _extensions: &http::Extensions,
            ) -> Option<Self> {
                Some(Route)
            }

            type DeleteBody = serde::de::IgnoredAny;
            type PostBody = serde::de::IgnoredAny;
            type PutBody = serde::de::IgnoredAny;
        }
    }
}
