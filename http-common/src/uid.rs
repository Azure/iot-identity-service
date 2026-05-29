// Copyright (c) Microsoft. All rights reserved.

use std::error::Error as StdError;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::{Request, body::Incoming, service::Service};
use libc::{pid_t, uid_t};

#[derive(Clone)]
pub struct UidService<T> {
    pid: Option<pid_t>,
    uid: uid_t,
    inner: T,
}

impl<T> UidService<T> {
    pub fn new(pid: Option<pid_t>, uid: uid_t, inner: T) -> Self {
        UidService { pid, uid, inner }
    }
}

impl<T> Service<Request<Incoming>> for UidService<T>
where
    T: Service<
            Request<Incoming>,
            Response = hyper::Response<BoxBody<Bytes, Box<dyn StdError + Send + Sync>>>,
            Error = std::convert::Infallible,
        >,
    <T as Service<Request<Incoming>>>::Future: Send + 'static,
{
    type Response = T::Response;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        hyper::Response<BoxBody<Bytes, Box<dyn StdError + Send + Sync>>>,
                        std::convert::Infallible,
                    >,
                > + Send,
        >,
    >;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let mut req = req;
        let extensions = req.extensions_mut();
        extensions.insert(self.uid);
        extensions.insert(self.pid);
        Box::pin(self.inner.call(req))
    }
}
