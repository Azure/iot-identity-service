// Copyright (c) Microsoft. All rights reserved.

mod cert;
mod identity;
mod key;

pub use cert::CertClient;
pub use identity::IdentityClient;
pub use key::KeyClient;
pub use key::KeyEngine;

/// Generic client error. Current tests don't act on the error other
/// than passing it up the call stack, so it's fine to return any error.
fn client_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, "test error")
}
