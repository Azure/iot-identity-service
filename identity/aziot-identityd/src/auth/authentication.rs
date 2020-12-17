// Copyright (c) Microsoft. All rights reserved.

use aziot_identityd_config::{Credentials, Uid};

use crate::auth::AuthId;
use crate::error::Error;

/// A trait to authenticate IS clients with given user id.
pub trait Authenticator {
    /// Authentication error.
    type Error: std::error::Error + Send;

    /// Authenticates an IS client with given its credentials.
    fn authenticate(&self, credentials: Uid) -> Result<AuthId, Self::Error>;
}

impl<F> Authenticator for F
where
    F: Fn(Credentials) -> Result<AuthId, Error> + Send + Sync,
{
    type Error = Error;

    fn authenticate(&self, credentials: Credentials) -> Result<AuthId, Self::Error> {
        self(credentials)
    }
}

/// Default implementation that returns Unknown user for unmapped users.
/// This implementation will be used if custom authentication mechanism was not provided.
pub struct DefaultAuthenticator;

impl Authenticator for DefaultAuthenticator {
    type Error = Error;

    fn authenticate(&self, _: Credentials) -> Result<AuthId, Self::Error> {
        Ok(AuthId::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use aziot_identityd_config::Uid;

    use super::{Authenticator, DefaultAuthenticator};
    use crate::auth::AuthId;

    #[test]
    fn default_auth_always_return_unknown_client_identity() {
        let authenticator = DefaultAuthenticator;
        let credentials = Uid(1000);

        let auth_id = authenticator.authenticate(credentials);

        match auth_id {
            Ok(AuthId::Unknown) => (),
            _ => panic!("incorrect auth id selected"),
        }
    }

    #[test]
    fn authenticator_wrapper_around_function() {
        let authenticator = |_| Ok(AuthId::LocalRoot);
        let credentials = Uid(0);

        let auth_id = authenticator.authenticate(credentials);

        match auth_id {
            Ok(AuthId::LocalRoot) => (),
            _ => panic!("incorrect auth id selected"),
        }
    }
}
