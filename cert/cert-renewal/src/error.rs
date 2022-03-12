// Copyright (c) Microsoft. All rights reserved.

pub enum Error {
    Fatal(String),
    Retryable(String),
}

impl Error {
    pub fn fatal_error(message: impl std::fmt::Display) -> Self {
        Error::Fatal(format!("{}", message))
    }

    pub fn retryable_error(message: impl std::fmt::Display) -> Self {
        Error::Retryable(format!("{}", message))
    }
}

impl std::convert::From<Error> for std::io::Error {
    fn from(err: Error) -> std::io::Error {
        let message = match err {
            Error::Fatal(message) | Error::Retryable(message) => message,
        };

        std::io::Error::new(std::io::ErrorKind::Other, message)
    }
}
