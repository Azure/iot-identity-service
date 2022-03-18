// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug)]
pub enum Error {
    Fatal(String),
    Retryable(String),
}

impl Error {
    pub fn fatal_error(message: impl std::fmt::Display) -> Self {
        Error::Fatal(message.to_string())
    }

    pub fn retryable_error(message: impl std::fmt::Display) -> Self {
        Error::Retryable(message.to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Error::Fatal(message) | Error::Retryable(message) => message,
        };

        write!(f, "{}", message)
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
