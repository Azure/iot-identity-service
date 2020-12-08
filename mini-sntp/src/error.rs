// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug)]
pub enum Error {
    BadServerResponse(BadServerResponseReason),
    BindLocalSocket(std::io::Error),
    ReceiveServerResponse(std::io::Error),
    ResolveNtpPoolHostname(Option<std::io::Error>),
    SendClientRequest(std::io::Error),
    SetReadTimeoutOnSocket(std::io::Error),
    SetWriteTimeoutOnSocket(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadServerResponse(reason) => {
                write!(f, "could not parse NTP server response: {}", reason)
            }
            Error::BindLocalSocket(_) => write!(f, "could not bind local UDP socket"),
            Error::ReceiveServerResponse(err) => {
                write!(f, "could not receive NTP server response: {}", err)
            }
            Error::ResolveNtpPoolHostname(Some(err)) => {
                write!(f, "could not resolve NTP pool hostname: {}", err)
            }
            Error::ResolveNtpPoolHostname(None) => {
                write!(f, "could not resolve NTP pool hostname: no addresses found")
            }
            Error::SendClientRequest(err) => {
                write!(f, "could not send SNTP client request: {}", err)
            }
            Error::SetReadTimeoutOnSocket(_) => {
                write!(f, "could not set read timeout on local UDP socket")
            }
            Error::SetWriteTimeoutOnSocket(_) => {
                write!(f, "could not set write timeout on local UDP socket")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            Error::BadServerResponse(_) => None,
            Error::BindLocalSocket(err) => Some(err),
            Error::ReceiveServerResponse(err) => Some(err),
            Error::ResolveNtpPoolHostname(Some(err)) => Some(err),
            Error::ResolveNtpPoolHostname(None) => None,
            Error::SendClientRequest(err) => Some(err),
            Error::SetReadTimeoutOnSocket(err) => Some(err),
            Error::SetWriteTimeoutOnSocket(err) => Some(err),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum BadServerResponseReason {
    LeapIndicator(u8),
    OriginateTimestamp {
        expected: chrono::DateTime<chrono::Utc>,
        actual: chrono::DateTime<chrono::Utc>,
    },
    Mode(u8),
    VersionNumber(u8),
}

impl std::fmt::Display for BadServerResponseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BadServerResponseReason::LeapIndicator(leap_indicator) => {
                write!(f, "invalid value of leap indicator {}", leap_indicator)
            }
            BadServerResponseReason::OriginateTimestamp { expected, actual } => write!(
                f,
                "expected originate timestamp to be {} but it was {}",
                expected, actual
            ),
            BadServerResponseReason::Mode(mode) => {
                write!(f, "expected mode to be 4 but it was {}", mode)
            }
            BadServerResponseReason::VersionNumber(version_number) => write!(
                f,
                "expected version number to be 3 but it was {}",
                version_number
            ),
        }
    }
}
