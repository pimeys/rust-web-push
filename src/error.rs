use base64::DecodeError;
use http::uri::InvalidUri;
use openssl::error::ErrorStack;
use ring::error;
use serde_json::error::Error as JsonError;
use std::string::FromUtf8Error;
use std::time::{Duration, SystemTime};
use std::{convert::From, error::Error, fmt, io::Error as IoError};

#[derive(PartialEq, Debug)]
pub enum WebPushError {
    /// An unknown error happened encrypting the message,
    Unspecified,
    /// Please provide valid credentials to send the notification
    Unauthorized,
    /// Request was badly formed
    BadRequest(Option<String>),
    /// Contains an optional `Duration`, until the user can retry the request
    ServerError(Option<Duration>),
    /// The feature is not implemented yet
    NotImplemented,
    /// The provided URI is invalid
    InvalidUri,
    /// The URL specified is no longer valid and should no longer be used
    EndpointNotValid,
    /// The URL specified is invalid and should not be used again
    EndpointNotFound,
    /// Maximum allowed payload size is 3800 characters
    PayloadTooLarge,
    /// Could not initialize a TLS connection
    TlsError,
    /// Error in SSL signing
    SslError,
    /// Error in reading a file
    IoError,
    /// Make sure the message was addressed to a registration token whose
    /// package name matches the value passed in the request (Google).
    InvalidPackageName,
    /// The TTL value provided was not valid or was not provided
    InvalidTtl,
    /// The request was missing required crypto keys
    MissingCryptoKeys,
    /// One or more of the crypto key elements are invalid.
    InvalidCryptoKeys,
    /// Corrupted response data
    InvalidResponse,
    Other(String),
}

impl Error for WebPushError {}

impl From<JsonError> for WebPushError {
    fn from(_: JsonError) -> WebPushError {
        WebPushError::InvalidResponse
    }
}

impl From<FromUtf8Error> for WebPushError {
    fn from(_: FromUtf8Error) -> WebPushError {
        WebPushError::InvalidResponse
    }
}

impl From<InvalidUri> for WebPushError {
    fn from(_: InvalidUri) -> WebPushError {
        WebPushError::InvalidUri
    }
}

impl From<error::Unspecified> for WebPushError {
    fn from(_: error::Unspecified) -> WebPushError {
        WebPushError::Unspecified
    }
}

impl From<hyper::Error> for WebPushError {
    fn from(_: hyper::Error) -> Self {
        Self::Unspecified
    }
}

impl From<native_tls::Error> for WebPushError {
    fn from(_: native_tls::Error) -> WebPushError {
        WebPushError::TlsError
    }
}

impl From<IoError> for WebPushError {
    fn from(_: IoError) -> WebPushError {
        WebPushError::IoError
    }
}

impl From<ErrorStack> for WebPushError {
    fn from(_: ErrorStack) -> WebPushError {
        WebPushError::SslError
    }
}

impl From<DecodeError> for WebPushError {
    fn from(_: DecodeError) -> WebPushError {
        WebPushError::InvalidCryptoKeys
    }
}

impl WebPushError {
    pub fn short_description(&self) -> &'static str {
        match *self {
            WebPushError::Unspecified => "unspecified",
            WebPushError::Unauthorized => "unauthorized",
            WebPushError::BadRequest(_) => "bad_request",
            WebPushError::ServerError(_) => "server_error",
            WebPushError::NotImplemented => "not_implemented",
            WebPushError::InvalidUri => "invalid_uri",
            WebPushError::EndpointNotValid => "endpoint_not_valid",
            WebPushError::EndpointNotFound => "endpoint_not_found",
            WebPushError::PayloadTooLarge => "payload_too_large",
            WebPushError::TlsError => "tls_error",
            WebPushError::InvalidPackageName => "invalid_package_name",
            WebPushError::InvalidTtl => "invalid_ttl",
            WebPushError::InvalidResponse => "invalid_response",
            WebPushError::MissingCryptoKeys => "missing_crypto_keys",
            WebPushError::InvalidCryptoKeys => "invalid_crypto_keys",
            WebPushError::SslError => "ssl_error",
            WebPushError::IoError => "io_error",
            WebPushError::Other(_) => "other",
        }
    }
}

impl fmt::Display for WebPushError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            WebPushError::Unspecified =>
                write!(f, "An unknown error happened encrypting the message"),
            WebPushError::Unauthorized =>
                write!(f, "Please provide valid credentials to send the notification"),
            WebPushError::BadRequest(_) =>
                write!(f, "Request was badly formed"),
            WebPushError::ServerError(_) =>
                write!(f, "Server was unable to process the request, please try again later"),
            WebPushError::PayloadTooLarge =>
                write!(f, "Maximum allowed payload size is 3070 characters"),
            WebPushError::InvalidUri =>
                write!(f, "The provided URI is invalid"),
            WebPushError::NotImplemented =>
                write!(f, "The feature is not implemented yet"),
            WebPushError::EndpointNotValid =>
                write!(f, "The URL specified is no longer valid and should no longer be used"),
            WebPushError::EndpointNotFound =>
                write!(f, "The URL specified is invalid and should not be used again"),
            WebPushError::TlsError =>
                write!(f, "Could not initialize a TLS connection"),
            WebPushError::SslError =>
                write!(f, "Error signing with SSL"),
            WebPushError::IoError =>
                write!(f, "Error opening a file"),
            WebPushError::InvalidPackageName =>
                write!(f, "Make sure the message was addressed to a registration token whose package name matches the value passed in the request."),
            WebPushError::InvalidTtl => write!(f, "The TTL value provided was not valid or was not provided"),
            WebPushError::InvalidResponse => write!(f, "The response data couldn't be parses"),
            WebPushError::MissingCryptoKeys  => write!(f, "The request is missing cryptographic keys"),
            WebPushError::InvalidCryptoKeys  => write!(f, "The request is having invalid cryptographic keys"),
            WebPushError::Other(_) => write!(f, "An unknown error when connecting the notification service"),
        }
    }
}

pub struct RetryAfter;
impl RetryAfter {
    pub fn from_str(header_value: &str) -> Option<Duration> {
        if let Ok(seconds) = header_value.parse::<u64>() {
            Some(Duration::from_secs(seconds))
        } else {
            chrono::DateTime::parse_from_rfc2822(header_value)
                .map(|date_time| {
                    let systime: SystemTime = date_time.into();

                    systime
                        .duration_since(SystemTime::now())
                        .unwrap_or_else(|_| Duration::new(0, 0))
                })
                .ok()
        }
    }
}
