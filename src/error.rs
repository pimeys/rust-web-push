use std::error::Error;
use std::convert::From;
use std::fmt;
use ring::error;
use tokio_timer::TimeoutError;
use client::WebPushResponse;
use native_tls;
use std::time::Duration;
use hyper::error::UriError;
use std::string::FromUtf8Error;
use serde_json::error::Error as JsonError;

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
    /// The request timed out
    TimeoutError,
    /// The URL specified is no longer valid and should no longer be used
    EndpointNotValid,
    /// The URL specified is invalid and should not be used again
    EndpointNotFound,
    /// Maximum allowed payload size is 3800 characters
    PayloadTooLarge,
    /// Could not initialize a TLS connection
    TlsError,
    /// Make sure the message was addressed to a registration token whose
    /// package name matches the value passed in the request (Google).
    InvalidPackageName,
    /// The TTL value provided was not valid or was not provided
    InvalidTtl,
    /// The request was missing required crypto keys
    MissingCryptoKeys,
    /// One or more of the crytpo key elements are invalid.
    InvalidCryptoKeys,
    /// Corrupted response data
    InvalidResponse,
    Other(String),
}

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

impl From<UriError> for WebPushError {
    fn from(_: UriError) -> WebPushError {
        WebPushError::InvalidUri
    }
}

impl From<TimeoutError<WebPushResponse>> for WebPushError {
    fn from(_: TimeoutError<WebPushResponse>) -> WebPushError {
        WebPushError::TimeoutError
    }
}

impl From<error::Unspecified> for WebPushError {
    fn from(_: error::Unspecified) -> WebPushError {
        WebPushError::Unspecified
    }
}

impl From<native_tls::Error> for WebPushError {
    fn from(_: native_tls::Error) -> WebPushError {
        WebPushError::TlsError
    }
}

impl WebPushError {
    pub fn short_description(&self) -> &'static str {
        match *self {
            WebPushError::Unspecified        => "unspecified",
            WebPushError::Unauthorized       => "unauthorized",
            WebPushError::BadRequest(_)      => "bad_request",
            WebPushError::ServerError(_)     => "server_error",
            WebPushError::NotImplemented     => "not_implemented",
            WebPushError::InvalidUri         => "invalid_uri",
            WebPushError::TimeoutError       => "timeout_error",
            WebPushError::EndpointNotValid   => "endpoint_not_valid",
            WebPushError::EndpointNotFound   => "endpoint_not_found",
            WebPushError::PayloadTooLarge    => "payload_too_large",
            WebPushError::TlsError           => "tls_error",
            WebPushError::InvalidPackageName => "invalid_package_name",
            WebPushError::InvalidTtl         => "invalid_ttl",
            WebPushError::InvalidResponse    => "invalid_response",
            WebPushError::MissingCryptoKeys  => "missing_crypto_keys",
            WebPushError::InvalidCryptoKeys  => "invalid_crypto_keys",
            WebPushError::Other(_)           => "other",
        }
    }
}

impl Error for WebPushError {
    fn description(&self) -> &str {
        match *self {
            WebPushError::Unspecified =>
                "An unknown error happened encrypting the message",
            WebPushError::Unauthorized =>
                "Please provide valid credentials to send the notification",
            WebPushError::BadRequest(_) =>
                "Request was badly formed",
            WebPushError::ServerError(_) =>
                "Server was unable to process the request, please try again later",
            WebPushError::PayloadTooLarge =>
                "Maximum allowed payload size is 3800 characters",
            WebPushError::InvalidUri =>
                "The provided URI is invalid",
            WebPushError::NotImplemented =>
                "The feature is not implemented yet",
            WebPushError::TimeoutError =>
                "The request timed out",
            WebPushError::EndpointNotValid =>
                "The URL specified is no longer valid and should no longer be used",
            WebPushError::EndpointNotFound =>
                "The URL specified is invalid and should not be used again",
            WebPushError::TlsError =>
                "Could not initialize a TLS connection",
            WebPushError::InvalidPackageName =>
                "Make sure the message was addressed to a registration token whose package name matches the value passed in the request.",
            WebPushError::InvalidTtl => "The TTL value provided was not valid or was not provided",
            WebPushError::InvalidResponse => "The response data couldn't be parses",
            WebPushError::MissingCryptoKeys  => "The request is missing cryptographic keys",
            WebPushError::InvalidCryptoKeys  => "The request is having invalid cryptographic keys",
            WebPushError::Other(_) => "An unknown error when connecting the notification service",
        }
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

impl fmt::Display for WebPushError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}
