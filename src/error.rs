use base64::DecodeError;
use chrono;
use openssl::error::ErrorStack;
use ring::error;
use serde_json::error::Error as JsonError;
use std::{
    convert::From,
    io::Error as IoError,
    string::FromUtf8Error,
    time::{Duration, SystemTime},
};
use thiserror::Error;

/// An error message when either creating or sending the notification.
#[derive(PartialEq, Debug, Error)]
pub enum WebPushError {
    /// An unknown error happened encrypting the message.
    #[error("An unknown error happened encrypting the message.")]
    Unspecified,
    /// Please provide valid credentials to send the notification.
    #[error("Please provide valid credentials to send the notification.")]
    Unauthorized,
    /// Request was badly formed.
    #[error("Request was badly formed. Reason: {:?}", _0)]
    BadRequest(Option<String>),
    /// Contains an optional `Duration`, until the user can retry the request
    #[error("Request was badly formed. Retry in: {:?}", _0)]
    ServerError(Option<Duration>),
    /// The feature is not implemented yet.
    #[error("The feature is not implemented yet.")]
    NotImplemented,
    /// The provided URI is invalid.
    #[error("The provided URI is invalid.")]
    InvalidUri,
    /// The URL specified is no longer valid and should no longer be used.
    #[error("The URL specified is no longer valid and should no longer be used.")]
    EndpointNotValid,
    /// The URL specified is invalid and should not be used again.
    #[error("The URL specified is invalid and should not be used again.")]
    EndpointNotFound,
    /// Maximum allowed payload size is 3800 characters.
    #[error("Maximum allowed payload size is 3800 characters.")]
    PayloadTooLarge,
    /// Could not initialize a TLS connection.
    #[error("Could not initialize a TLS connection.")]
    TlsError,
    /// Error in SSL signing.
    #[error("Error in SSL signing.")]
    SslError,
    /// Error in reading a file.
    #[error("Error in reading a file.")]
    IoError,
    /// Make sure the message was addressed to a registration token whose
    /// package name matches the value passed in the request (Google).
    #[error("Make sure the message was addressed to a registration token whose package name matches the value passed in the request (Google).")]
    InvalidPackageName,
    /// The TTL value provided was not valid or was not provided.
    #[error("The TTL value provided was not valid or was not provided.")]
    InvalidTtl,
    /// The request was missing required crypto keys.
    #[error("The request was missing required crypto keys.")]
    MissingCryptoKeys,
    /// One or more of the crypto key elements are invalid.
    #[error("One or more of the crypto key elements are invalid.")]
    InvalidCryptoKeys,
    /// Corrupted response data.
    #[error("Corrupted response data.")]
    InvalidResponse,
    /// Other, unknown error.
    #[error("{}", _0)]
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

impl From<error::Unspecified> for WebPushError {
    fn from(_: error::Unspecified) -> WebPushError {
        WebPushError::Unspecified
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

impl From<http_types::Error> for WebPushError {
    fn from(e: http_types::Error) -> Self {
        Self::Other(e.to_string())
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
