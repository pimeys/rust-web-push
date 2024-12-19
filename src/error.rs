use std::string::FromUtf8Error;
use std::time::{Duration, SystemTime};
use std::{convert::From, error::Error, fmt, io::Error as IoError};

use http::uri::InvalidUri;
use serde_json::error::Error as JsonError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorInfo {
    pub code: u16,
    pub errno: u16,
    pub error: String,
    pub message: String,
}

impl fmt::Display for ErrorInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "code {}, errno {}: {} ({})",
            self.code, self.errno, self.error, self.message
        )
    }
}

#[derive(Debug)]
pub enum WebPushError {
    /// An unknown error happened while encrypting or sending the message
    Unspecified,
    /// Please provide valid credentials to send the notification
    Unauthorized(ErrorInfo),
    /// Request was badly formed
    BadRequest(ErrorInfo),
    /// Contains an optional `Duration`, until the user can retry the request
    ServerError {
        retry_after: Option<Duration>,
        info: ErrorInfo,
    },
    /// The feature is not implemented yet
    NotImplemented(ErrorInfo),
    /// The provided URI is invalid
    InvalidUri,
    /// The URL specified is no longer valid and should no longer be used
    EndpointNotValid(ErrorInfo),
    /// The URL specified is invalid and should not be used again
    EndpointNotFound(ErrorInfo),
    /// Maximum allowed payload size is 3800 characters
    PayloadTooLarge,
    /// Error in reading a file
    Io(IoError),
    /// Make sure the message was addressed to a registration token whose
    /// package name matches the value passed in the request (Google).
    InvalidPackageName,
    /// The TTL value provided was not valid or was not provided
    InvalidTtl,
    /// The Topic value provided was invalid
    InvalidTopic,
    /// The request was missing required crypto keys
    MissingCryptoKeys,
    /// One or more of the crypto key elements are invalid.
    InvalidCryptoKeys,
    /// Corrupted response data
    InvalidResponse,
    /// A claim had invalid data
    InvalidClaims,
    Other(ErrorInfo),
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

#[cfg(feature = "hyper-client")]
impl From<hyper::Error> for WebPushError {
    fn from(_: hyper::Error) -> Self {
        Self::Unspecified
    }
}

#[cfg(feature = "isahc-client")]
impl From<isahc::Error> for WebPushError {
    fn from(_: isahc::Error) -> Self {
        Self::Unspecified
    }
}

impl From<IoError> for WebPushError {
    fn from(err: IoError) -> WebPushError {
        WebPushError::Io(err)
    }
}

impl WebPushError {
    pub fn short_description(&self) -> &'static str {
        match *self {
            WebPushError::Unspecified => "unspecified",
            WebPushError::Unauthorized(_) => "unauthorized",
            WebPushError::BadRequest(_) => "bad_request",
            WebPushError::ServerError { .. } => "server_error",
            WebPushError::NotImplemented(_) => "not_implemented",
            WebPushError::InvalidUri => "invalid_uri",
            WebPushError::EndpointNotValid(_) => "endpoint_not_valid",
            WebPushError::EndpointNotFound(_) => "endpoint_not_found",
            WebPushError::PayloadTooLarge => "payload_too_large",
            WebPushError::InvalidPackageName => "invalid_package_name",
            WebPushError::InvalidTtl => "invalid_ttl",
            WebPushError::InvalidTopic => "invalid_topic",
            WebPushError::InvalidResponse => "invalid_response",
            WebPushError::MissingCryptoKeys => "missing_crypto_keys",
            WebPushError::InvalidCryptoKeys => "invalid_crypto_keys",
            WebPushError::Io(_) => "io_error",
            WebPushError::Other(_) => "other",
            WebPushError::InvalidClaims => "invalidClaims",
        }
    }
}

impl fmt::Display for WebPushError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WebPushError::Unspecified => write!(f, "unspecified error"),
            WebPushError::Unauthorized(info) => write!(f, "unauthorized: {}", info),
            WebPushError::BadRequest(info) => write!(f, "bad request: {}", info),
            WebPushError::ServerError { info, .. } => write!(f, "server error: {}", info),
            WebPushError::PayloadTooLarge => write!(f, "maximum payload size of 3070 characters exceeded"),
            WebPushError::InvalidUri => write!(f, "invalid uri provided"),
            WebPushError::NotImplemented(info) => write!(f, "not implemented: {}", info),
            WebPushError::EndpointNotValid(info) => write!(f, "endpoint not valid: {}", info),
            WebPushError::EndpointNotFound(info) => write!(f, "endpoint not found: {}", info),
            WebPushError::Io(err) => write!(f, "i/o error: {}", err),
            WebPushError::InvalidPackageName => write!(
                f,
                "package name of registration token does not match package name provided in the request"
            ),
            WebPushError::InvalidTtl => write!(f, "invalid or missing ttl value"),
            WebPushError::InvalidTopic => write!(f, "invalid topic value"),
            WebPushError::InvalidResponse => write!(f, "could not parse response data"),
            WebPushError::MissingCryptoKeys => write!(f, "request is missing cryptographic keys"),
            WebPushError::InvalidCryptoKeys => write!(f, "request has invalid cryptographic keys"),
            WebPushError::Other(info) => write!(f, "other: {}", info),
            WebPushError::InvalidClaims => write!(f, "at least one jwt claim was invalid"),
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
