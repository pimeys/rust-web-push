use std::error::Error;
use std::convert::From;
use std::fmt;
use ring::error;
use tokio_timer::TimeoutError;
use client::WebPushResponse;
use native_tls;
use std::time::Duration;

#[derive(PartialEq, Debug)]
pub enum WebPushError {
    // An unknown error happened encrypting the message,
    Unspecified,
    // Please provide valid credentials to send the notification
    Unauthorized,
    // Request was badly formed
    BadRequest,
    // Contains an optional `Duration`, until the user can retry the request
    ServerError(Option<Duration>),
    // The feature is not implemented yet
    NotImplemented,
    // The provided URI is invalid
    InvalidUri,
    // The request timed out
    TimeoutError,
    // The URL specified is no longer valid and should no longer be used
    EndpointNotValid,
    // The URL specified is invalid and should not be used again
    EndpointNotFound,
    // Maximum allowed payload size is 3800 characters
    PayloadTooLarge,
    // Could not initialize a TLS connection
    TlsError,
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
            WebPushError::Unspecified      => "unspecified",
            WebPushError::Unauthorized     => "unauthorized",
            WebPushError::BadRequest       => "bad_request",
            WebPushError::ServerError(_)   => "server_error",
            WebPushError::NotImplemented   => "not_implemented",
            WebPushError::InvalidUri       => "invalid_uri",
            WebPushError::TimeoutError     => "timeout_error",
            WebPushError::EndpointNotValid => "endpoint_not_valid",
            WebPushError::EndpointNotFound => "endpoint_not_found",
            WebPushError::PayloadTooLarge  => "payload_too_large",
            WebPushError::TlsError         => "tls_error",
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
            WebPushError::BadRequest =>
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
                "Could not initialize a TLS connection"
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
