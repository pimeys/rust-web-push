use std::time::{SystemTime, Duration};
use std::error::Error;
use std::convert::From;
use std::fmt;
use ring::error;
use hyper::header::RetryAfter;
use tokio_timer::TimeoutError;
use client::WebPushResponse;
use native_tls;

#[derive(PartialEq, Debug)]
pub enum WebPushError {
    Unspecified,
    Unauthorized,
    BadRequest,
    ServerError(Option<RetryAfter>),
    NotImplemented,
    InvalidUri,
    TimeoutError,
    EndpointNotValid,
    EndpointNotFound,
    PayloadTooLarge,
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

    /// In some cases the server tells the time when to try to send the
    /// notification again. This is a helper method to get a duration from the
    /// possible options.
    pub fn retry_after(&self) -> Option<Duration> {
        match *self {
            WebPushError::ServerError(error) => {
                match error {
                    Some(RetryAfter::Delay(duration)) =>
                        Some(duration),
                    Some(RetryAfter::DateTime(retry_time)) => {
                        let retry_system_time: SystemTime = retry_time.into();
                        let duration = retry_system_time.duration_since(SystemTime::now()).unwrap_or(Duration::new(0, 0));

                        Some(duration)
                    },
                    None => None
                }
            },
            _ => None
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
