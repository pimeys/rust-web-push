use std::error::Error;
use std::convert::From;
use std::fmt;
use ring::error;
use hyper::header::RetryAfter;
use tokio_timer::TimeoutError;
use client::WebPushResponse;

#[derive(PartialEq, Debug)]
pub enum WebPushError {
    Unspecified,
    Unauthorized,
    BadRequest,
    ServerError(Option<RetryAfter>),
    ContentTooLong,
    NotImplemented,
    InvalidUri,
    TimeoutError,
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
            WebPushError::ContentTooLong =>
                "Maximum allowed payload size is 3800 characters",
            WebPushError::InvalidUri =>
                "The provided URI is invalid",
            WebPushError::NotImplemented =>
                "The feature is not implemented yet",
            WebPushError::TimeoutError =>
                "The request timed out"
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
