use hyper::{
    client::{Client, HttpConnector},
    Body, Request as HttpRequest,
};

use futures::{
    future::{err, ok},
    Future, Poll, Stream,
};

use std::{fmt, time::Duration};

use crate::error::{RetryAfter, WebPushError};

use http::header::RETRY_AFTER;
use hyper_tls::HttpsConnector;
use crate::message::{WebPushMessage, WebPushService};
use crate::services::{autopush, firebase};
use tokio_service::Service;
use tokio_timer::{Timeout, Timer};

/// The response future. When successful, returns an empty `Unit` for failures
/// gives a [WebPushError](enum.WebPushError.html).
pub struct WebPushResponse(Box<dyn Future<Item = (), Error = WebPushError> + Send + 'static>);

impl fmt::Debug for WebPushResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.pad("Future<Response>")
    }
}

impl Future for WebPushResponse {
    type Item = ();
    type Error = WebPushError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

/// An async client for sending the notification payload.
pub struct WebPushClient {
    client: Client<HttpsConnector<HttpConnector>>,
    timer: Timer,
}

impl WebPushClient {
    pub fn new() -> Result<WebPushClient, WebPushError> {
        let mut builder = Client::builder();
        builder.keep_alive(true);

        Ok(WebPushClient {
            client: builder.build(HttpsConnector::new(4)?),
            timer: Timer::default(),
        })
    }

    /// Sends a notification. Never times out.
    pub fn send(&self, message: WebPushMessage) -> WebPushResponse {
        self.call(message)
    }

    /// Sends a notification with a timeout. Triggers `WebPushError::TimeoutError` if the request takes too long.
    pub fn send_with_timeout(
        &self,
        message: WebPushMessage,
        timeout: Duration,
    ) -> Timeout<WebPushResponse> {
        self.timer.timeout(self.send(message), timeout)
    }
}

impl Service for WebPushClient {
    type Request = WebPushMessage;
    type Response = ();
    type Error = WebPushError;
    type Future = WebPushResponse;

    fn call(&self, message: Self::Request) -> Self::Future {
        let service = message.service.clone();

        let request: HttpRequest<Body> = match service {
            WebPushService::Firebase => firebase::build_request(message),
            _ => autopush::build_request(message),
        };

        trace!("Request: {:?}", request);

        let request_f = self
            .client
            .request(request)
            .map_err(|_| WebPushError::Unspecified);

        let push_f = request_f.and_then(move |response| {
            let retry_after = response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|ra| ra.to_str().ok())
                .and_then(|ra| RetryAfter::from_str(ra));
            let response_status = response.status().clone();

            trace!("Response status: {}", response_status);

            response
                .into_body()
                .map_err(|_| WebPushError::Unspecified)
                .concat2()
                .and_then(move |body| {
                    trace!("Body: {:?}", body);

                    let response = match service {
                        WebPushService::Firebase => {
                            firebase::parse_response(response_status, body.to_vec())
                        }
                        _ => autopush::parse_response(response_status, body.to_vec()),
                    };

                    debug!("Response: {:?}", response);

                    match response {
                        Err(WebPushError::ServerError(None)) => {
                            err(WebPushError::ServerError(retry_after))
                        }

                        Err(e) => err(e),
                        Ok(()) => ok(()),
                    }
                })
        });

        WebPushResponse(Box::new(push_f))
    }
}
