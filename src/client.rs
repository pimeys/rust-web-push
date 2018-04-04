use hyper::client::{HttpConnector, Client};
use hyper_tls::HttpsConnector;
use hyper::client::{Request as HttpRequest, Response as HttpResponse};
use hyper::header::RetryAfter;
use futures::{Future, Poll};
use futures::future::{ok, err};
use futures::stream::Stream;
use tokio_core::reactor::Handle;
use tokio_service::Service;
use tokio_timer::{Timer, Timeout};
use std::fmt;
use std::time::{SystemTime, Duration};
use services::{firebase, autopush};
use error::WebPushError;
use message::{WebPushMessage, WebPushService};

pub struct WebPushResponse(Box<Future<Item = (), Error = WebPushError> + 'static>);

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

pub struct WebPushClient {
    client: Client<HttpsConnector<HttpConnector>>,
    timer: Timer,
}

impl WebPushClient {
    pub fn new(handle: &Handle) -> Result<WebPushClient, WebPushError> {
        let client = Client::configure()
            .connector(HttpsConnector::new(4, handle)?)
            .keep_alive(true)
            .build(handle);

        Ok(WebPushClient {
            client: client,
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

        let request: HttpRequest = match service {
            WebPushService::Firebase =>
                firebase::build_request(message),
            _ =>
                autopush::build_request(message),
        };

        let request_f = self.client.request(request).map_err(
            |_| WebPushError::Unspecified,
        );

        let push_f = request_f.and_then(move |response: HttpResponse| {
            let retry_after = response.headers().get::<RetryAfter>().map(|ra| *ra);
            let response_status = response.status().clone();

            response
                .body()
                .map_err(|_| WebPushError::Unspecified)
                .concat2()
                .and_then(move |body| {
                    let response = match service {
                        WebPushService::Firebase =>
                            firebase::parse_response(response_status, body.to_vec()),
                        _ =>
                            autopush::parse_response(response_status, body.to_vec()),
                    };
                    println!("{:?}", response);
                    match response {
                        Err(WebPushError::ServerError(None)) => {
                            let retry_duration = match retry_after {
                                Some(RetryAfter::Delay(duration)) => Some(duration),
                                Some(RetryAfter::DateTime(retry_time)) => {
                                    let retry_system_time: SystemTime = retry_time.into();

                                    let duration = retry_system_time
                                        .duration_since(SystemTime::now())
                                        .unwrap_or(Duration::new(0, 0));

                                    Some(duration)
                                }
                                None => None,
                            };

                            err(WebPushError::ServerError(retry_duration))
                        }

                        Err(e) => err(e),
                        Ok(()) => ok(()),
                    }
                })
        });

        WebPushResponse(Box::new(push_f))
    }
}
