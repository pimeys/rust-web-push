use hyper::{
    client::{Client, HttpConnector},
    Body, Request as HttpRequest,
};
use futures::stream::StreamExt;
use crate::error::{RetryAfter, WebPushError};
use http::header::{RETRY_AFTER, CONTENT_LENGTH};
use hyper_tls::HttpsConnector;
use crate::message::{WebPushMessage, WebPushService};
use crate::services::{autopush, firebase};
use std::future::Future;

/// An async client for sending the notification payload.
pub struct WebPushClient {
    client: Client<HttpsConnector<HttpConnector>>,
}

impl WebPushClient {
    pub fn new() -> WebPushClient {
        let mut builder = Client::builder();
        builder.pool_max_idle_per_host( std::usize::MAX);
        

        WebPushClient {
            client: builder.build(HttpsConnector::new()),
        }
    }

    /// Sends a notification. Never times out.
    pub fn send(&self, message: WebPushMessage) -> impl Future<Output = Result<(), WebPushError>> + 'static {
        let service = message.service.clone();

        let request: HttpRequest<Body> = match service {
            WebPushService::Firebase => firebase::build_request(message),
            _ => autopush::build_request(message),
        };

        trace!("Request: {:?}", request);

        let requesting = self.client.request(request);

        async move {
            let response = requesting.await?;
            trace!("Response: {:?}", response);

            let retry_after = response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|ra| ra.to_str().ok())
                .and_then(|ra| RetryAfter::from_str(ra));

            let response_status = response.status();
            trace!("Response status: {}", response_status);

            let content_length: usize = response
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|s| s.to_str().ok())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            let mut body: Vec<u8> = Vec::with_capacity(content_length);
            let mut chunks = response.into_body();

            while let Some(chunk) = chunks.next().await {
                body.extend_from_slice(&chunk?);
            }
            trace!("Body: {:?}", body);

            trace!("Body text: {:?}", std::str::from_utf8(&body));

            let response = match service {
                WebPushService::Firebase => {
                    firebase::parse_response(response_status, body.to_vec())
                }
                _ => autopush::parse_response(response_status, body.to_vec()),
            };

            debug!("Response: {:?}", response);

            if let Err(WebPushError::ServerError(None)) = response {
                Err(WebPushError::ServerError(retry_after))
            } else {
                Ok(response?)
            }
        }
    }
}
