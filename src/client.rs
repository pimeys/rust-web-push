use crate::error::{RetryAfter, WebPushError};
use crate::message::{WebPushMessage};
use crate::services::{autopush};
use http::header::{CONTENT_LENGTH, RETRY_AFTER};
use hyper::{body::HttpBody, client::HttpConnector, Body, Client, Request as HttpRequest};
use hyper_tls::HttpsConnector;
use std::future::Future;

/// An async client for sending the notification payload.
pub struct WebPushClient { //TODO see if we can add a non tokio client alternative
    client: Client<HttpsConnector<HttpConnector>>,
}

impl Default for WebPushClient {
    fn default() -> Self {
        Self::new()
    }
}

impl WebPushClient {
    pub fn new() -> WebPushClient {
        WebPushClient {
            client: Client::builder().build(HttpsConnector::new()),
        }
    }

    /// Sends a notification. Never times out.
    pub fn send(&self, message: WebPushMessage) -> impl Future<Output = Result<(), WebPushError>> + 'static {
        trace!("Message: {:?}", message);

        let request: HttpRequest<Body> = autopush::build_request(message);

        info!("Request: {:?}", request);

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

            while let Some(chunk) = chunks.data().await {
                body.extend(&chunk?);
            }
            trace!("Body: {:?}", body);

            info!("Body text: {:?}", std::str::from_utf8(&body));

            let response = autopush::parse_response(response_status, body.to_vec());

            debug!("Response: {:?}", response);

            if let Err(WebPushError::ServerError(None)) = response {
                Err(WebPushError::ServerError(retry_after))
            } else {
                Ok(response?)
            }
        }
    }
}
