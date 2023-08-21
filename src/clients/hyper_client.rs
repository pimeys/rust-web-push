use async_trait::async_trait;

use http::header::{CONTENT_LENGTH, RETRY_AFTER};
use hyper::{body::HttpBody, client::HttpConnector, Body, Client, Request as HttpRequest};
use hyper_tls::HttpsConnector;

use crate::clients::{request_builder, WebPushClient};
use crate::error::{RetryAfter, WebPushError};
use crate::message::WebPushMessage;

/// An async client for sending the notification payload.
///
/// This client is thread-safe. Clones of this client will share the same underlying resources,
/// so cloning is a cheap and effective method to provide access to the client.
///
/// This client is [`hyper`](https://crates.io/crates/hyper) based, and will only work in Tokio contexts.
#[derive(Clone)]
pub struct HyperWebPushClient {
    client: Client<HttpsConnector<HttpConnector>>,
}

impl Default for HyperWebPushClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HyperWebPushClient {
    /// Creates a new client.
    pub fn new() -> Self {
        Self {
            client: Client::builder().build(HttpsConnector::new()),
        }
    }
}

#[async_trait]
impl WebPushClient for HyperWebPushClient {
    /// Sends a notification. Never times out.
    async fn send(&self, message: WebPushMessage) -> Result<(), WebPushError> {
        trace!("Message: {:?}", message);

        let request: HttpRequest<Body> = request_builder::build_request(message);

        debug!("Request: {:?}", request);

        let requesting = self.client.request(request);

        let response = requesting.await?;

        trace!("Response: {:?}", response);

        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|ra| ra.to_str().ok())
            .and_then(RetryAfter::from_str);

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

        trace!("Body text: {:?}", std::str::from_utf8(&body));

        let response = request_builder::parse_response(response_status, body.to_vec());

        debug!("Response: {:?}", response);

        if let Err(WebPushError::ServerError(None)) = response {
            Err(WebPushError::ServerError(retry_after))
        } else {
            Ok(response?)
        }
    }
}
