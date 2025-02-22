use async_trait::async_trait;

use http::header::RETRY_AFTER;
use hyper::{body::HttpBody, client::HttpConnector, Body, Client, Request as HttpRequest};
use hyper_tls::HttpsConnector;

use crate::clients::{request_builder, WebPushClient, MAX_RESPONSE_SIZE};
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

impl From<Client<HttpsConnector<HttpConnector>>> for HyperWebPushClient {
    /// Creates a new client from a custom hyper HTTP client.
    fn from(client: Client<HttpsConnector<HttpConnector>>) -> Self {
        Self { client }
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

        let mut chunks = response.into_body();
        let mut body = Vec::new();
        while let Some(chunk) = chunks.data().await {
            body.extend(&chunk?);
            if body.len() > MAX_RESPONSE_SIZE {
                return Err(WebPushError::ResponseTooLarge);
            }
        }
        trace!("Body: {:?}", body);

        trace!("Body text: {:?}", std::str::from_utf8(&body));

        let response = request_builder::parse_response(response_status, body.to_vec());

        debug!("Response: {:?}", response);

        if let Err(WebPushError::ServerError {
            retry_after: None,
            info,
        }) = response
        {
            Err(WebPushError::ServerError { retry_after, info })
        } else {
            Ok(response?)
        }
    }
}
