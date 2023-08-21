use async_trait::async_trait;
use futures_lite::AsyncReadExt;
use http::header::{CONTENT_LENGTH, RETRY_AFTER};
use isahc::HttpClient;

use crate::clients::request_builder;
use crate::clients::WebPushClient;
use crate::error::{RetryAfter, WebPushError};
use crate::message::WebPushMessage;

/// An async client for sending the notification payload. This client is expensive to create, and
/// should be reused.
///
/// This client is thread-safe. Clones of this client will share the same underlying resources,
/// so cloning is a cheap and effective method to provide access to the client.
///
/// This client is built on [`isahc`](https://crates.io/crates/isahc), and will therefore work on any async executor.
#[derive(Clone)]
pub struct IsahcWebPushClient {
    client: HttpClient,
}

impl Default for IsahcWebPushClient {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[async_trait]
impl WebPushClient for IsahcWebPushClient {
    type CreationError = WebPushError;

    /// Creates a new client. Can fail under resource depletion.
    fn new() -> Result<Self, Self::CreationError> {
        Ok(Self {
            client: HttpClient::new()?,
        })
    }

    /// Sends a notification. Never times out.
    async fn send(&self, message: WebPushMessage) -> Result<(), WebPushError> {
        trace!("Message: {:?}", message);

        let request = request_builder::build_request::<isahc::AsyncBody>(message);

        trace!("Request: {:?}", request);

        let requesting = self.client.send_async(request);

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

        chunks
            .read_to_end(&mut body)
            .await
            .map_err(|_| WebPushError::InvalidResponse)?;

        trace!("Body: {:?}", body);

        trace!("Body text: {:?}", std::str::from_utf8(&body));

        let response = request_builder::parse_response(response_status, body.to_vec());

        trace!("Response: {:?}", response);

        if let Err(WebPushError::ServerError(None)) = response {
            Err(WebPushError::ServerError(retry_after))
        } else {
            Ok(response?)
        }
    }
}
