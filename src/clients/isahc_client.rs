use async_trait::async_trait;
use futures_lite::AsyncReadExt;
use http::header::RETRY_AFTER;
use isahc::HttpClient;

use crate::clients::request_builder;
use crate::clients::{WebPushClient, MAX_RESPONSE_SIZE};
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

impl From<HttpClient> for IsahcWebPushClient {
    /// Creates a new client from a custom Isahc HTTP client.
    fn from(client: HttpClient) -> Self {
        Self { client }
    }
}

impl IsahcWebPushClient {
    /// Creates a new client. Can fail under resource depletion.
    pub fn new() -> Result<Self, WebPushError> {
        Ok(Self {
            client: HttpClient::new()?,
        })
    }
}

#[async_trait]
impl WebPushClient for IsahcWebPushClient {
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

        let mut body = Vec::new();
        if response
            .into_body()
            .take(MAX_RESPONSE_SIZE as u64 + 1)
            .read_to_end(&mut body)
            .await?
            > MAX_RESPONSE_SIZE
        {
            return Err(WebPushError::ResponseTooLarge);
        }
        trace!("Body: {:?}", body);

        trace!("Body text: {:?}", std::str::from_utf8(&body));

        let response = request_builder::parse_response(response_status, body.to_vec());

        trace!("Response: {:?}", response);

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
