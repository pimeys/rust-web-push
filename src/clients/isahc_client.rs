use http::header::{CONTENT_LENGTH, RETRY_AFTER};
use isahc::HttpClient;

use crate::clients::request_builder;
use crate::error::{RetryAfter, WebPushError};
use crate::message::WebPushMessage;
use futures::AsyncReadExt;

/// An async client for sending the notification payload.
pub struct WebPushClient {
    client: HttpClient,
}

impl Default for WebPushClient {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

impl WebPushClient {

    /// Creates a new client. Can fail under resource depletion.
    pub fn new() -> Result<WebPushClient, WebPushError> {
        Ok(WebPushClient {
            client: HttpClient::new()?,
        })
    }

    /// Sends a notification. Never times out.
    pub async fn send(&self, message: WebPushMessage) -> Result<(), WebPushError> {
        trace!("Message: {:?}", message);

        let request = request_builder::build_request::<isahc::AsyncBody>(message);

        info!("Request: {:?}", request);

        let requesting = self.client.send_async(request);

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

        chunks
            .read_to_end(&mut body)
            .await
            .map_err(|_| WebPushError::InvalidResponse)?;

        trace!("Body: {:?}", body);

        info!("Body text: {:?}", std::str::from_utf8(&body));

        let response = request_builder::parse_response(response_status, body.to_vec());

        debug!("Response: {:?}", response);

        if let Err(WebPushError::ServerError(None)) = response {
            Err(WebPushError::ServerError(retry_after))
        } else {
            Ok(response?)
        }
    }
}
