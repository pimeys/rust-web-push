use async_trait::async_trait;
use http::header::RETRY_AFTER;
use reqwest::Body;

use crate::{
    WebPushClient, WebPushError, WebPushMessage,
    clients::MAX_RESPONSE_SIZE,
    error::RetryAfter,
    request_builder::{self, build_request},
};

#[derive(Clone)]
pub struct ReqwestWebPushClient {
    client: reqwest::Client,
}

impl ReqwestWebPushClient {
    /// Creates a new client. Can fail under resource depletion.
    pub fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: reqwest::ClientBuilder::new().build()?,
        })
    }

    pub fn from_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl WebPushClient for ReqwestWebPushClient {
    async fn send(&self, message: WebPushMessage) -> Result<(), WebPushError> {
        trace!("Message: {:?}", message);

        let http_request = build_request::<Body>(message);
        let (parts, body) = http_request.into_parts();

        let request = self
            .client
            .request(parts.method, parts.uri.to_string())
            .headers(parts.headers)
            .body(body);

        trace!("Request: {:?}", request);

        let mut response = request.send().await?;

        trace!("Response: {:?}", response);

        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|ra| ra.to_str().ok())
            .and_then(RetryAfter::from_str);

        let response_status = response.status();
        trace!("Response status: {}", response_status);

        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_RESPONSE_SIZE {
                return Err(WebPushError::ResponseTooLarge);
            }
            body.extend(chunk);
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
