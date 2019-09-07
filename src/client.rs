use hyper::{
    client::{Client, HttpConnector},
    Body, Request as HttpRequest,
};
use futures::stream::TryStreamExt;
use crate::error::{RetryAfter, WebPushError};
use http::header::RETRY_AFTER;
use hyper_tls::HttpsConnector;
use crate::message::{WebPushMessage, WebPushService};
use crate::services::{autopush, firebase};

/// An async client for sending the notification payload.
pub struct WebPushClient {
    client: Client<HttpsConnector<HttpConnector>>,
}

impl WebPushClient {
    pub fn new() -> Result<WebPushClient, WebPushError> {
        let mut builder = Client::builder();
        builder.keep_alive(true);

        Ok(WebPushClient {
            client: builder.build(HttpsConnector::new()?),
        })
    }

    /// Sends a notification. Never times out.
    pub async fn send(&self, message: WebPushMessage) -> Result<(), WebPushError> {
        let service = message.service.clone();

        let request: HttpRequest<Body> = match service {
            WebPushService::Firebase => firebase::build_request(message),
            _ => autopush::build_request(message),
        };

        trace!("Request: {:?}", request);

        let response = self.client.request(request).await?;

        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|ra| ra.to_str().ok())
            .and_then(|ra| RetryAfter::from_str(ra));

        let response_status = response.status();
        trace!("Response status: {}", response_status);

        let body = response.into_body().try_concat().await?;
        trace!("Body: {:?}", body);

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
