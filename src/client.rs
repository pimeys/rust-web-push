mod tcp;

use crate::{
    error::{RetryAfter, WebPushError},
    message::{WebPushMessage, WebPushService},
    services::{autopush, firebase},
};
use deadpool::managed::Pool;
use http_types::Url;
use std::{collections::HashMap, fmt, io};
use tcp::{TlsConnWrapper, WebPushManager, WebPushStream};

#[cfg(feature = "rt-async-std")]
use async_std::sync::Mutex;
#[cfg(feature = "rt-tokio")]
use tokio::sync::Mutex;

type SenderPool = HashMap<String, Pool<WebPushStream, io::Error>>;

/// An async client for sending the notification payload.
pub struct WebPushClient {
    pool: Mutex<SenderPool>,
}

impl fmt::Debug for WebPushClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebPushClient").finish()
    }
}

impl WebPushClient {
    /// Creates a new instance. Please reuse the client between requests for
    /// best performance.
    pub fn new() -> WebPushClient {
        let pool = Mutex::new(SenderPool::new());
        WebPushClient { pool }
    }

    /// Sends a notification. Never times out.
    pub async fn send(&self, message: WebPushMessage) -> Result<(), WebPushError> {
        trace!("Message: {:?}", message);

        let service = message.service.clone();
        let conn = self.get_conn(&message.endpoint).await;

        let request = match service {
            WebPushService::Firebase => {
                trace!("Building firebase request");
                firebase::build_request(message)
            }
            _ => {
                trace!("Building autopush request");
                autopush::build_request(message)
            }
        };

        trace!("Request: {:?}", request);

        let mut response = async_h1::connect(conn, request).await?;

        trace!("Response: {:?}", response);

        let retry_after = response
            .header("Retry-After")
            .map(|h| h.last().as_str())
            .and_then(RetryAfter::from_str);

        let response_status = response.status();

        trace!("Response status: {}", response_status);

        let body = response.body_bytes().await?;

        trace!("Body: {:?}", body);
        trace!("Body text: {:?}", std::str::from_utf8(&body));

        let response = match service {
            WebPushService::Firebase => firebase::parse_response(response_status, body.to_vec()),
            _ => autopush::parse_response(response_status, body.to_vec()),
        };

        debug!("Response: {:?}", response);

        if let Err(WebPushError::ServerError(None)) = response {
            Err(WebPushError::ServerError(retry_after))
        } else {
            Ok(response?)
        }
    }

    async fn get_conn(&self, endpoint: &Url) -> TlsConnWrapper {
        let mut map = self.pool.lock().await;
        let host = endpoint.host_str().unwrap();

        let pool = match map.get(host) {
            Some(pool) => pool,
            None => {
                let manager = WebPushManager::new(endpoint);

                map.insert(host.to_string(), Pool::new(manager, 50));
                map.get(host).unwrap()
            }
        };

        TlsConnWrapper::new(pool.get().await.unwrap())
    }
}
