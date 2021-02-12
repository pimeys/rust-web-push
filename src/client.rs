mod tcp;

use crate::{error::WebPushError, message::WebPushMessage, read_response};
use deadpool::managed::Pool;
use http_types::{Request, Url};
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
        let service = message.service;

        let request: Request = message.into();

        let conn = self.get_conn(request.url()).await;

        trace!("Request: {:?}", request);

        let response = async_h1::connect(conn, request).await?;

        trace!("Response: {:?}", response);

        read_response(response, service).await
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
