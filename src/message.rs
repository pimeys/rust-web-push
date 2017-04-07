use http_ece::{HttpEce, ContentEncoding};
use error::WebPushError;

#[derive(Debug, PartialEq)]
pub struct WebPushPayload {
    pub content: Vec<u8>,
    pub public_key: Vec<u8>,
    pub salt: Vec<u8>,
    pub crypto_headers: Vec<(&'static str, String)>,
    pub content_encoding: &'static str,
}

#[derive(Debug)]
pub struct WebPushMessage {
    pub gcm_key: Option<String>,
    pub endpoint: String,
    pub ttl: Option<u32>,
    pub payload: Option<WebPushPayload>,
}

pub struct WebPushMessageBuilder<'a> {
    gcm_key: Option<&'a str>,
    endpoint: &'a str,
    auth: &'a [u8],
    p256dh: &'a [u8],
    payload: Option<&'a [u8]>,
    ttl: Option<u32>,
    encoding: ContentEncoding,
}

impl<'a> WebPushMessageBuilder<'a> {
    /// Creates a builder for generating the web push payload.
    ///
    /// All parameters are from the subscription info given by browser when
    /// subscribing to push notifications.
    pub fn new(encoding: ContentEncoding, endpoint: &'a str, auth: &'a [u8], p256dh: &'a [u8]) -> WebPushMessageBuilder<'a> {
        WebPushMessageBuilder {
            endpoint: endpoint,
            auth: auth,
            p256dh: p256dh,
            encoding: encoding,
            ttl: None,
            gcm_key: None,
            payload: None,
        }
    }

    /// How long the server should keep the message if it cannot be delivered
    /// currently. If not set, the message is deleted immediately on failed
    /// delivery.
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = Some(ttl);
    }

    /// For Google's push service, one must provide an API key from Firebase console.
    pub fn set_gcm_key(&mut self, gcm_key: &'a str) {
        self.gcm_key = Some(gcm_key);
    }

    /// If set, the client will get content in the notification. Has a maximum size of
    /// 3800 characters.
    pub fn set_payload(&mut self, payload: &'a [u8]) {
        self.payload = Some(payload);
    }

    /// Builds and if set, encrypts the payload. Any errors will be `Undefined`, meaning
    /// something was wrong in the given public key or authentication.
    pub fn build(self) -> Result<WebPushMessage, WebPushError> {
        if let Some(payload) = self.payload {
            let http_ece = HttpEce::new(self.encoding, self.p256dh, self.auth);

            Ok(WebPushMessage {
                gcm_key: self.gcm_key.map(|k| k.to_string()),
                endpoint: self.endpoint.to_string(),
                ttl: self.ttl,
                payload: Some(http_ece.encrypt(payload)?),
            })
        } else {
            Ok(WebPushMessage {
                gcm_key: self.gcm_key.map(|k| k.to_string()),
                endpoint: self.endpoint.to_string(),
                ttl: self.ttl,
                payload: None,
            })
        }
    }
}
