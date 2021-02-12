use std::fmt;

use crate::{
    error::WebPushError,
    http_ece::{ContentEncoding, HttpEce},
    services::*,
    vapid::VapidSignature,
};
use base64;
use http_types::{Request, Url};

/// Encryption keys from the client.
#[derive(Debug, Deserialize, Serialize)]
pub struct SubscriptionKeys {
    /// The public key
    pub p256dh: String,
    /// Authentication secret
    pub auth: String,
}

/// Client info for sending the notification. Maps the values from browser's
/// subscription info JSON data.
#[derive(Debug, Deserialize, Serialize)]
pub struct SubscriptionInfo {
    /// The endpoint URI for sending the notification.
    pub endpoint: String,
    /// The encryption key and secret for payload encryption.
    pub keys: SubscriptionKeys,
}

impl SubscriptionInfo {
    /// A constructor function to create a new `SubscriptionInfo`, if not using
    /// Serde's serialization.
    pub fn new<S>(endpoint: S, p256dh: S, auth: S) -> SubscriptionInfo
    where
        S: Into<String>,
    {
        SubscriptionInfo {
            endpoint: endpoint.into(),
            keys: SubscriptionKeys {
                p256dh: p256dh.into(),
                auth: auth.into(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum WebPushService {
    Firebase,
    Autopush,
}

/// The push content payload, already in an encrypted form.
#[derive(Debug, PartialEq)]
pub struct WebPushPayload {
    /// Encrypted content data.
    pub content: Vec<u8>,
    /// Headers depending on the authorization scheme and encryption standard.
    pub crypto_headers: Vec<(&'static str, String)>,
    /// The encryption standard.
    pub content_encoding: &'static str,
}

/// Everything needed to send a push notification to the user.
#[derive(Debug)]
pub struct WebPushMessage {
    /// When not using VAPID, certain browsers need a Firebase account key for
    /// sending a notification.
    pub gcm_key: Option<String>,
    /// The endpoint URI where to send the payload.
    pub endpoint: Url,
    /// Time to live, how long the message should wait in the server if user is
    /// not online. Some services require this value to be set.
    pub ttl: u32,
    /// The encrypted request payload, if sending any data.
    pub payload: Option<WebPushPayload>,
    /// The service type where to connect. Firebase when not using VAPID with
    /// Chrome-based browsers. Data is in JSON format instead of binary.
    pub service: WebPushService,
}

impl From<WebPushMessage> for Request {
    fn from(message: WebPushMessage) -> Self {
        let service = message.service;

        match service {
            #[cfg(feature = "firebase")]
            WebPushService::Firebase => {
                trace!("Building firebase request");
                firebase::build_request(message)
            }
            _ => {
                trace!("Building autopush request");
                autopush::build_request(message)
            }
        }
    }
}

struct WebPushPayloadBuilder<'a> {
    pub content: &'a [u8],
    pub encoding: ContentEncoding,
}

impl<'a> fmt::Debug for WebPushPayloadBuilder<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebPushMessageBuilder").finish()
    }
}

/// The main class for creating a notification payload.
#[derive(Debug)]
pub struct WebPushMessageBuilder<'a> {
    subscription_info: &'a SubscriptionInfo,
    gcm_key: Option<&'a str>,
    payload: Option<WebPushPayloadBuilder<'a>>,
    ttl: u32,
    vapid_signature: Option<VapidSignature>,
}

impl<'a> WebPushMessageBuilder<'a> {
    /// Creates a builder for generating the web push payload.
    ///
    /// All parameters are from the subscription info given by browser when
    /// subscribing to push notifications.
    pub fn new(subscription_info: &'a SubscriptionInfo) -> Result<WebPushMessageBuilder<'a>, WebPushError> {
        Ok(WebPushMessageBuilder {
            subscription_info: subscription_info,
            ttl: 2_419_200,
            gcm_key: None,
            payload: None,
            vapid_signature: None,
        })
    }

    /// How long the server should keep the message if it cannot be delivered
    /// currently. If not set, the message is deleted immediately on failed
    /// delivery.
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl;
    }

    /// For Google's push service, one must provide an API key from Firebase console.
    pub fn set_gcm_key(&mut self, gcm_key: &'a str) {
        self.gcm_key = Some(gcm_key);
    }

    /// Add a VAPID signature to the request. To be generated with the
    /// [VapidSignatureBuilder](struct.VapidSignatureBuilder.html).
    pub fn set_vapid_signature(&mut self, vapid_signature: VapidSignature) {
        self.vapid_signature = Some(vapid_signature);
    }

    /// If set, the client will get content in the notification. Has a maximum size of
    /// 3800 characters.
    pub fn set_payload(&mut self, encoding: ContentEncoding, payload: &'a [u8]) {
        self.payload = Some(WebPushPayloadBuilder {
            content: payload,
            encoding: encoding,
        });
    }

    /// Builds and if set, encrypts the payload. Any errors will be `Undefined`, meaning
    /// something was wrong in the given public key or authentication.
    pub fn build(self) -> Result<WebPushMessage, WebPushError> {
        let endpoint: Url = self.subscription_info.endpoint.parse().unwrap();

        let service = match self.vapid_signature {
            Some(_) => WebPushService::Autopush,
            _ => match endpoint.host_str() {
                Some("android.googleapis.com") => WebPushService::Firebase,
                Some("fcm.googleapis.com") => WebPushService::Firebase,
                _ => WebPushService::Autopush,
            },
        };

        if let Some(payload) = self.payload {
            let p256dh = base64::decode_config(&self.subscription_info.keys.p256dh, base64::URL_SAFE)?;
            let auth = base64::decode_config(&self.subscription_info.keys.auth, base64::URL_SAFE)?;

            let http_ece = HttpEce::new(payload.encoding, &p256dh, &auth, self.vapid_signature);

            Ok(WebPushMessage {
                gcm_key: self.gcm_key.map(|k| k.to_string()),
                endpoint,
                ttl: self.ttl,
                payload: Some(http_ece.encrypt(payload.content)?),
                service: service,
            })
        } else {
            Ok(WebPushMessage {
                gcm_key: self.gcm_key.map(|k| k.to_string()),
                endpoint: endpoint,
                ttl: self.ttl,
                payload: None,
                service: service,
            })
        }
    }
}
