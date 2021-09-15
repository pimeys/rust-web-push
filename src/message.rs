use http::uri::Uri;

use crate::error::WebPushError;
use crate::http_ece::{ContentEncoding, HttpEce};
use crate::vapid::VapidSignature;

/// Encryption keys from the client.
#[derive(Debug, Deserialize, Serialize, Clone, Eq, PartialEq, Ord, PartialOrd, Default, Hash)]
pub struct SubscriptionKeys {
    /// The public key. Base64 encoded.
    pub p256dh: String,
    /// Authentication secret. Base64 encoded.
    pub auth: String,
}

/// Client info for sending the notification. Maps the values from browser's
/// subscription info JSON data (AKA pushSubscription object).
///
/// Client pushSubscription objects can be directly deserialized into this struct using serde.
#[derive(Debug, Deserialize, Serialize, Clone, Eq, PartialEq, Ord, PartialOrd, Default, Hash)]
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
    /// The endpoint URI where to send the payload.
    pub endpoint: Uri,
    /// Time to live, how long the message should wait in the server if user is
    /// not online. Some services require this value to be set.
    pub ttl: u32,
    /// The encrypted request payload, if sending any data.
    pub payload: Option<WebPushPayload>,
}

struct WebPushPayloadBuilder<'a> {
    pub content: &'a [u8],
    pub encoding: ContentEncoding,
}

/// The main class for creating a notification payload.
pub struct WebPushMessageBuilder<'a> {
    subscription_info: &'a SubscriptionInfo,
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
            subscription_info,
            ttl: 2_419_200,
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

    /// Add a VAPID signature to the request. To be generated with the
    /// [VapidSignatureBuilder](struct.VapidSignatureBuilder.html).
    pub fn set_vapid_signature(&mut self, vapid_signature: VapidSignature) {
        self.vapid_signature = Some(vapid_signature);
    }

    /// If set, the client will get content in the notification. Has a maximum size of
    /// 3800 characters.
    ///
    /// Currently, Aes128Gcm is the recommended and only encoding standard implemented.
    pub fn set_payload(&mut self, encoding: ContentEncoding, content: &'a [u8]) {
        self.payload = Some(WebPushPayloadBuilder { content, encoding });
    }

    /// Builds and if set, encrypts the payload. Any errors due to bad encryption will be
    /// [`WebPushError::Unspecified`], meaning
    /// something was wrong in the given public key or authentication.
    /// You can further debug these issues by checking the API responses visible with
    /// `log::trace` level.
    pub fn build(self) -> Result<WebPushMessage, WebPushError> {
        let endpoint: Uri = self.subscription_info.endpoint.parse()?;

        if let Some(payload) = self.payload {
            let p256dh = base64::decode_config(&self.subscription_info.keys.p256dh, base64::URL_SAFE)?;
            let auth = base64::decode_config(&self.subscription_info.keys.auth, base64::URL_SAFE)?;

            let http_ece = HttpEce::new(payload.encoding, &p256dh, &auth, self.vapid_signature);

            Ok(WebPushMessage {
                endpoint,
                ttl: self.ttl,
                payload: Some(http_ece.encrypt(payload.content)?),
            })
        } else {
            Ok(WebPushMessage {
                endpoint,
                ttl: self.ttl,
                payload: None,
            })
        }
    }
}
