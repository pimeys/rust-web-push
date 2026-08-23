//! # Web Push
//!
//! A library for creating and sending push notifications to a web browser. For
//! content payload encryption it uses [RFC8188](https://datatracker.ietf.org/doc/html/rfc8188).
//! The client is asynchronous and can run on any executor.
//!
//! # Example
//!
//! ```no_run
//! # use web_push::*;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
//! let endpoint = "https://updates.push.services.mozilla.com/wpush/v1/...";
//! let p256dh = "key_from_browser_as_base64";
//! let auth = "auth_from_browser_as_base64";
//!
//! // You would likely get this by deserializing a browser `pushSubscription` object.
//! let subscription_info = SubscriptionInfo::new(
//!     endpoint,
//!     p256dh,
//!     auth
//! );
//!
//! // Read signing material for payload.
//! let pem = std::fs::read_to_string("private.pem").unwrap();
//! let mut sig_builder = VapidSignatureBuilder::from_pem(&pem, &subscription_info)?.build()?;
//!
//! // Now add payload and encrypt.
//! let content = "Encrypted payload to be sent in the notification".as_bytes();
//! let builder = WebPushMessageBuilder::new(&subscription_info)
//!   .payload(ContentEncoding::Aes128Gcm, content)
//!   .vapid_signature(sig_builder);
//!
//! # #[cfg(feature = "isahc-client")]
//! let client = IsahcWebPushClient::new()?;
//!
//! // Finally, send the notification!
//! # #[cfg(feature = "isahc-client")]
//! client.send(builder.build()?).await?;
//! # Ok(())
//! # }
//! ```

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

#[cfg(feature = "isahc-client")]
pub use crate::clients::isahc_client::IsahcWebPushClient;
#[cfg(feature = "reqwest-client")]
pub use crate::clients::reqwest_client::ReqwestWebPushClient;
pub use crate::{
    clients::{WebPushClient, request_builder},
    error::WebPushError,
    http_ece::ContentEncoding,
    message::{SubscriptionInfo, SubscriptionKeys, Urgency, WebPushMessage, WebPushMessageBuilder, WebPushPayload},
    vapid::*,
};

mod clients;
mod error;
mod http_ece;
mod message;
mod vapid;
