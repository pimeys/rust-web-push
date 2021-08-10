//! # Web Push
//!
//! A library for creating and sending push notifications to a web browser. For
//! content payload encryption it uses [RFC8188](https://datatracker.ietf.org/doc/html/rfc8188).
//! The client is asynchronous and can run on any executor. An optional [`hyper`](https://crates.io/crates/hyper) based client is
//! available with the feature `hyper-client`.
//!
//! # Example
//!
//! ```no_run
//! # use web_push::*;
//! # use base64::URL_SAFE;
//! # use std::fs::File;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
//! let endpoint = "https://updates.push.services.mozilla.com/wpush/v1/...";
//! let p256dh = "key_from_browser_as_base64";
//! let auth = "auth_from_browser_as_base64";
//!
//! //You would likely get this by deserializing a browser `pushSubscription` object.  
//! let subscription_info = SubscriptionInfo::new(
//!     endpoint,
//!     p256dh,
//!     auth
//! );
//!
//! //Read signing material for payload.
//! let file = File::open("private.pem").unwrap();
//! let mut sig_builder = VapidSignatureBuilder::from_pem(file, &subscription_info)?.build()?;
//!
//! //Now add payload and encrypt.
//! let mut builder = WebPushMessageBuilder::new(&subscription_info)?;
//! let content = "Encrypted payload to be sent in the notification".as_bytes();
//! builder.set_payload(ContentEncoding::Aes128Gcm, content);
//! builder.set_vapid_signature(sig_builder);
//!
//! let client = WebPushClient::new()?;
//!
//! //Finally, send the notification!
//! client.send(builder.build()?).await?;
//! # Ok(())
//! # }
//! ```

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate log;

mod clients;
mod error;
mod http_ece;
mod message;
mod vapid;

#[cfg(feature = "hyper-client")]
pub use crate::clients::hyper_client::WebPushClient;

#[cfg(not(feature = "hyper-client"))]
pub use crate::clients::isahc_client::WebPushClient;

pub use crate::error::WebPushError;

pub use crate::message::{SubscriptionInfo, SubscriptionKeys, WebPushMessage, WebPushMessageBuilder, WebPushPayload};

pub use crate::http_ece::ContentEncoding;
pub use crate::vapid::builder::PartialVapidSignatureBuilder;
pub use crate::vapid::{VapidSignature, VapidSignatureBuilder};

pub use crate::clients::request_builder;
