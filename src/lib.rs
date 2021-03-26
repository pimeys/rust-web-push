//! # Web Push
//!
//! A library for creating and sending push notifications to a web browser. For
//! content payload encryption it uses the [Encrypted Content-Encoding for HTTP, draft 3](https://datatracker.ietf.org/doc/draft-ietf-httpbis-encryption-encoding/03/?include_text=1).
//! The client is asynchronious and uses [Tokio](https://tokio.rs) with futures.
//!
//! # Example
//!
//! ```no_run
//! # use web_push::*;
//! # use base64::URL_SAFE;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
//! let endpoint = "https://updates.push.services.mozilla.com/wpush/v1/...";
//! let p256dh = base64::decode_config("key_from_browser_as_base64", URL_SAFE)?;
//! let auth = base64::decode_config("auth_from_browser_as_base64", URL_SAFE)?;
//!
//! let subscription_info = SubscriptionInfo::new(
//!     endpoint,
//!     "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
//!     "xS03Fi5ErfTNH_l9WHE9Ig"
//! );
//!
//! let mut builder = WebPushMessageBuilder::new(&subscription_info)?;
//! let content = "Encrypted payload to be sent in the notification".as_bytes();
//! builder.set_payload(ContentEncoding::AesGcm, content);
//!
//! let client = WebPushClient::new();
//!
//! let response = client.send(builder.build()?).await?;
//! println!("Got response: {:?}", response);
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

mod client;
mod error;
mod http_ece;
mod message;
mod services;
mod vapid;

pub use crate::client::WebPushClient;
pub use crate::error::WebPushError;

pub use crate::message::{SubscriptionInfo, SubscriptionKeys, WebPushMessage, WebPushMessageBuilder, WebPushPayload};

pub use crate::http_ece::ContentEncoding;
pub use crate::vapid::{VapidSignature, VapidSignatureBuilder};
