//! # Web Push
//!
//! A library for creating and sending push notifications to a web browser. For
//! content payload encryption it uses the [Encrypted Content-Encoding for HTTP, draft 3](https://datatracker.ietf.org/doc/draft-ietf-httpbis-encryption-encoding/03/?include_text=1).
//! The client is asynchronious and uses [Tokio](https://tokio.rs) with futures.
//!
//! # Example
//!
//! ```no_run
//! extern crate tokio;
//! extern crate web_push;
//! extern crate base64;
//! extern crate futures;
//!
//! use web_push::*;
//! use base64::URL_SAFE;
//! use futures::{Future, future::lazy};
//!
//! # fn main() {
//! let endpoint = "https://updates.push.services.mozilla.com/wpush/v1/...";
//! let p256dh = base64::decode_config("key_from_browser_as_base64", URL_SAFE).unwrap();
//! let auth = base64::decode_config("auth_from_browser_as_base64", URL_SAFE).unwrap();
//!
//! let subscription_info = SubscriptionInfo::new(
//!     endpoint,
//!     "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
//!     "xS03Fi5ErfTNH_l9WHE9Ig"
//! );
//!
//! let mut builder = WebPushMessageBuilder::new(&subscription_info).unwrap();
//! let content = "Encrypted payload to be sent in the notification".as_bytes();
//! builder.set_payload(ContentEncoding::AesGcm, content);
//!
//! match builder.build() {
//!    Ok(message) => {
//!        let client = WebPushClient::new().unwrap();
//!
//!        tokio::run(lazy(move || {
//!            client
//!                .send(message)
//!                .map(|_| {
//!                    println!("OK");
//!                }).map_err(|error| {
//!                    println!("ERROR: {:?}", error)
//!                })
//!            }));
//!    },
//!    Err(error) => {
//!        println!("ERROR in building message: {:?}", error)
//!    }
//! }
//! # }
//! ```

#[macro_use] extern crate serde_derive;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate serde_json;

extern crate chrono;
extern crate serde;
extern crate base64;
extern crate hyper;
extern crate http;
extern crate futures;
extern crate tokio_timer;
extern crate tokio_service;
extern crate hyper_tls;
extern crate ring;
extern crate crypto;
extern crate untrusted;
extern crate native_tls;
extern crate openssl;
extern crate erased_serde;
extern crate time;

mod client;
mod error;
mod http_ece;
mod message;
mod services;
mod vapid;

pub use error::WebPushError;
pub use client::{WebPushResponse, WebPushClient};

pub use message::{
    WebPushMessage,
    WebPushMessageBuilder,
    WebPushPayload,
    SubscriptionInfo,
    SubscriptionKeys
};

pub use http_ece::ContentEncoding;
pub use vapid::{VapidSignature, VapidSignatureBuilder};
