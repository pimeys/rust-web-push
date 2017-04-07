//! # Web Push
//!
//! A library for creating and sending push notifications to a web browser. For
//! content payload encryption it uses the [Encrypted Content-Encoding for HTTP, draft 3](https://datatracker.ietf.org/doc/draft-ietf-httpbis-encryption-encoding/03/?include_text=1).
//! The client is asynchronious and uses [Tokio](https://tokio.rs) with futures.
//!
//! # Example
//!
//! ```no_run
//! extern crate tokio_core;
//! extern crate web_push;
//! extern crate rustc_serialize;
//!
//! use web_push::*;
//! use rustc_serialize::base64::FromBase64;
//!
//! # fn main() {
//! let endpoint = "https://updates.push.services.mozilla.com/wpush/v1/...";
//! let p256dh = "key_from_browser_as_base64".from_base64().unwrap();
//! let auth = "auth_from_browser_as_base64".from_base64().unwrap();
//!
//! let mut builder = WebPushMessageBuilder::new(endpoint, &auth, &p256dh);
//! let content = "Encrypted payload to be sent in the notification".as_bytes();
//! builder.set_payload(ContentEncoding::AesGcm, content);
//!
//! match builder.build() {
//!    Ok(message) => {
//!        let mut core = tokio_core::reactor::Core::new().unwrap();
//!        let handle = core.handle();
//!        let client = WebPushClient::new(&handle);
//!
//!        let work = client.send(message);
//!
//!        match core.run(work) {
//!            Err(error) => println!("ERROR: {:?}", error),
//!            _ => println!("OK")
//!        }
//!    },
//!    Err(error) => {
//!        println!("ERROR in building message: {:?}", error)
//!    }
//! }
//! # }
//! ```

extern crate hyper;
extern crate futures;
extern crate tokio_core;
extern crate tokio_timer;
extern crate tokio_service;
extern crate hyper_tls;
extern crate rustc_serialize;
extern crate ring;
extern crate crypto;
extern crate untrusted;

mod client;
mod error;
mod http_ece;
mod message;

pub use error::WebPushError;
pub use client::{WebPushResponse, WebPushClient};
pub use message::{WebPushMessage, WebPushMessageBuilder, WebPushPayload};
pub use http_ece::ContentEncoding;
