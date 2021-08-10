//! Contains implementations of web push clients.
//!
//! [`request_builder`] contains the functions used to send and consume push http messages.
//! This module should be consumed by each client, by using [`http`]'s flexible api.

pub mod request_builder;

#[cfg(feature = "hyper-client")]
pub mod hyper_client;

#[cfg(not(feature = "hyper-client"))]
pub mod isahc_client;
