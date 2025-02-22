//! Contains tooling for signing with VAPID.

pub use self::{builder::VapidSignatureBuilder, signer::VapidSignature};
use self::{key::VapidKey, signer::VapidSigner};

pub mod builder;
mod key;
mod signer;
