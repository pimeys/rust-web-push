//! Contains tooling for signing with VAPID.

use self::signer::VapidSigner;
pub use self::{builder::VapidSignatureBuilder, key::VapidKey, signer::VapidSignature};

pub mod builder;
mod key;
mod signer;
