use std::collections::BTreeMap;

use http::uri::Uri;
use jwt_simple::prelude::*;
use serde_json::Value;

use crate::{error::WebPushError, vapid::VapidKey};

/// A struct representing a VAPID signature. Should be generated using the
/// [VapidSignatureBuilder](struct.VapidSignatureBuilder.html).
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VapidSignature {
    /// The signed JWT, base64-encoded
    pub auth_t: String,
    /// The public key bytes
    pub auth_k: Vec<u8>,
}

/// JWT claims object. Custom claims are implemented as a map.
pub type Claims = JWTClaims<BTreeMap<String /*Use String as lifetimes bug out when serializing a tuple*/, Value>>;

pub struct VapidSigner {}

impl VapidSigner {
    /// Create a signature with a given key. Sets the default audience from the
    /// endpoint host and sets the expiry in twelve hours. Values can be
    /// overwritten by adding the `aud` and `exp` claims.
    pub fn sign(key: VapidKey, endpoint: &Uri, mut claims: Claims) -> Result<VapidSignature, WebPushError> {
        if !claims.custom.contains_key("aud") {
            //Add audience if not provided.
            let audience = format!("{}://{}", endpoint.scheme_str().unwrap(), endpoint.host().unwrap());
            claims = claims.with_audience(audience);
        } else {
            //Use provided claims if given. This is here to avoid breaking changes.
            let aud = claims.custom.get("aud").unwrap().clone();
            //NOTE: This as_str is needed, else \" gets added around the string
            claims = claims.with_audience(aud.as_str().ok_or(WebPushError::InvalidClaims)?);
            claims.custom.remove("aud");
        }

        //Override the exp claim if provided in custom. Must then remove from custom to avoid printing
        //Twice, as this is just for backwards compatibility.
        if claims.custom.contains_key("exp") {
            let exp = claims.custom.get("exp").unwrap().clone();
            claims.expires_at = Some(Duration::from_secs(exp.as_u64().ok_or(WebPushError::InvalidClaims)?));
            claims.custom.remove("exp");
        }

        // Add sub if not provided as some browsers (like firefox) require it even though the API doesn't say its needed >:[
        if !claims.custom.contains_key("sub") {
            claims = claims.with_subject("mailto:example@example.com".to_string());
        }

        log::trace!("Using jwt: {:?}", claims);

        let auth_k = key.public_key();

        //Generate JWT signature
        let auth_t = key.0.sign(claims).map_err(|_| WebPushError::InvalidClaims)?;

        Ok(VapidSignature { auth_t, auth_k })
    }
}

#[cfg(test)]
mod tests {}
