use crate::{error::WebPushError, vapid::VapidKey};
use base64::{self, URL_SAFE_NO_PAD};
use http::uri::Uri;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer as SslSigner};
use serde_json::{Number, Value};
use std::collections::BTreeMap;
use time::{self, OffsetDateTime};

lazy_static! {
    /// This is the header of all JWTs.
    static ref JWT_HEADERS: String = base64::encode_config(
        &serde_json::to_string(&json!({"typ": "JWT","alg": "ES256"})).unwrap(),
        URL_SAFE_NO_PAD
    );
}

/// A struct representing a VAPID signature. Should be generated using the
/// [VapidSignatureBuilder](struct.VapidSignatureBuilder.html).
#[derive(Debug)]
pub struct VapidSignature {
    /// The signed JWT, base64 encoded
    pub auth_t: String,
    /// The public key bytes
    pub auth_k: Vec<u8>,
}

pub struct VapidSigner {}

impl VapidSigner {
    /// Create a signature with a given key. Sets the default audience from the
    /// endpoint host and sets the expiry in twelve hours. Values can be
    /// overwritten by adding the `aud` and `exp` claims.
    pub fn sign(
        key: VapidKey,
        endpoint: &Uri,
        mut claims: BTreeMap<&str, Value>,
    ) -> Result<VapidSignature, WebPushError> {
        if !claims.contains_key("aud") {
            let audience = format!("{}://{}", endpoint.scheme_str().unwrap(), endpoint.host().unwrap());
            claims.insert("aud", Value::String(audience));
        }

        if !claims.contains_key("exp") {
            let expiry = OffsetDateTime::now_utc() + time::Duration::hours(12);
            let number = Number::from(expiry.unix_timestamp());
            claims.insert("exp", Value::Number(number));
        }

        //Generate first half of JWT
        let signing_input = format!(
            "{}.{}",
            *JWT_HEADERS,
            base64::encode_config(&serde_json::to_string(&claims)?, URL_SAFE_NO_PAD)
        );

        let auth_k = key.public_key();

        let pkey = PKey::from_ec_key(key.0)?;

        let mut signer = SslSigner::new(MessageDigest::sha256(), &pkey)?;
        signer.update(signing_input.as_bytes())?;

        let signature = signer.sign_to_vec()?;

        let r_off: usize = 3;
        let r_len = signature[r_off] as usize;
        let s_off: usize = r_off + r_len + 2;
        let s_len = signature[s_off] as usize;

        let mut r_val = &signature[(r_off + 1)..(r_off + 1 + r_len)];
        let mut s_val = &signature[(s_off + 1)..(s_off + 1 + s_len)];

        if r_len == 33 && r_val[0] == 0 {
            r_val = &r_val[1..];
        }

        if s_len == 33 && s_val[0] == 0 {
            s_val = &s_val[1..];
        }

        let mut sigval: Vec<u8> = Vec::with_capacity(64);
        sigval.extend(r_val);
        sigval.extend(s_val);

        let auth_t = format!("{}.{}", signing_input, base64::encode_config(&sigval, URL_SAFE_NO_PAD));

        Ok(VapidSignature { auth_t, auth_k })
    }
}

#[cfg(test)]
mod tests {}
