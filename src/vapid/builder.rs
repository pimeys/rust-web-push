use crate::error::WebPushError;
use crate::message::SubscriptionInfo;
use crate::vapid::{VapidKey, VapidSignature, VapidSigner};
use http::uri::Uri;
use openssl::ec::EcKey;
use openssl::pkey::Private;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Read;

/// A VAPID signature builder for generating an optional signature to the
/// request. This encryption is required for payloads in all current and future browsers.
///
/// To communicate with the site, one needs to generate a private key to keep in
/// the server and derive a public key from the generated private key for the
/// client.
///
/// Private key generation:
///
/// ```bash,ignore
/// openssl ecparam -name prime256v1 -genkey -noout -out private.pem
/// ```
///
/// To derive a public key out of generated private key:
///
/// ```bash,ignore
/// openssl ec -in private.pem -pubout -out vapid_public.pem
/// ```
///
/// To get the byte form of the public key for the JavaScript client:
///
/// ```bash,ignore
/// openssl ec -in private.pem -text -noout -conv_form uncompressed
/// ```
///
/// ... or a base64 encoded string, which the client should convert into
/// byte form before using:
///
/// ```bash,ignore
/// openssl ec -in private.pem -pubout -outform DER|tail -c 65|base64|tr '/+' '_-'|tr -d '\n'
/// ```
///
/// The above commands can be done in code using a library such as openssl if you prefer.
///
/// To create a VAPID signature:
///
/// ```no_run
/// # extern crate web_push;
/// # use web_push::*;
/// # use std::fs::File;
/// # fn main () {
/// //You would get this as a `pushSubscription` object from the client. They need your public key to get that object.
/// let subscription_info = SubscriptionInfo {
///     keys: SubscriptionKeys {
///         p256dh: String::from("something"),
///         auth: String::from("secret"),
///     },
///     endpoint: String::from("https://mozilla.rules/something"),
/// };
///
/// let file = File::open("private.pem").unwrap();
///
/// let mut sig_builder = VapidSignatureBuilder::from_pem(file, &subscription_info).unwrap();
///
/// //These fields are optional, and likely unneeded for most uses.
/// sig_builder.add_claim("sub", "mailto:test@example.com");
/// sig_builder.add_claim("foo", "bar");
/// sig_builder.add_claim("omg", 123);
///
/// let signature = sig_builder.build().unwrap();
/// # }
/// ```

pub struct VapidSignatureBuilder<'a> {
    claims: BTreeMap<&'a str, Value>,
    key: VapidKey,
    subscription_info: &'a SubscriptionInfo,
}

impl<'a> VapidSignatureBuilder<'a> {
    /// Creates a new builder from a PEM formatted private key.
    ///
    /// # Details
    ///
    /// This should be the raw private key PEM, including the -----BEGIN EC PRIVATE KEY----- header.
    /// If you have a public and private key in the same PEM, the function will still work.
    pub fn from_pem<R: Read>(
        mut pk_pem: R,
        subscription_info: &'a SubscriptionInfo,
    ) -> Result<VapidSignatureBuilder<'a>, WebPushError> {
        let mut pem_key: Vec<u8> = Vec::new();
        pk_pem.read_to_end(&mut pem_key)?;

        let pr_key = EcKey::private_key_from_pem(&pem_key)?;

        Ok(Self::from_ec(pr_key, subscription_info))
    }

    /// Creates a new builder from a PEM formatted private key. This function doesn't take a subscription,
    /// allowing the reuse of one builder for multiple messages by cloning the resulting builder.
    ///
    /// # Details
    ///
    /// This should be the raw private key PEM, including the -----BEGIN EC PRIVATE KEY----- header.
    /// If you have a public and private key in the same PEM, the function will still work.
    pub fn from_pem_no_sub<R: Read>(mut pk_pem: R) -> Result<PartialVapidSignatureBuilder, WebPushError> {
        let mut pem_key: Vec<u8> = Vec::new();
        pk_pem.read_to_end(&mut pem_key)?;

        let pr_key = EcKey::private_key_from_pem(&pem_key)?;

        Ok(PartialVapidSignatureBuilder {
            key: VapidKey::new(pr_key),
        })
    }

    /// Creates a new builder from a DER formatted private key.
    pub fn from_der<R: Read>(
        mut pk_der: R,
        subscription_info: &'a SubscriptionInfo,
    ) -> Result<VapidSignatureBuilder<'a>, WebPushError> {
        let mut der_key: Vec<u8> = Vec::new();
        pk_der.read_to_end(&mut der_key)?;

        Ok(Self::from_ec(EcKey::private_key_from_der(&der_key)?, subscription_info))
    }

    /// Creates a new builder from a DER formatted private key. This function doesn't take a subscription,
    /// allowing the reuse of one builder for multiple messages by cloning the resulting builder.
    pub fn from_der_no_sub<R: Read>(mut pk_der: R) -> Result<PartialVapidSignatureBuilder, WebPushError> {
        let mut der_key: Vec<u8> = Vec::new();
        pk_der.read_to_end(&mut der_key)?;

        Ok(PartialVapidSignatureBuilder {
            key: VapidKey::new(EcKey::private_key_from_der(&der_key)?),
        })
    }

    /// Add a claim to the signature. Claims `aud` and `exp` are automatically
    /// added to the signature. Add them manually to override the default
    /// values.
    ///
    /// The function accepts any value that can be converted into a type JSON
    /// supports.
    pub fn add_claim<V>(&mut self, key: &'a str, val: V)
    where
        V: Into<Value>,
    {
        self.claims.insert(key, val.into());
    }

    /// Builds a signature to be used in [WebPushMessageBuilder](struct.WebPushMessageBuilder.html).
    pub fn build(self) -> Result<VapidSignature, WebPushError> {
        let endpoint: Uri = self.subscription_info.endpoint.parse()?;
        let signature = VapidSigner::sign(self.key, &endpoint, self.claims)?;

        Ok(signature)
    }

    fn from_ec(ec_key: EcKey<Private>, subscription_info: &'a SubscriptionInfo) -> VapidSignatureBuilder<'a> {
        VapidSignatureBuilder {
            claims: BTreeMap::new(),
            key: VapidKey::new(ec_key),
            subscription_info,
        }
    }
}

/// A [`VapidSignatureBuilder`] without VAPID subscription info.
///
/// # Example
///
/// ```no_run
/// use web_push::{VapidSignatureBuilder, SubscriptionInfo};
///
/// let builder = VapidSignatureBuilder::from_pem_no_sub("Some PEM".as_bytes()).unwrap();
///
/// //Clone builder for each use of the same private key
/// {
///     //Pretend this changes for each connection
///     let subscription_info = SubscriptionInfo::new(
///     "https://updates.push.services.mozilla.com/wpush/v1/...",
///     "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
///     "xS03Fi5ErfTNH_l9WHE9Ig"
///     );
///
///     let builder = builder.clone();
///     let sig = builder.add_sub_info(&subscription_info).build();
///     //Sign message ect.
/// }
///
/// ```
#[derive(Clone)]
pub struct PartialVapidSignatureBuilder {
    key: VapidKey,
}

impl<'a> PartialVapidSignatureBuilder {
    /// Adds the VAPID subscription info for a particular client.
    pub fn add_sub_info(self, subscription_info: &'a SubscriptionInfo) -> VapidSignatureBuilder {
        VapidSignatureBuilder {
            key: self.key,
            claims: BTreeMap::new(),
            subscription_info,
        }
    }

    /// Gets the public key bytes derived from the private key used for this VAPID signature.
    ///
    /// Base64 encode these bytes to get the key to send to the client.
    pub fn get_public_key(&self) -> Vec<u8> {
        self.key.public_key()
    }
}

#[cfg(test)]
mod tests {
    use crate::message::SubscriptionInfo;
    use crate::vapid::VapidSignatureBuilder;
    use std::fs::File;

    lazy_static! {
        static ref PRIVATE_PEM: File = File::open("resources/vapid_test_key.pem").unwrap();
        static ref PRIVATE_DER: File = File::open("resources/vapid_test_key.der").unwrap();
    }

    lazy_static! {
        static ref SUBSCRIPTION_INFO: SubscriptionInfo =
            serde_json::from_value(
                json!({
                    "endpoint": "https://updates.push.services.mozilla.com/wpush/v2/gAAAAABaso4Vajy4STM25r5y5oFfyN451rUmES6mhQngxABxbZB5q_o75WpG25oKdrlrh9KdgWFKdYBc-buLPhvCTqR5KdsK8iCZHQume-ndtZJWKOgJbQ20GjbxHmAT1IAv8AIxTwHO-JTQ2Np2hwkKISp2_KUtpnmwFzglLP7vlCd16hTNJ2I",
                    "keys": {
                        "auth": "sBXU5_tIYz-5w7G2B25BEw",
                        "p256dh": "BH1HTeKM7-NwaLGHEqxeu2IamQaVVLkcsFHPIHmsCnqxcBHPQBprF41bEMOr3O1hUQ2jU1opNEm1F_lZV_sxMP8"
                    }
                })
            ).unwrap();
    }

    #[test]
    fn test_builder_from_pem() {
        let builder = VapidSignatureBuilder::from_pem(&*PRIVATE_PEM, &*SUBSCRIPTION_INFO).unwrap();
        let signature = builder.build().unwrap();

        assert_eq!(
            "BMo1HqKF6skMZYykrte9duqYwBD08mDQKTunRkJdD3sTJ9E-yyN6sJlPWTpKNhp-y2KeS6oANHF-q3w37bClb7U",
            base64::encode_config(&signature.auth_k, base64::URL_SAFE_NO_PAD)
        );

        assert!(!signature.auth_t.is_empty());
    }

    #[test]
    fn test_builder_from_der() {
        let builder = VapidSignatureBuilder::from_der(&*PRIVATE_DER, &*SUBSCRIPTION_INFO).unwrap();
        let signature = builder.build().unwrap();

        assert_eq!(
            "BMo1HqKF6skMZYykrte9duqYwBD08mDQKTunRkJdD3sTJ9E-yyN6sJlPWTpKNhp-y2KeS6oANHF-q3w37bClb7U",
            base64::encode_config(&signature.auth_k, base64::URL_SAFE_NO_PAD)
        );

        assert!(!signature.auth_t.is_empty());
    }
}
