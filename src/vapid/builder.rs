use crate::error::WebPushError;
use crate::message::SubscriptionInfo;
use crate::vapid::{VapidKey, VapidSignature, VapidSigner};
use hyper::Uri;
use openssl::ec::EcKey;
use openssl::pkey::Private;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Read;

/// A VAPID signature builder for generating an optional signature to the
/// request. With a given signature, one can pass the registration to Google's
/// FCM service. And prevent unauthorized notifications to be sent to the client.
///
/// To communicate with the site, one needs to generate a private key to keep in
/// the server and derive a public key from the generated private key to the
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
/// To create a VAPID signature:
///
/// ```no_run
/// # extern crate web_push;
/// # use web_push::*;
/// # use std::fs::File;
/// # fn main () {
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
    pub fn from_pem<R: Read>(
        mut pk_pem: R,
        subscription_info: &'a SubscriptionInfo,
    ) -> Result<VapidSignatureBuilder<'a>, WebPushError> {
        let mut pem_key: Vec<u8> = Vec::new();
        pk_pem.read_to_end(&mut pem_key)?;

        Ok(Self::from_ec(EcKey::private_key_from_pem(&pem_key)?, subscription_info))
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

#[cfg(test)]
mod tests {
    use crate::message::SubscriptionInfo;
    use crate::vapid::VapidSignatureBuilder;
    use serde_json;
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
            &signature.auth_k
        );

        assert!(!signature.auth_t.is_empty());
    }

    #[test]
    fn test_builder_from_der() {
        let builder = VapidSignatureBuilder::from_der(&*PRIVATE_DER, &*SUBSCRIPTION_INFO).unwrap();
        let signature = builder.build().unwrap();

        assert_eq!(
            "BMo1HqKF6skMZYykrte9duqYwBD08mDQKTunRkJdD3sTJ9E-yyN6sJlPWTpKNhp-y2KeS6oANHF-q3w37bClb7U",
            &signature.auth_k
        );

        assert!(!signature.auth_t.is_empty());
    }
}
