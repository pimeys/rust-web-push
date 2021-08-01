use crate::error::WebPushError;
use crate::message::WebPushPayload;
use crate::vapid::VapidSignature;
use ece::{encrypt, legacy::encrypt_aesgcm};

pub enum ContentEncoding {
    AesGcm,
    Aes128Gcm,
}

pub struct HttpEce<'a> {
    peer_public_key: &'a [u8],
    peer_secret: &'a [u8],
    encoding: ContentEncoding,
    vapid_signature: Option<VapidSignature>,
}

impl<'a> HttpEce<'a> {
    /// Create a new encryptor.
    ///
    /// `peer_public_key` is the `p256dh` and `peer_secret` the `auth` from
    /// browser subscription info.
    pub fn new(
        encoding: ContentEncoding,
        peer_public_key: &'a [u8],
        peer_secret: &'a [u8],
        vapid_signature: Option<VapidSignature>,
    ) -> HttpEce<'a> {
        HttpEce {
            peer_public_key,
            peer_secret,
            encoding,
            vapid_signature,
        }
    }

    /// Encrypts a payload. The maximum length for the payload is 3800
    /// characters, which is the largest that works with Google's and Mozilla's
    /// push servers.
    pub fn encrypt(&self, content: &'a [u8]) -> Result<WebPushPayload, WebPushError> {
        if content.len() > 3052 {
            return Err(WebPushError::PayloadTooLarge);
        }

        match self.encoding {
            ContentEncoding::AesGcm => {
                let encrypted_block = encrypt_aesgcm(self.peer_public_key, self.peer_secret, content)
                    .map_err(|_| WebPushError::InvalidCryptoKeys)?;

                let vapid_public_key = self.vapid_signature.as_ref().map(|sig| sig.auth_k.clone().into_bytes());

                //Ece headers will automatically base64 encode.
                let mut headers = encrypted_block.headers(vapid_public_key.as_deref());

                if let Some(ref signature) = self.vapid_signature {
                    headers.push(("Authorization", format!("WebPush {}", signature.auth_t)));
                };

                Ok(WebPushPayload {
                    content: encrypted_block.body().into_bytes(),
                    crypto_headers: headers,
                    content_encoding: "aesgcm",
                })
            }
            ContentEncoding::Aes128Gcm => {
                let result = encrypt(self.peer_public_key, self.peer_secret, content);

                let mut headers = Vec::new();

                if let Some(signature) = &self.vapid_signature {
                    headers.push((
                        "Authorization",
                        format!(
                            "vapid t={}, k={}",
                            signature.auth_t,
                            base64::encode_config(&signature.auth_k, base64::URL_SAFE_NO_PAD) //Must base64 encode here, as we dont pass to ece.
                        ),
                    ));
                }

                match result {
                    Ok(data) => Ok(WebPushPayload {
                        content: data,
                        crypto_headers: headers,
                        content_encoding: "aes128gcm",
                    }),
                    _ => Err(WebPushError::InvalidCryptoKeys),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::WebPushError;
    use crate::http_ece::{ContentEncoding, HttpEce};
    use crate::VapidSignature;
    use crate::WebPushPayload;
    use base64::{self, URL_SAFE};
    use regex::Regex;

    #[test]
    fn test_payload_too_big() {
        let p256dh = base64::decode_config(
            "BLMaF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            URL_SAFE,
        )
        .unwrap();
        let auth = base64::decode_config("xS03Fj5ErfTNH_l9WHE9Ig", URL_SAFE).unwrap();
        let http_ece = HttpEce::new(ContentEncoding::AesGcm, &p256dh, &auth, None);
        let content = [0u8; 3801];

        assert_eq!(Err(WebPushError::PayloadTooLarge), http_ece.encrypt(&content));
    }

    fn setup_payload(vapid_signature: Option<VapidSignature>, encoding: ContentEncoding) -> WebPushPayload {
        let p256dh = base64::decode_config(
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            URL_SAFE,
        )
        .unwrap();
        let auth = base64::decode_config("xS03Fi5ErfTNH_l9WHE9Ig", URL_SAFE).unwrap();

        let http_ece = HttpEce::new(encoding, &p256dh, &auth, vapid_signature);
        let content = "Hello, world!".as_bytes();

        http_ece.encrypt(content).unwrap()
    }

    fn test_aesgcm_common_headers(vapid_signature: Option<VapidSignature>) -> Option<String> {
        let crypto_re = Regex::new(r"dh=(?P<dh>[^;]*)(?P<vapid>(; p256ecdsa=(?P<ecdsa>.*))?)").unwrap();
        let encryption_re = Regex::new(r"salt=(?P<salt>.*)").unwrap();

        let wp_payload = setup_payload(vapid_signature, ContentEncoding::AesGcm);

        let mut has_enc = false;
        let mut has_crypto = false;
        let mut authorization = None;

        for kvp in &wp_payload.crypto_headers {
            match kvp.0 {
                "Authorization" => authorization = Some(kvp.1.clone()),
                "Crypto-Key" => {
                    assert!(crypto_re.captures(&kvp.1).is_some());
                    has_crypto = true;
                }
                "Encryption" => {
                    assert!(encryption_re.captures(&kvp.1).is_some());
                    let enc_captures = encryption_re.captures(&kvp.1);
                    assert!(enc_captures.is_some());
                    assert!(&enc_captures.unwrap().name("vapid").is_none());
                    has_enc = true;
                }
                _ => {}
            }
        }
        assert!(has_crypto && has_enc);
        authorization
    }

    #[test]
    fn test_aesgcm_headers_no_vapid() {
        let authorization = test_aesgcm_common_headers(None);
        assert!(authorization.is_none());
    }

    #[test]
    fn test_aesgcm_headers_vapid() {
        let auth_re = Regex::new(r"WebPush (?P<sig>.*)").unwrap();
        let vapid_signature = VapidSignature {
            auth_t: String::from("foo"),
            auth_k: String::from("bar"),
        };
        let authorization = test_aesgcm_common_headers(Some(vapid_signature));
        assert!(authorization.is_some());
        let auth_str = authorization.unwrap();
        let auth_cap_opt = auth_re.captures(&auth_str);
        assert!(auth_cap_opt.is_some());
        assert_eq!(&auth_cap_opt.unwrap()["sig"], "foo");
    }

    #[test]
    fn test_aes128gcm_headers_no_vapid() {
        let wp_payload = setup_payload(None, ContentEncoding::Aes128Gcm);
        assert_eq!(wp_payload.crypto_headers.len(), 0);
    }

    #[test]
    fn test_aes128gcm_headers_vapid() {
        let auth_re = Regex::new(r"vapid t=(?P<sig_t>[^,]*), k=(?P<sig_k>[^,]*)").unwrap();
        let vapid_signature = VapidSignature {
            auth_t: String::from("foo"),
            auth_k: String::from("bar"),
        };
        let wp_payload = setup_payload(Some(vapid_signature), ContentEncoding::Aes128Gcm);
        assert_eq!(wp_payload.crypto_headers.len(), 1);
        let auth = wp_payload.crypto_headers[0].clone();
        assert_eq!(auth.0, "Authorization");
        assert!(auth_re.captures(&auth.1).is_some());
    }
}
