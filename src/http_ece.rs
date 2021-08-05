use crate::error::WebPushError;
use crate::message::WebPushPayload;
use crate::vapid::VapidSignature;
use ece::encrypt;

/// Content encoding profiles.
pub enum ContentEncoding {
    //Make sure this enum remains exhaustive as that allows for easier migrations to new versions.
    Aes128Gcm,
}

/// Struct for handling payload encryption.
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

        //Add more encoding standards to this match as they are created.
        match self.encoding {
            ContentEncoding::Aes128Gcm => {
                let result = encrypt(self.peer_public_key, self.peer_secret, content);

                let mut headers = Vec::new();

                if let Some(signature) = &self.vapid_signature {
                    headers.push((
                        "Authorization",
                        format!(
                            "vapid t={}, k={}",
                            signature.auth_t,
                            base64::encode_config(&signature.auth_k, base64::URL_SAFE_NO_PAD)
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
        let http_ece = HttpEce::new(ContentEncoding::Aes128Gcm, &p256dh, &auth, None);
        //This content is one above limit.
        let content = [0u8; 3801];

        assert_eq!(Err(WebPushError::PayloadTooLarge), http_ece.encrypt(&content));
    }

    /// Tests that the content encryption is properly reversible while using aes128gcm.
    #[test]
    fn test_payload_encrypts_128() {
        let (key, auth) = ece::generate_keypair_and_auth_secret().unwrap();
        let p_key = key.raw_components().unwrap();
        let p_key = p_key.public_key();

        let http_ece = HttpEce::new(ContentEncoding::Aes128Gcm, p_key, &auth, None);
        let plaintext = "Hello world!";
        let ciphertext = http_ece.encrypt(plaintext.as_bytes()).unwrap();

        assert_ne!(plaintext.as_bytes(), ciphertext.content);

        assert_eq!(
            String::from_utf8(ece::decrypt(&key.raw_components().unwrap(), &auth, &ciphertext.content).unwrap())
                .unwrap(),
            plaintext
        )
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
            auth_k: String::from("bar").into_bytes(),
        };
        let wp_payload = setup_payload(Some(vapid_signature), ContentEncoding::Aes128Gcm);
        assert_eq!(wp_payload.crypto_headers.len(), 1);
        let auth = wp_payload.crypto_headers[0].clone();
        assert_eq!(auth.0, "Authorization");
        assert!(auth_re.captures(&auth.1).is_some());
    }
}
