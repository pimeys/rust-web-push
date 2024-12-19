//! Payload encryption algorithm

use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use ece::encrypt;

use crate::error::WebPushError;
use crate::message::WebPushPayload;
use crate::vapid::VapidSignature;

/// Content encoding profiles.
#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub enum ContentEncoding {
    //Make sure this enum remains exhaustive as that allows for easier migrations to new versions.
    #[default]
    Aes128Gcm,
    /// Note: this is an older version of ECE, and should not be used unless you know for sure it is required. In all other cases, use aes128gcm.
    AesGcm,
}

impl ContentEncoding {
    /// Gets the associated string for this content encoding, as would be used in the content-encoding header.
    pub fn to_str(&self) -> &'static str {
        match &self {
            ContentEncoding::Aes128Gcm => "aes128gcm",
            ContentEncoding::AesGcm => "aesgcm",
        }
    }
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

                self.add_vapid_headers(&mut headers);

                match result {
                    Ok(data) => Ok(WebPushPayload {
                        content: data,
                        crypto_headers: headers,
                        content_encoding: self.encoding,
                    }),
                    _ => Err(WebPushError::InvalidCryptoKeys),
                }
            }
            ContentEncoding::AesGcm => {
                let result = self.aesgcm_encrypt(content);

                let data = result.map_err(|_| WebPushError::InvalidCryptoKeys)?;

                // Get headers exclusive to the aesgcm scheme (Crypto-Key ect.)
                let mut headers = data.headers(self.vapid_signature.as_ref().map(|v| v.auth_k.as_slice()));

                self.add_vapid_headers(&mut headers);

                // ECE library base64 encodes content in aesgcm, but not aes128gcm, so decode base64 here to match the 128 API
                let data = Base64UrlSafeNoPadding::decode_to_vec(data.body(), None)
                    .expect("ECE library should always base64 encode");

                Ok(WebPushPayload {
                    content: data,
                    crypto_headers: headers,
                    content_encoding: self.encoding,
                })
            }
        }
    }

    /// Adds VAPID authorisation header to headers, if VAPID is being used.
    fn add_vapid_headers(&self, headers: &mut Vec<(&str, String)>) {
        //VAPID uses a special Authorisation header, which contains a ecdhsa key and a jwt.
        if let Some(signature) = &self.vapid_signature {
            headers.push((
                "Authorization",
                format!(
                    "vapid t={}, k={}",
                    signature.auth_t,
                    Base64UrlSafeNoPadding::encode_to_string(&signature.auth_k)
                        .expect("encoding a valid auth_k cannot overflow")
                ),
            ));
        }
    }

    /// Encrypts the content using the aesgcm encoding.
    ///
    /// This is extracted into a function for testing.
    fn aesgcm_encrypt(&self, content: &[u8]) -> ece::Result<ece::legacy::AesGcmEncryptedBlock> {
        ece::legacy::encrypt_aesgcm(self.peer_public_key, self.peer_secret, content)
    }
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    use crate::error::WebPushError;
    use crate::http_ece::{ContentEncoding, HttpEce};
    use crate::VapidSignature;
    use crate::WebPushPayload;
    use ct_codecs::{Base64UrlSafeNoPadding, Decoder};

    #[test]
    fn test_payload_too_big() {
        let p256dh = Base64UrlSafeNoPadding::decode_to_vec(
            "BLMaF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            None,
        )
        .unwrap();
        let auth = Base64UrlSafeNoPadding::decode_to_vec("xS03Fj5ErfTNH_l9WHE9Ig", None).unwrap();
        let http_ece = HttpEce::new(ContentEncoding::Aes128Gcm, &p256dh, &auth, None);
        //This content is one above limit.
        let content = [0u8; 3801];

        assert!(matches!(http_ece.encrypt(&content), Err(WebPushError::PayloadTooLarge)));
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

    /// Tests that the content encryption is properly reversible while using aesgcm.
    #[test]
    fn test_payload_encrypts() {
        let (key, auth) = ece::generate_keypair_and_auth_secret().unwrap();
        let p_key = key.raw_components().unwrap();
        let p_key = p_key.public_key();

        let http_ece = HttpEce::new(ContentEncoding::AesGcm, p_key, &auth, None);
        let plaintext = "Hello world!";
        let ciphertext = http_ece.aesgcm_encrypt(plaintext.as_bytes()).unwrap();

        assert_ne!(plaintext, ciphertext.body());

        assert_eq!(
            String::from_utf8(ece::legacy::decrypt_aesgcm(&key.raw_components().unwrap(), &auth, &ciphertext).unwrap())
                .unwrap(),
            plaintext
        )
    }

    fn setup_payload(vapid_signature: Option<VapidSignature>, encoding: ContentEncoding) -> WebPushPayload {
        let p256dh = Base64UrlSafeNoPadding::decode_to_vec(
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            None,
        )
        .unwrap();
        let auth = Base64UrlSafeNoPadding::decode_to_vec("xS03Fi5ErfTNH_l9WHE9Ig", None).unwrap();

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
    fn test_aesgcm_headers_no_vapid() {
        let wp_payload = setup_payload(None, ContentEncoding::AesGcm);
        assert_eq!(wp_payload.crypto_headers.len(), 2);
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

    #[test]
    fn test_aesgcm_headers_vapid() {
        let auth_re = Regex::new(r"vapid t=(?P<sig_t>[^,]*), k=(?P<sig_k>[^,]*)").unwrap();
        let vapid_signature = VapidSignature {
            auth_t: String::from("foo"),
            auth_k: String::from("bar").into_bytes(),
        };
        let wp_payload = setup_payload(Some(vapid_signature), ContentEncoding::AesGcm);
        // Should have Authorization, Crypto-key, and Encryption
        assert_eq!(wp_payload.crypto_headers.len(), 3);
        let auth = wp_payload.crypto_headers[2].clone();
        assert_eq!(auth.0, "Authorization");
        assert!(auth_re.captures(&auth.1).is_some());
    }
}
