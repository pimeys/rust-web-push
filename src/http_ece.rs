use std::collections::HashMap;

use crate::error::WebPushError;
use crate::message::WebPushPayload;
use crate::vapid::VapidSignature;
use ece::{encrypt as encrypt_aes128gcm, legacy::encrypt_aesgcm};
use ring::rand;
use ring::rand::SecureRandom;

pub enum ContentEncoding {
    AesGcm,
    Aes128Gcm,
}

pub struct HttpEce<'a> {
    peer_public_key: &'a [u8],
    peer_secret: &'a [u8],
    encoding: ContentEncoding,
    rng: rand::SystemRandom,
    vapid_signature: Option<VapidSignature>,
}

impl<'a> HttpEce<'a> {
    /// Create a new encryptor. The content encoding has preliminary support for
    /// Aes128Gcm, which is the 8th draft of the Encrypted Content-Encoding, but
    /// currently using it will return an error when trying to encrypt. There is
    /// no real support yet for the encoding in web browsers.
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
            rng: rand::SystemRandom::new(),
            peer_public_key: peer_public_key,
            peer_secret: peer_secret,
            encoding: encoding,
            vapid_signature: vapid_signature,
        }
    }

    /// Encrypts a payload. The maximum length for the payload is 3800
    /// characters, which is the largest that works with Google's and Mozilla's
    /// push servers.
    pub fn encrypt(&self, content: &'a [u8]) -> Result<WebPushPayload, WebPushError> {
        if content.len() > 3052 {
            return Err(WebPushError::PayloadTooLarge);
        }
        let mut salt_bytes = [0u8; 16];
        self.rng.fill(&mut salt_bytes)?;

        match self.encoding {
            ContentEncoding::AesGcm => {
                let encrypted_block =
                    encrypt_aesgcm(self.peer_public_key, self.peer_secret, &salt_bytes, content)
                        .map_err(|_| WebPushError::InvalidCryptoKeys)?;
                let payload = encrypted_block.ciphertext.to_owned();
                let mut headers = encrypted_block.headers();
                self.merge_headers(&mut headers, ContentEncoding::AesGcm)?;
                Ok(WebPushPayload {
                    content_encoding: "aesgcm",
                    crypto_headers: headers,
                    content: payload,
                })
            }
            ContentEncoding::Aes128Gcm => {
                let payload =
                    encrypt_aes128gcm(self.peer_public_key, self.peer_secret, &salt_bytes, content)
                        .map_err(|_| WebPushError::InvalidCryptoKeys)?;
                let mut headers = HashMap::new();
                self.merge_headers(&mut headers, ContentEncoding::Aes128Gcm)?;
                Ok(WebPushPayload {
                    content_encoding: "aes128gcm",
                    crypto_headers: headers,
                    content: payload,
                })
            }
        }
    }

    pub fn merge_headers(&self, headers: &mut HashMap<String, String>, encoding : ContentEncoding) -> Result<(), WebPushError> {
        match (encoding,&self.vapid_signature) {
            (ContentEncoding::Aes128Gcm, Some(signature)) => {
                headers.insert("Authorization".to_string(), format!("vapid t={}, k={}",signature.auth_t,signature.auth_k));
                Ok(())
            },
            (ContentEncoding::AesGcm, Some(ref signature)) => {
                if let Some(crypto_key) = headers.get("Crypto-Key") {
                    let merged_key =
                        format!("{}; p256ecdsa={}", crypto_key.to_string(), signature.auth_k);
                    headers.insert("Crypto-Key".to_string(), merged_key);
                    headers.insert("Authorization".to_string(), signature.into());
                    Ok(())
                }
                else {
                    Err(WebPushError::InvalidCryptoKeys)
                }
            },
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::WebPushError;
    use crate::http_ece::{ContentEncoding, HttpEce};
    use crate::vapid::VapidSignature;
    use base64::{self, URL_SAFE};
    use regex::Regex;

    #[test]
    fn test_payload_too_big() {
        let p256dh = base64::decode_config("BLMaF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
                                           URL_SAFE).unwrap();
        let auth = base64::decode_config("xS03Fj5ErfTNH_l9WHE9Ig", URL_SAFE).unwrap();
        let http_ece = HttpEce::new(ContentEncoding::AesGcm, &p256dh, &auth, None);
        let content = [0u8; 3801];

        assert_eq!(
            Err(WebPushError::PayloadTooLarge),
            http_ece.encrypt(&content)
        );
    }

    #[test]
    fn test_aesgcm_headers_without_vapid() {
        let crypto_re =
            Regex::new(r"dh=(?P<dh>[^;]*)(?P<vapid>(; p256ecdsa=(?P<ecdsa>.*))?)").unwrap();
        let encryption_re = Regex::new(r"salt=(?P<salt>.*)").unwrap();

        let p256dh = base64::decode_config("BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
                                           URL_SAFE).unwrap();
        let auth = base64::decode_config("xS03Fi5ErfTNH_l9WHE9Ig", URL_SAFE).unwrap();

        let http_ece = HttpEce::new(ContentEncoding::AesGcm, &p256dh, &auth, None);
        let content = "Hello, world!".as_bytes();

        let wp_payload = http_ece.encrypt(content).unwrap();

        let crypto_cap_opt = crypto_re.captures(&wp_payload.crypto_headers["Crypto-Key"]);
        let encryption_cap_opt = encryption_re.captures(&wp_payload.crypto_headers["Encryption"]);

        assert!(&wp_payload.crypto_headers.get("Authorization").is_none());
        assert!(crypto_cap_opt.is_some());
        assert!(encryption_cap_opt.is_some());
        let crypto_cap = crypto_cap_opt.unwrap();
        assert_eq!(&crypto_cap["vapid"], "");
    }

    #[test]
    fn test_aesgcm_headers_with_vapid() {
        let crypto_re =
            Regex::new(r"dh=(?P<dh>[^;]*)(?P<vapid>(; p256ecdsa=(?P<ecdsa>.*))?)").unwrap();
        let encryption_re = Regex::new(r"salt=(?P<salt>.*)").unwrap();
        let auth_re = Regex::new(r"WebPush (?P<sig>.*)").unwrap();

        let p256dh = base64::decode_config("BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
                                           URL_SAFE).unwrap();
        let auth = base64::decode_config("xS03Fi5ErfTNH_l9WHE9Ig", URL_SAFE).unwrap();

        let vapid_signature = VapidSignature {
            auth_t: String::from("foo"),
            auth_k: String::from("bar"),
        };

        let http_ece = HttpEce::new(
            ContentEncoding::AesGcm,
            &p256dh,
            &auth,
            Some(vapid_signature),
        );
        let content = "Hello, world!".as_bytes();

        let wp_payload = http_ece.encrypt(content).unwrap();

        let crypto_cap_opt = crypto_re.captures(&wp_payload.crypto_headers["Crypto-Key"]);
        let encryption_cap_opt = encryption_re.captures(&wp_payload.crypto_headers["Encryption"]);
        let auth_cap_opt = auth_re.captures(&wp_payload.crypto_headers["Authorization"]);

        assert!(crypto_cap_opt.is_some());
        assert!(encryption_cap_opt.is_some());
        assert!(auth_cap_opt.is_some());
        let crypto_cap = crypto_cap_opt.unwrap();
        assert_eq!(&crypto_cap["ecdsa"], "bar");
        assert_eq!(&auth_cap_opt.unwrap()["sig"], "foo");
    }

    #[test]
    fn test_aes128gcm_headers_without_vapid() {
        let crypto_re =
            Regex::new(r"dh=(?P<dh>[^;]*)(?P<vapid>(; p256ecdsa=(?P<ecdsa>.*))?)").unwrap();
        let encryption_re = Regex::new(r"salt=(?P<salt>.*)").unwrap();

        let p256dh = base64::decode_config("BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
                                           URL_SAFE).unwrap();
        let auth = base64::decode_config("xS03Fi5ErfTNH_l9WHE9Ig", URL_SAFE).unwrap();

        let http_ece = HttpEce::new(ContentEncoding::AesGcm, &p256dh, &auth, None);
        let content = "Hello, world!".as_bytes();

        let wp_payload = http_ece.encrypt(content).unwrap();

        let crypto_cap_opt = crypto_re.captures(&wp_payload.crypto_headers["Crypto-Key"]);
        let encryption_cap_opt = encryption_re.captures(&wp_payload.crypto_headers["Encryption"]);

        assert!(&wp_payload.crypto_headers.get("Authorization").is_none());
        assert!(crypto_cap_opt.is_some());
        assert!(encryption_cap_opt.is_some());
        let crypto_cap = crypto_cap_opt.unwrap();
        assert_eq!(&crypto_cap["vapid"], "");
    }

    #[test]
    fn test_aes128gcm_headers_with_vapid() {
        let crypto_re =
            Regex::new(r"(?P<vapid>(p256ecdsa=(?P<ecdsa>.*))?)").unwrap();
        let encryption_re = Regex::new(r"salt=(?P<salt>.*)").unwrap();
        let auth_re = Regex::new(r"WebPush (?P<sig>.*)").unwrap();

        let p256dh = base64::decode_config("BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
                                           URL_SAFE).unwrap();
        let auth = base64::decode_config("xS03Fi5ErfTNH_l9WHE9Ig", URL_SAFE).unwrap();

        let vapid_signature = VapidSignature {
            auth_t: String::from("foo"),
            auth_k: String::from("bar"),
        };

        let http_ece = HttpEce::new(
            ContentEncoding::Aes128Gcm,
            &p256dh,
            &auth,
            Some(vapid_signature),
        );
        let content = "Hello, world!".as_bytes();

        let wp_payload = http_ece.encrypt(content).unwrap();

        let crypto_cap_opt = crypto_re.captures(&wp_payload.crypto_headers["Crypto-Key"]);
        let encryption_cap_opt = encryption_re.captures(&wp_payload.crypto_headers["Encryption"]);
        let auth_cap_opt = auth_re.captures(&wp_payload.crypto_headers["Authorization"]);

        assert!(crypto_cap_opt.is_some());
        assert!(encryption_cap_opt.is_some());
        assert!(auth_cap_opt.is_some());
        let crypto_cap = crypto_cap_opt.unwrap();
        assert_eq!(&crypto_cap["ecdsa"], "bar");
        assert_eq!(&auth_cap_opt.unwrap()["sig"], "foo");
    }
}
