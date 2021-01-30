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
                self.merge_headers(&mut headers)?;
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
                Ok(WebPushPayload {
                    content_encoding: "aes128gcm",
                    crypto_headers: HashMap::new(),
                    content: payload,
                })
            }
        }
    }

    pub fn merge_headers(&self, headers: &mut HashMap<String, String>) -> Result<(), WebPushError> {
        match (headers.get("Crypto-Key"), &self.vapid_signature) {
            (None, _) => Err(WebPushError::MissingCryptoKeys),
            (Some(crypto_key), Some(ref signature)) => {
                let merged_key =
                    format!("{}; p256ecdsa={}", crypto_key.to_string(), signature.auth_k);
                headers.insert("Crypto-Key".to_string(), merged_key);
                headers.insert("Authorization".to_string(), signature.into());
                Ok(())
            }
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
    // TODO : adapt tests to new structure
    /*#[test]
    fn test_aes128gcm() {
        let p256dh = base64::decode_config("BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
                                           URL_SAFE).unwrap();
        let auth = base64::decode_config("xS03Fi5ErfTNH_l9WHE9Ig", URL_SAFE).unwrap();

        let http_ece = HttpEce::new(ContentEncoding::Aes128Gcm, &p256dh, &auth, None);
        let content = [0u8; 10];

        assert_eq!(
            Ok(_)), //TODO (ietf?)
            http_ece.encrypt(&content)
        );
    }*/

    /*#[test]
    fn test_headers_with_vapid() {
        let as_pubkey =
            base64::decode_config(
                "BBXpqeMbtt1iwSoYzs7uRL-QVSKTAuAPrunJoNyW2wMKeVBUyNFCqbkmpVTZOVbqWpwpr_-6TpJvk1qT8T-iOYs=",
                URL_SAFE
            ).unwrap();

        let salt_bytes = base64::decode_config("YMcMuxqRkchXwy7vMwNl1Q==", URL_SAFE).unwrap();

        let p256dh =
            base64::decode_config(
                "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
                URL_SAFE
            ).unwrap();

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

        let payload = http_ece.encrypt("Hello, world!".as_bytes()).unwrap();

        assert_eq!(
            vec![
                ("Authorization".to_string(), "WebPush foo".to_string()),
                ("Crypto-Key".to_string(), "dh=BBXpqeMbtt1iwSoYzs7uRL-QVSKTAuAPrunJoNyW2wMKeVBUyNFCqbkmpVTZOVbqWpwpr_-6TpJvk1qT8T-iOYs; p256ecdsa=bar".to_string()),
                ("Encryption".to_string(), "salt=YMcMuxqRkchXwy7vMwNl1Q".to_string())],
            payload.crypto_headers)
    }

    #[test]
    fn test_headers_without_vapid() {
        let as_pubkey =
            base64::decode_config(
                "BBXpqeMbtt1iwSoYzs7uRL-QVSKTAuAPrunJoNyW2wMKeVBUyNFCqbkmpVTZOVbqWpwpr_-6TpJvk1qT8T-iOYs=",
                URL_SAFE
            ).unwrap();

        let salt_bytes = base64::decode_config("YMcMuxqRkchXwy7vMwNl1Q==", URL_SAFE).unwrap();

        let p256dh =
            base64::decode_config(
                "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
                URL_SAFE
            ).unwrap();

        let auth = base64::decode_config("xS03Fi5ErfTNH_l9WHE9Ig", URL_SAFE).unwrap();

        let http_ece = HttpEce::new(ContentEncoding::AesGcm, &p256dh, &auth, None);

        let payload = http_ece.encrypt("Hello, world!".as_bytes()).unwrap();

        assert_eq!(
            vec![
                ("Crypto-Key".to_string(), "dh=BBXpqeMbtt1iwSoYzs7uRL-QVSKTAuAPrunJoNyW2wMKeVBUyNFCqbkmpVTZOVbqWpwpr_-6TpJvk1qT8T-iOYs".to_string()),
                ("Encryption".to_string(), "salt=YMcMuxqRkchXwy7vMwNl1Q".to_string())],
            payload.crypto_headers)
    }*/
}
