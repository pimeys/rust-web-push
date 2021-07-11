use crate::error::WebPushError;
use crate::message::WebPushPayload;
use crate::vapid::VapidSignature;
use ece::{legacy::encrypt_aesgcm,encrypt};

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
        let mut payload = vec![0; 3054];
        front_pad(content, &mut payload);
        
        match self.encoding {
            ContentEncoding::AesGcm => {
                let encrypted_block = encrypt_aesgcm(self.peer_public_key,self.peer_secret, &payload).map_err(|_| WebPushError::InvalidCryptoKeys)?;
                let vapid_public_key = match &self.vapid_signature {
                    None => None,
                    Some(sig) => Some(sig.auth_k.clone().into_bytes()),
                };
                Ok(WebPushPayload {
                    content: encrypted_block.body().into_bytes(),
                    crypto_headers: encrypted_block.headers(vapid_public_key.as_deref()),
                    content_encoding: "aesgcm",
                })
            }
            ContentEncoding::Aes128Gcm => {
                let result = encrypt(self.peer_public_key, self.peer_secret, &payload);
                match result {
                    Ok(data) => Ok(WebPushPayload {
                        content: data,
                        crypto_headers: self.generate_headers_aes128gcm(),
                        content_encoding: "aes128gcm",
                    }),
                    _ => Err(WebPushError::InvalidCryptoKeys)
                }
            },
        }
    }

    pub fn generate_headers_aes128gcm(&self) -> Vec<(&'static str, String)> {
        let mut headers = Vec::new();
        if let Some(signature) = &self.vapid_signature {
            headers.push((
                "Authorization",
                format!("vapid t={}, k={}", signature.auth_t, signature.auth_k),
            ));
        }
        headers
    }
}

fn front_pad(payload: &[u8], output: &mut [u8]) {
    let payload_len = payload.len();
    let max_payload = output.len() - 2;
    let padding_size = max_payload - payload.len();

    output[0] = (padding_size >> 8) as u8;
    output[1] = (padding_size & 0xff) as u8;

    for i in 0..payload_len {
        output[padding_size + i + 2] = payload[i];
    }
}

#[cfg(test)]
mod tests {
    use crate::error::WebPushError;
    use crate::http_ece::{ContentEncoding, HttpEce};
    use crate::vapid::VapidSignature;
    use base64::{self, URL_SAFE, URL_SAFE_NO_PAD};
    use super::front_pad;

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

    #[test]
    fn test_aes128gcm() {
        let p256dh = base64::decode_config(
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            URL_SAFE,
        )
        .unwrap();
        let auth = base64::decode_config("xS03Fi5ErfTNH_l9WHE9Ig", URL_SAFE).unwrap();

        let http_ece = HttpEce::new(ContentEncoding::Aes128Gcm, &p256dh, &auth, None);
        let content = [0u8; 10];

        assert_eq!(Err(WebPushError::NotImplemented), http_ece.encrypt(&content));
    }

    #[test]
    fn test_aesgcm() {
        let p256dh = base64::decode_config(
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            URL_SAFE,
        )
        .unwrap();
        let auth = base64::decode_config("xS03Fi5ErfTNH_l9WHE9Ig", URL_SAFE).unwrap();
        let http_ece = HttpEce::new(ContentEncoding::AesGcm, &p256dh, &auth, None);
        let shared_secret = base64::decode_config("9vcttSQ8tq-Wi_lLQ_xA37tkYssMtJsdY6xENG5f1sE=", URL_SAFE).unwrap();
        let as_pubkey = base64::decode_config(
            "BBXpqeMbtt1iwSoYzs7uRL-QVSKTAuAPrunJoNyW2wMKeVBUyNFCqbkmpVTZOVbqWpwpr_-6TpJvk1qT8T-iOYs=",
            URL_SAFE,
        )
        .unwrap();
        let salt_bytes = base64::decode_config("YMcMuxqRkchXwy7vMwNl1Q==", URL_SAFE).unwrap();

        let mut payload = "This is test data. XXX".as_bytes().to_vec();

        http_ece
            .aes_gcm(&shared_secret, &as_pubkey, &salt_bytes, &mut payload)
            .unwrap();
        assert_eq!(
            "tmE7-emq6iasohjXNMue0i0vn5o7EIOyP-bKyDoM1teHLcLtg44",
            base64::encode_config(&payload.to_vec(), URL_SAFE_NO_PAD)
        );
    }

    #[test]
    fn test_headers_with_vapid() {
        let as_pubkey = base64::decode_config(
            "BBXpqeMbtt1iwSoYzs7uRL-QVSKTAuAPrunJoNyW2wMKeVBUyNFCqbkmpVTZOVbqWpwpr_-6TpJvk1qT8T-iOYs=",
            URL_SAFE,
        )
        .unwrap();

        let salt_bytes = base64::decode_config("YMcMuxqRkchXwy7vMwNl1Q==", URL_SAFE).unwrap();

        let p256dh = base64::decode_config(
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            URL_SAFE,
        )
        .unwrap();

        let auth = base64::decode_config("xS03Fi5ErfTNH_l9WHE9Ig", URL_SAFE).unwrap();

        let vapid_signature = VapidSignature {
            auth_t: String::from("foo"),
            auth_k: String::from("bar"),
        };

        let http_ece = HttpEce::new(ContentEncoding::AesGcm, &p256dh, &auth, Some(vapid_signature));

        assert_eq!(
            vec![
                ("Authorization", "WebPush foo".to_string()),
                ("Crypto-Key", "dh=BBXpqeMbtt1iwSoYzs7uRL-QVSKTAuAPrunJoNyW2wMKeVBUyNFCqbkmpVTZOVbqWpwpr_-6TpJvk1qT8T-iOYs; p256ecdsa=bar".to_string()),
                ("Encryption", "salt=YMcMuxqRkchXwy7vMwNl1Q".to_string())],
            http_ece.generate_headers(&as_pubkey, &salt_bytes))
    }

    #[test]
    fn test_headers_without_vapid() {
        let as_pubkey = base64::decode_config(
            "BBXpqeMbtt1iwSoYzs7uRL-QVSKTAuAPrunJoNyW2wMKeVBUyNFCqbkmpVTZOVbqWpwpr_-6TpJvk1qT8T-iOYs=",
            URL_SAFE,
        )
        .unwrap();

        let salt_bytes = base64::decode_config("YMcMuxqRkchXwy7vMwNl1Q==", URL_SAFE).unwrap();

        let p256dh = base64::decode_config(
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            URL_SAFE,
        )
        .unwrap();

        let auth = base64::decode_config("xS03Fi5ErfTNH_l9WHE9Ig", URL_SAFE).unwrap();

        let http_ece = HttpEce::new(ContentEncoding::AesGcm, &p256dh, &auth, None);

        assert_eq!(
            vec![
                (
                    "Crypto-Key",
                    "dh=BBXpqeMbtt1iwSoYzs7uRL-QVSKTAuAPrunJoNyW2wMKeVBUyNFCqbkmpVTZOVbqWpwpr_-6TpJvk1qT8T-iOYs"
                        .to_string()
                ),
                ("Encryption", "salt=YMcMuxqRkchXwy7vMwNl1Q".to_string())
            ],
            http_ece.generate_headers(&as_pubkey, &salt_bytes)
        )
    }

    #[test]
    fn test_front_pad() {
        // writes the padding count in the beginning, zeroes, content and again space for the encryption tag
        let content = "naukio";
        let mut output = [0u8; 30];

        front_pad(content.as_bytes(), &mut output);

        assert_eq!(
            vec![0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 110, 97, 117, 107, 105, 111],
            output
        );
    }
}
