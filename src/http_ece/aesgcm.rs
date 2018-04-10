use ring::{aead, hkdf, digest, hmac};
use base64::{self, URL_SAFE_NO_PAD};
use vapid::VapidSignature;
use error::WebPushError;
use http_ece::encryptor::Encryptor;

pub struct AesGcm<'a> {
    peer_public_key: &'a [u8],
    peer_secret: &'a [u8],
    shared_secret: &'a [u8],
    public_key: &'a [u8],
    salt: &'a [u8],
    vapid_signature: Option<VapidSignature>,
}

impl<'a> AesGcm<'a> {
    pub fn new(
        peer_public_key: &'a [u8],
        peer_secret: &'a [u8],
        shared_secret: &'a [u8],
        public_key: &'a [u8],
        salt: &'a [u8],
        vapid_signature: Option<VapidSignature>,
    ) -> AesGcm<'a> {
        AesGcm {
            peer_public_key,
            peer_secret,
            shared_secret,
            public_key,
            salt,
            vapid_signature,
        }
    }
}

impl<'a> Encryptor<'a> for AesGcm<'a> {
    fn encrypt(&self, mut payload: &'a mut [u8]) -> Result<(), WebPushError> {
        let salt               = hmac::SigningKey::new(&digest::SHA256, self.salt);
        let client_auth_secret = hmac::SigningKey::new(&digest::SHA256, self.peer_secret);

        let mut context = Vec::with_capacity(140);
        context.extend_from_slice("P-256\0".as_bytes());
        context.push((self.peer_public_key.len() >> 8) as u8);
        context.push((self.peer_public_key.len() & 0xff) as u8);
        context.extend_from_slice(self.peer_public_key);
        context.push((self.public_key.len() >> 8) as u8);
        context.push((self.public_key.len() & 0xff) as u8);
        context.extend_from_slice(self.public_key);

        let mut ikm = [0u8; 32];
        hkdf::extract_and_expand(
            &client_auth_secret,
            self.shared_secret,
            b"Content-Encoding: auth\0",
            &mut ikm
        );

        let mut cek_info = Vec::with_capacity(165);
        cek_info.extend_from_slice("Content-Encoding: aesgcm\0".as_bytes());
        cek_info.extend_from_slice(&context);

        let mut content_encryption_key = [0u8; 16];
        hkdf::extract_and_expand(
            &salt,
            &ikm,
            &cek_info,
            &mut content_encryption_key
        );

        let mut nonce_info = Vec::with_capacity(164);
        nonce_info.extend_from_slice("Content-Encoding: nonce\0".as_bytes());
        nonce_info.extend_from_slice(&context);

        let mut nonce = [0u8; 12];
        hkdf::extract_and_expand(
            &salt,
            &ikm,
            &nonce_info,
            &mut nonce
        );

        let sealing_key = aead::SealingKey::new(&aead::AES_128_GCM, &content_encryption_key)?;
        aead::seal_in_place(&sealing_key, &nonce, &[], &mut payload, 16)?;

        Ok(())
    }

    fn headers(&self) -> Vec<(&'static str, String)> {
        let mut crypto_headers = Vec::new();

        let mut crypto_key = format!(
            "dh={}",
            base64::encode_config(self.public_key, URL_SAFE_NO_PAD)
        );

        if let Some(ref signature) = self.vapid_signature {
            crypto_key = format!(
                "{}; p256ecdsa={}",
                crypto_key,
                signature.auth_k
            );

            let sig_s = format!("WebPush {}", signature.auth_t);
            crypto_headers.push(("Authorization", sig_s));
        };

        crypto_headers.push(("Crypto-Key", crypto_key));
        crypto_headers.push((
            "Encryption",
            format!("salt={}", base64::encode_config(self.salt, URL_SAFE_NO_PAD))
        ));

        crypto_headers
    }

    fn pad(&self, payload: &'a [u8], padded_output: &'a mut [u8]) {
        let max_payload = padded_output.len() - 2 - 16;
        let padding_size = max_payload - payload.len();

        padded_output[0] = (padding_size >> 8) as u8;
        padded_output[1] = (padding_size & 0xff) as u8;

        for i in 0..payload.len() {
            padded_output[padding_size + i + 2] = payload[i];
        }
    }
}

#[cfg(test)]
mod tests {
    use http_ece::AesGcm;
    use http_ece::Encryptor;
    use base64::{self, URL_SAFE, URL_SAFE_NO_PAD};
    use vapid::VapidSignature;

    #[test]
    fn test_encrypt() {
        let content = "This is test data. XXX".as_bytes();

        let p256dh = base64::decode_config(
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            URL_SAFE
        ).unwrap();

        let auth = base64::decode_config(
            "xS03Fi5ErfTNH_l9WHE9Ig",
            URL_SAFE
        ).unwrap();

        let shared_secret = base64::decode_config(
            "9vcttSQ8tq-Wi_lLQ_xA37tkYssMtJsdY6xENG5f1sE=",
            URL_SAFE
        ).unwrap();

        let as_pubkey = base64::decode_config(
            "BBXpqeMbtt1iwSoYzs7uRL-QVSKTAuAPrunJoNyW2wMKeVBUyNFCqbkmpVTZOVbqWpwpr_-6TpJvk1qT8T-iOYs=",
            URL_SAFE
        ).unwrap();

        let salt_bytes = base64::decode_config(
            "YMcMuxqRkchXwy7vMwNl1Q==",
            URL_SAFE
        ).unwrap();

        let mut payload = [0u8; 38];

        for i in 0..content.len() {
            payload[i] = content[i];
        }

        let aes_gcm = AesGcm::new(
            &p256dh,
            &auth,
            &shared_secret,
            &as_pubkey,
            &salt_bytes,
            None
        );

        aes_gcm.encrypt(&mut payload).unwrap();
        assert_eq!("tmE7-emq6iasohjXNMue0i0vn5o7EIOyP-bKyDoM1teHLcLtg44", base64::encode_config(&payload.to_vec(), URL_SAFE_NO_PAD));
    }

    #[test]
    fn test_headers_with_vapid() {
        let as_pubkey =
            base64::decode_config(
                "BBXpqeMbtt1iwSoYzs7uRL-QVSKTAuAPrunJoNyW2wMKeVBUyNFCqbkmpVTZOVbqWpwpr_-6TpJvk1qT8T-iOYs=",
                URL_SAFE
            ).unwrap();

        let salt_bytes =
            base64::decode_config(
                "YMcMuxqRkchXwy7vMwNl1Q==",
                URL_SAFE
            ).unwrap();

        let p256dh =
            base64::decode_config(
                "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
                URL_SAFE
            ).unwrap();

        let auth = base64::decode_config(
            "xS03Fi5ErfTNH_l9WHE9Ig",
            URL_SAFE
        ).unwrap();

        let shared_secret = base64::decode_config(
            "9vcttSQ8tq-Wi_lLQ_xA37tkYssMtJsdY6xENG5f1sE=",
            URL_SAFE
        ).unwrap();

        let vapid_signature = VapidSignature {
            auth_t: String::from("foo"),
            auth_k: String::from("bar"),
        };

        let aes_gcm = AesGcm::new(
            &p256dh,
            &auth,
            &shared_secret,
            &as_pubkey,
            &salt_bytes,
            Some(vapid_signature),
        );

        let expected_headers = vec![
            ("Authorization", "WebPush foo".to_string()),
            ("Crypto-Key", "dh=BBXpqeMbtt1iwSoYzs7uRL-QVSKTAuAPrunJoNyW2wMKeVBUyNFCqbkmpVTZOVbqWpwpr_-6TpJvk1qT8T-iOYs; p256ecdsa=bar".to_string()),
            ("Encryption", "salt=YMcMuxqRkchXwy7vMwNl1Q".to_string())
        ];

        assert_eq!(expected_headers, aes_gcm.headers());
    }

    #[test]
    fn test_headers_without_vapid() {
        let as_pubkey =
            base64::decode_config(
                "BBXpqeMbtt1iwSoYzs7uRL-QVSKTAuAPrunJoNyW2wMKeVBUyNFCqbkmpVTZOVbqWpwpr_-6TpJvk1qT8T-iOYs=",
                URL_SAFE
            ).unwrap();

        let salt_bytes =
            base64::decode_config(
                "YMcMuxqRkchXwy7vMwNl1Q==",
                URL_SAFE
            ).unwrap();

        let p256dh =
            base64::decode_config(
                "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
                URL_SAFE
            ).unwrap();

        let auth = base64::decode_config(
            "xS03Fi5ErfTNH_l9WHE9Ig",
            URL_SAFE
        ).unwrap();

        let shared_secret = base64::decode_config(
            "9vcttSQ8tq-Wi_lLQ_xA37tkYssMtJsdY6xENG5f1sE=",
            URL_SAFE
        ).unwrap();

        let aes_gcm = AesGcm::new(
            &p256dh,
            &auth,
            &shared_secret,
            &as_pubkey,
            &salt_bytes,
            None,
        );

        let expected_headers = vec![
            ("Crypto-Key", "dh=BBXpqeMbtt1iwSoYzs7uRL-QVSKTAuAPrunJoNyW2wMKeVBUyNFCqbkmpVTZOVbqWpwpr_-6TpJvk1qT8T-iOYs".to_string()),
            ("Encryption", "salt=YMcMuxqRkchXwy7vMwNl1Q".to_string())
        ];

        assert_eq!(expected_headers, aes_gcm.headers());
    }

    #[test]
    fn test_padding() {
        // writes the padding count in the beginning, zeroes, content and again space for the encryption tag
        let content = "naukio";
        let mut output = [0u8; 30];

        AesGcm::pad(content.as_bytes(), &mut output);

        assert_eq!(vec![0, 6, 0, 0, 0, 0, 0, 0, 110, 97, 117, 107, 105, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], output);
    }
}
