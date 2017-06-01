use ring::{hmac, hkdf, agreement, rand, digest, aead};
use ring::rand::SecureRandom;
use untrusted::Input;
use error::WebPushError;
use message::WebPushPayload;
use rustc_serialize::base64::{ToBase64, URL_SAFE};

pub enum ContentEncoding {
    AesGcm,
    Aes128Gcm,
}

pub struct HttpEce<'a> {
    peer_public_key: &'a [u8],
    peer_secret: &'a [u8],
    encoding: ContentEncoding,
    rng: rand::SystemRandom,
}

impl<'a> HttpEce<'a> {
    /// Create a new encryptor. The content encoding has preliminary support for
    /// Aes128Gcm, which is the 8th draft of the Encrypted Content-Encoding, but
    /// currently using it will return an error when trying to encrypt. There is
    /// no real support yet for the encoding in web browsers.
    ///
    /// `peer_public_key` is the `p256dh` and `peer_secret` the `auth` from
    /// browser subscription info.
    pub fn new(encoding: ContentEncoding, peer_public_key: &'a [u8], peer_secret: &'a [u8]) -> HttpEce<'a> {
        HttpEce {
            rng: rand::SystemRandom::new(),
            peer_public_key: peer_public_key,
            peer_secret: peer_secret,
            encoding: encoding,
        }
    }

    /// Encrypts a payload. The maximum length for the payload is 3800
    /// characters, which is the largest that works with Google's and Mozilla's
    /// push servers.
    pub fn encrypt(&self, content: &'a [u8]) -> Result<WebPushPayload, WebPushError> {
        if content.len() > 3800 { return Err(WebPushError::PayloadTooLarge) }

        let private_key        = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &self.rng)?;
        let mut public_key     = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
        let public_key         = &mut public_key[..private_key.public_key_len()];
        let agr                = &agreement::ECDH_P256;
        let mut salt_bytes     = [0u8; 16];
        let peer_input         = Input::from(self.peer_public_key);

        self.rng.fill(&mut salt_bytes)?;
        private_key.compute_public_key(public_key)?;

        agreement::agree_ephemeral(private_key, agr, peer_input, WebPushError::Unspecified, |shared_secret| {
            match self.encoding {
                ContentEncoding::AesGcm => {
                    let mut payload = [0u8; 3818];
                    front_pad(content, &mut payload);

                    self.aes_gcm(shared_secret, public_key, &salt_bytes, &mut payload)?;

                    let mut crypto_headers = Vec::new();
                    crypto_headers.push(("Crypto-Key", format!("keyid=p256dh;dh={}", public_key.to_base64(URL_SAFE))));
                    crypto_headers.push(("Encryption", format!("keyid=p256dh;salt={}", salt_bytes.to_base64(URL_SAFE))));

                    Ok(WebPushPayload {
                        content: payload.to_vec(),
                        crypto_headers: crypto_headers,
                        content_encoding: "aesgcm"
                    })
                },
                ContentEncoding::Aes128Gcm => Err(WebPushError::NotImplemented),
            }
        })
    }

    /// The aesgcm encrypted content-encoding, draft 3.
    pub fn aes_gcm(&self, shared_secret: &'a [u8], as_public_key: &'a [u8], salt_bytes: &'a [u8], mut payload: &'a mut [u8])
               -> Result<(), WebPushError> {
        let salt               = hmac::SigningKey::new(&digest::SHA256, salt_bytes);
        let client_auth_secret = hmac::SigningKey::new(&digest::SHA256, self.peer_secret);

        let mut context = Vec::with_capacity(140);
        context.extend_from_slice("P-256\0".as_bytes());
        context.push((self.peer_public_key.len() >> 8) as u8);
        context.push((self.peer_public_key.len() & 0xff) as u8);
        context.extend_from_slice(self.peer_public_key);
        context.push((as_public_key.len() >> 8) as u8);
        context.push((as_public_key.len() & 0xff) as u8);
        context.extend_from_slice(as_public_key);

        let mut prk = [0u8; 32];
        hkdf::extract_and_expand(&client_auth_secret, &shared_secret, "Content-Encoding: auth\0".as_bytes(), &mut prk);

        let mut cek_info = Vec::with_capacity(165);
        cek_info.extend_from_slice("Content-Encoding: aesgcm\0".as_bytes());
        cek_info.extend_from_slice(&context);

        let mut content_encryption_key = [0u8; 16];
        hkdf::extract_and_expand(&salt, &prk, &cek_info, &mut content_encryption_key);

        let mut nonce_info = Vec::with_capacity(164);
        nonce_info.extend_from_slice("Content-Encoding: nonce\0".as_bytes());
        nonce_info.extend_from_slice(&context);

        let mut nonce = [0u8; 12];
        hkdf::extract_and_expand(&salt, &prk, &nonce_info, &mut nonce);

        let sealing_key = aead::SealingKey::new(&aead::AES_128_GCM, &content_encryption_key)?;
        aead::seal_in_place(&sealing_key, &nonce, "".as_bytes(), &mut payload, 16)?;

        Ok(())
    }
}

fn front_pad(payload: &[u8], output: &mut [u8]) {
    let payload_len = payload.len();
    let max_payload = output.len() - 2 - 16;
    let padding_size = max_payload - payload.len();

    output[0] = (padding_size >> 8) as u8;
    output[1] = (padding_size & 0xff) as u8;

    for i in 0..payload_len {
        output[padding_size + i + 2] = payload[i];
    }
}

#[cfg(test)]
mod tests {
    use http_ece::{HttpEce, ContentEncoding, front_pad};
    use error::WebPushError;
    use rustc_serialize::base64::{FromBase64, ToBase64, URL_SAFE};

    #[test]
    fn test_payload_too_big() {
        let p256dh = "BLMaF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8".from_base64().unwrap();
        let auth = "xS03Fj5ErfTNH_l9WHE9Ig".from_base64().unwrap();
        let http_ece = HttpEce::new(ContentEncoding::AesGcm, &p256dh, &auth);
        let content = [0u8; 3801];

        assert_eq!(Err(WebPushError::ContentTooLong), http_ece.encrypt(&content));
    }

    #[test]
    fn test_aes128gcm() {
        let p256dh = "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8".from_base64().unwrap();
        let auth = "xS03Fi5ErfTNH_l9WHE9Ig".from_base64().unwrap();
        let http_ece = HttpEce::new(ContentEncoding::Aes128Gcm, &p256dh, &auth);
        let content = [0u8; 10];

        assert_eq!(Err(WebPushError::NotImplemented), http_ece.encrypt(&content));
    }

    #[test]
    fn test_aesgcm() {
        let p256dh = "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8".from_base64().unwrap();
        let auth = "xS03Fi5ErfTNH_l9WHE9Ig".from_base64().unwrap();
        let http_ece = HttpEce::new(ContentEncoding::AesGcm, &p256dh, &auth);
        let content = "This is test data. XXX".as_bytes();
        let shared_secret = "9vcttSQ8tq-Wi_lLQ_xA37tkYssMtJsdY6xENG5f1sE=".from_base64().unwrap();
        let as_pubkey = "BBXpqeMbtt1iwSoYzs7uRL-QVSKTAuAPrunJoNyW2wMKeVBUyNFCqbkmpVTZOVbqWpwpr_-6TpJvk1qT8T-iOYs=".from_base64().unwrap();
        let salt_bytes = "YMcMuxqRkchXwy7vMwNl1Q==".from_base64().unwrap();

        let mut payload = [0u8; 38];

        for i in 0..content.len() {
            payload[i] = content[i];
        }

        http_ece.aes_gcm(&shared_secret, &as_pubkey, &salt_bytes, &mut payload).unwrap();

        assert_eq!("tmE7-emq6iasohjXNMue0i0vn5o7EIOyP-bKyDoM1teHLcLtg44", payload.to_base64(URL_SAFE));
    }

    #[test]
    fn test_front_pad() {
        // writes the padding count in the beginning, zeroes, content and again space for the encryption tag
        let content = "naukio";
        let mut output = [0u8; 30];

        front_pad(content.as_bytes(), &mut output);

        assert_eq!(vec![0, 6, 0, 0, 0, 0, 0, 0, 110, 97, 117, 107, 105, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], output);
    }
}
