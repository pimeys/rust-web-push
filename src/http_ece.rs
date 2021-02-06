use crate::error::WebPushError;
use crate::message::WebPushPayload;
use crate::vapid::VapidSignature;
use base64::{self, URL_SAFE_NO_PAD};
use ring::rand::SecureRandom;
use ring::{
    aead::{self, BoundKey},
    agreement, hkdf, rand,
};

/// The encryption standard.
#[derive(Debug, PartialEq)]
pub enum ContentEncoding {
    /// The legacy http-ece standard.
    AesGcm,
    /// The current http-ece standard.
    Aes128Gcm,
}

pub struct HttpEce<'a> {
    peer_public_key: &'a [u8],
    peer_secret: &'a [u8],
    encoding: ContentEncoding,
    rng: rand::SystemRandom,
    vapid_signature: Option<VapidSignature>,
}

#[derive(Debug, PartialEq)]
struct EceKey<T: core::fmt::Debug + PartialEq>(T);

impl hkdf::KeyType for EceKey<usize> {
    fn len(&self) -> usize {
        self.0
    }
}

impl From<hkdf::Okm<'_, EceKey<usize>>> for EceKey<Vec<u8>> {
    fn from(okm: hkdf::Okm<'_, EceKey<usize>>) -> Self {
        let mut r = vec![0u8; okm.len().0];
        okm.fill(&mut r).unwrap();
        EceKey(r)
    }
}

#[derive(Debug, PartialEq, Default)]
struct EceNonce {
    used: bool,
    nonce: Vec<u8>,
}

impl EceNonce {
    fn fill(&mut self, nonce: Vec<u8>) {
        self.nonce = nonce;
        self.used = false;
    }
}

impl aead::NonceSequence for EceNonce {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        if self.used {
            return Err(ring::error::Unspecified);
        }

        let mut nonce = [0u8; 12];

        for (i, n) in self.nonce.iter().enumerate() {
            if i >= 12 {
                return Err(ring::error::Unspecified);
            }

            nonce[i] = *n;
        }

        self.used = true;

        Ok(aead::Nonce::assume_unique_for_key(nonce))
    }
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

        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &self.rng)?;
        let public_key = private_key.compute_public_key()?;
        let mut salt_bytes = [0u8; 16];

        self.rng.fill(&mut salt_bytes)?;
        let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, self.peer_public_key);

        agreement::agree_ephemeral(
            private_key,
            &peer_public_key,
            WebPushError::Unspecified,
            |shared_secret| match self.encoding {
                ContentEncoding::AesGcm => {
                    let mut payload = vec![0; 3054];
                    front_pad(content, &mut payload);

                    self.aes_gcm(shared_secret, public_key.as_ref(), &salt_bytes, &mut payload)?;

                    Ok(WebPushPayload {
                        content: payload.to_vec(),
                        crypto_headers: self.generate_headers(public_key.as_ref(), &salt_bytes),
                        content_encoding: "aesgcm",
                    })
                }
                ContentEncoding::Aes128Gcm => Err(WebPushError::NotImplemented),
            },
        )
    }

    pub fn generate_headers(&self, public_key: &'a [u8], salt: &'a [u8]) -> Vec<(&'static str, String)> {
        let mut crypto_headers = Vec::new();

        let mut crypto_key = format!("dh={}", base64::encode_config(public_key, URL_SAFE_NO_PAD));

        if let Some(ref signature) = self.vapid_signature {
            crypto_key = format!("{}; p256ecdsa={}", crypto_key, signature.auth_k);

            let sig_s: String = signature.into();
            crypto_headers.push(("Authorization", sig_s));
        };

        crypto_headers.push(("Crypto-Key", crypto_key));
        crypto_headers.push((
            "Encryption",
            format!("salt={}", base64::encode_config(&salt, URL_SAFE_NO_PAD)),
        ));

        crypto_headers
    }

    /// The aesgcm encrypted content-encoding, draft 3.
    pub fn aes_gcm(
        &self,
        shared_secret: &'a [u8],
        as_public_key: &'a [u8],
        salt_bytes: &'a [u8],
        payload: &'a mut Vec<u8>,
    ) -> Result<(), WebPushError> {
        let mut context = Vec::with_capacity(140);

        context.extend_from_slice("P-256\0".as_bytes());
        context.push((self.peer_public_key.len() >> 8) as u8);
        context.push((self.peer_public_key.len() & 0xff) as u8);
        context.extend_from_slice(self.peer_public_key);
        context.push((as_public_key.len() >> 8) as u8);
        context.push((as_public_key.len() & 0xff) as u8);
        context.extend_from_slice(as_public_key);

        let client_auth_secret = hkdf::Salt::new(hkdf::HKDF_SHA256, &self.peer_secret);
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt_bytes);

        let EceKey(prk) = client_auth_secret
            .extract(shared_secret)
            .expand(&[&"Content-Encoding: auth\0".as_bytes()], EceKey(32))
            .unwrap()
            .into();

        let mut cek_info = Vec::with_capacity(165);
        cek_info.extend_from_slice("Content-Encoding: aesgcm\0".as_bytes());
        cek_info.extend_from_slice(&context);

        let EceKey(content_encryption_key) = salt.extract(&prk).expand(&[&cek_info], EceKey(16)).unwrap().into();

        let mut nonce_info = Vec::with_capacity(164);
        nonce_info.extend_from_slice("Content-Encoding: nonce\0".as_bytes());
        nonce_info.extend_from_slice(&context);

        let EceKey(nonce_bytes) = salt.extract(&prk).expand(&[&nonce_info], EceKey(12)).unwrap().into();

        let mut nonce = EceNonce::default();
        nonce.fill(nonce_bytes);

        let unbound_key = aead::UnboundKey::new(&aead::AES_128_GCM, &content_encryption_key)?;
        let mut sealing_key = aead::SealingKey::new(unbound_key, nonce);

        sealing_key.seal_in_place_append_tag(aead::Aad::empty(), payload)?;

        Ok(())
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
    use crate::http_ece::{front_pad, ContentEncoding, HttpEce};
    use crate::vapid::VapidSignature;
    use base64::{self, URL_SAFE, URL_SAFE_NO_PAD};

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
