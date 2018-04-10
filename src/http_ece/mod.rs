mod aesgcm;
mod aes128gcm;
mod encryptor;

pub use self::aesgcm::AesGcm;
pub use self::aes128gcm::Aes128Gcm;
pub use self::encryptor::Encryptor;

use ring::{agreement, rand};
use ring::rand::SecureRandom;
use untrusted::Input;
use error::WebPushError;
use message::WebPushPayload;
use vapid::VapidSignature;

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
    pub fn encrypt(
        self,
        content: &'a [u8],
    ) -> Result<WebPushPayload, WebPushError> {
        if content.len() > 3052 { return Err(WebPushError::PayloadTooLarge) }

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
                    let aes_gcm = AesGcm::new(
                        self.peer_public_key,
                        self.peer_secret,
                        shared_secret,
                        public_key,
                        &salt_bytes,
                        self.vapid_signature
                    );

                    let mut payload = [0u8; 3070];
                    aes_gcm.pad(content, &mut payload);
                    aes_gcm.encrypt(&mut payload)?;

                    Ok(WebPushPayload {
                        content: payload.to_vec(),
                        crypto_headers: aes_gcm.headers(),
                        content_encoding: "aesgcm"
                    })
                },
                ContentEncoding::Aes128Gcm => {
                    let aes_128_gcm = Aes128Gcm::new(
                        self.peer_public_key,
                        self.peer_secret,
                        shared_secret,
                        public_key,
                        &salt_bytes,
                        self.vapid_signature
                    );

                    let mut payload = [0u8; 88];
                    aes_128_gcm.pad(content, &mut payload);
                    aes_128_gcm.encrypt(&mut payload)?;

                    Ok(WebPushPayload {
                        content: payload.to_vec(),
                        crypto_headers: aes_128_gcm.headers(),
                        content_encoding: "aes128gcm"
                    })
                },
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use http_ece::{HttpEce, ContentEncoding};
    use error::WebPushError;
    use base64::{self, URL_SAFE};

    #[test]
    fn test_payload_too_big() {
        let p256dh = base64::decode_config("BLMaF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
                                           URL_SAFE).unwrap();
        let auth = base64::decode_config("xS03Fj5ErfTNH_l9WHE9Ig", URL_SAFE).unwrap();
        let http_ece = HttpEce::new(ContentEncoding::AesGcm, &p256dh, &auth, None);
        let content = [0u8; 3801];

        assert_eq!(Err(WebPushError::PayloadTooLarge), http_ece.encrypt(&content));
    }
}
