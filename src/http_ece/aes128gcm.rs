use ring::{aead, hkdf, digest, hmac};
use vapid::VapidSignature;
use error::WebPushError;
use http_ece::encryptor::Encryptor;

pub struct Aes128Gcm<'a> {
    peer_public_key: &'a [u8],
    peer_secret: &'a [u8],
    shared_secret: &'a [u8],
    public_key: &'a [u8],
    salt: &'a [u8],
    vapid_signature: Option<VapidSignature>,
}

impl<'a> Aes128Gcm<'a> {
    pub fn new(
        peer_public_key: &'a [u8],
        peer_secret: &'a [u8],
        shared_secret: &'a [u8],
        public_key: &'a [u8],
        salt: &'a [u8],
        vapid_signature: Option<VapidSignature>,
    ) -> Aes128Gcm<'a> {
        Aes128Gcm {
            peer_public_key,
            peer_secret,
            shared_secret,
            public_key,
            salt,
            vapid_signature,
        }
    }
}

impl<'a> Encryptor<'a> for Aes128Gcm<'a> {
    fn encrypt(&self, mut payload: &'a mut [u8]) -> Result<(), WebPushError> {
        let salt               = hmac::SigningKey::new(&digest::SHA256, self.salt);
        let client_auth_secret = hmac::SigningKey::new(&digest::SHA256, self.peer_secret);

        let mut ikm_info = Vec::with_capacity(144);
        ikm_info.extend_from_slice(b"WebPush: info\0");
        ikm_info.extend_from_slice(self.peer_public_key);
        ikm_info.extend_from_slice(self.public_key);

        let mut ikm = [0u8; 32];
        hkdf::extract_and_expand(
            &client_auth_secret,
            self.shared_secret,
            &ikm_info,
            &mut ikm
        );


        let mut content_encryption_key = [0u8; 16];
        hkdf::extract_and_expand(
            &salt,
            &ikm,
            b"Content-Encoding: aes128gcm\0",
            &mut content_encryption_key
        );

        let mut nonce = [0u8; 12];
        hkdf::extract_and_expand(
            &salt,
            &ikm,
            b"Content-Encoding: nonce\0",
            &mut nonce
        );

        let sealing_key = aead::SealingKey::new(&aead::AES_128_GCM, &content_encryption_key)?;
        aead::seal_in_place(&sealing_key, &nonce, &[], &mut payload, 16)?;

        Ok(())
    }

    fn headers(&self) -> Vec<(&'static str, String)> {
        let mut crypto_headers = Vec::new();

        if let Some(ref signature) = self.vapid_signature {
            let sig_s = format!("vapid t={}, k={}", signature.auth_t, signature.auth_k);

            crypto_headers.push(("Authorization", sig_s));
        };

        crypto_headers
    }

    fn pad(&self, payload: &'a [u8], padded_output: &'a mut [u8]) {
        // RFC8188, 2.1

        // Salt, 16 octets
        for i in 0..self.salt.len() {
            padded_output[i] = self.salt[i];
        }

        let offset = self.salt.len();

        let rs = payload.len();
        padded_output[offset]     = ((rs >> 24) & 0xff) as u8;
        padded_output[offset + 1] = ((rs >> 16) & 0xff) as u8;
        padded_output[offset + 2] = ((rs >> 8) & 0xff) as u8;
        padded_output[offset + 3] = (rs & 0xff) as u8;

        // keyid len
        padded_output[offset + 4] = self.public_key.len() as u8;

        let offset = offset + 5;

        for i in 0..self.public_key.len() {
            padded_output[i + offset] = self.public_key[i];
        }

        let offset = offset + self.public_key.len();

        // Notification content.
        for i in 0..payload.len() {
            padded_output[i + offset] = payload[i];
        }

        padded_output[payload.len() + offset] = 2u8;
    }
}
