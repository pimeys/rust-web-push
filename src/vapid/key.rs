use jwt_simple::prelude::*;

use crate::WebPushError;

/// The P256 curve key pair used for VAPID ECDHSA.
pub struct VapidKey(pub ES256KeyPair);

impl Clone for VapidKey {
    fn clone(&self) -> Self {
        VapidKey(ES256KeyPair::from_bytes(&self.0.to_bytes()).unwrap())
    }
}

impl VapidKey {
    pub fn new(ec_key: ES256KeyPair) -> VapidKey {
        VapidKey(ec_key)
    }

    /// Gets the uncompressed public key bytes derived from this private key.
    pub fn public_key(&self) -> Vec<u8> {
        self.0.public_key().public_key().to_bytes_uncompressed()
    }

    /// Creates a new VapidKey from a DER-formatted private key.
    pub fn from_der(input: &[u8]) -> Result<Self, WebPushError> {
        Ok(Self(
            ES256KeyPair::from_bytes(
                &sec1_decode::parse_der(input)
                    .map_err(|_| WebPushError::InvalidCryptoKeys)?
                    .key,
            )
            .map_err(|_| WebPushError::InvalidCryptoKeys)?,
        ))
    }

    pub fn from_base64(encoded: &str) -> Result<Self, WebPushError> {
        Ok(Self(
            ES256KeyPair::from_bytes(
                &Base64UrlSafeNoPadding::decode_to_vec(encoded, None).map_err(|_| WebPushError::InvalidCryptoKeys)?,
            )
            .map_err(|_| WebPushError::InvalidCryptoKeys)?,
        ))
    }

    /// Reads the pem file as either format sec1 or pkcs8, then returns the decoded private key.
    pub fn from_pem(input: &str) -> Result<Self, WebPushError> {
        //Parse many PEM in the assumption of extra unneeded sections.
        let parsed = pem::parse_many(input).map_err(|_| WebPushError::InvalidCryptoKeys)?;

        let found_pkcs8 = parsed.iter().any(|pem| pem.tag() == "PRIVATE KEY");
        let found_sec1 = parsed.iter().any(|pem| pem.tag() == "EC PRIVATE KEY");

        //Handle each kind of PEM file differently, as EC keys can be in SEC1 or PKCS8 format.
        if found_sec1 {
            let key = sec1_decode::parse_pem(input.as_bytes()).map_err(|_| WebPushError::InvalidCryptoKeys)?;
            Ok(Self(
                ES256KeyPair::from_bytes(&key.key).map_err(|_| WebPushError::InvalidCryptoKeys)?,
            ))
        } else if found_pkcs8 {
            Ok(Self(
                ES256KeyPair::from_pem(input).map_err(|_| WebPushError::InvalidCryptoKeys)?,
            ))
        } else {
            Err(WebPushError::MissingCryptoKeys)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::vapid::key::VapidKey;

    #[test]
    /// Tests that VapidKey derives the correct public key.
    fn test_public_key_derivation() {
        let pem = include_str!("../../resources/vapid_test_key.pem");
        let key = VapidKey::from_pem(pem).unwrap();

        assert_eq!(
            vec![
                4, 202, 53, 30, 162, 133, 234, 201, 12, 101, 140, 164, 174, 215, 189, 118, 234, 152, 192, 16, 244, 242,
                96, 208, 41, 59, 167, 70, 66, 93, 15, 123, 19, 39, 209, 62, 203, 35, 122, 176, 153, 79, 89, 58, 74, 54,
                26, 126, 203, 98, 158, 75, 170, 0, 52, 113, 126, 171, 124, 55, 237, 176, 165, 111, 181
            ],
            key.public_key()
        );
    }

    #[test]
    /// Tests that VapidKey clones properly.
    fn test_key_clones() {
        let pem = include_str!("../../resources/vapid_test_key.pem");
        let key = VapidKey::from_pem(pem).unwrap();
        let key2 = key.clone();

        assert_eq!(key.0.to_bytes(), key2.0.to_bytes())
    }
}
