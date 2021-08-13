use jwt_simple::prelude::*;

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
}

#[cfg(test)]
mod tests {
    use crate::{vapid::key::VapidKey};
    use std::{fs::File};

    #[test]
    fn test_public_key_derivation() {
        let f = File::open("resources/vapid_test_key.pem").unwrap();
        let key = crate::VapidSignatureBuilder::read_pem(f).unwrap();
        let key = VapidKey::new(key);

        assert_eq!(
            vec![
                4, 202, 53, 30, 162, 133, 234, 201, 12, 101, 140, 164, 174, 215, 189, 118, 234, 152, 192, 16, 244, 242,
                96, 208, 41, 59, 167, 70, 66, 93, 15, 123, 19, 39, 209, 62, 203, 35, 122, 176, 153, 79, 89, 58, 74, 54,
                26, 126, 203, 98, 158, 75, 170, 0, 52, 113, 126, 171, 124, 55, 237, 176, 165, 111, 181
            ],
            key.public_key()
        );
    }
}
