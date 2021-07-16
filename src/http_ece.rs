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
    /// Create a new encryptor.
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
                let mut headers = encrypted_block.headers(vapid_public_key.as_deref());
                
                if let Some(ref signature) = self.vapid_signature {
                    headers.push(("Authorization", format!("WebPush {}", signature.auth_t)));
                };
                
                Ok(WebPushPayload {
                    content: encrypted_block.body().into_bytes(),
                    crypto_headers: headers,
                    content_encoding: "aesgcm",
                })
            }
            ContentEncoding::Aes128Gcm => {
                let result = encrypt(self.peer_public_key, self.peer_secret, &payload);

                let mut headers = Vec::new();

                if let Some(signature) = &self.vapid_signature {
                    headers.push((
                        "Authorization",
                        format!("vapid t={}, k={}", signature.auth_t, signature.auth_k),
                    ));
                }

                match result {
                    Ok(data) => Ok(WebPushPayload {
                        content: data,
                        crypto_headers: headers,
                        content_encoding: "aes128gcm",
                    }),
                    _ => Err(WebPushError::InvalidCryptoKeys)
                }
            },
        }
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
    use crate::VapidSignature;
    use crate::error::WebPushError;
    use crate::http_ece::{ContentEncoding, HttpEce};
    use base64::{self, URL_SAFE};
    use regex::Regex;
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
    
    fn test_aesgcm_common_headers(vapid_signature : Option<VapidSignature>) -> Option<String>{
        let crypto_re =
        Regex::new(r"dh=(?P<dh>[^;]*)(?P<vapid>(; p256ecdsa=(?P<ecdsa>.*))?)").unwrap();
        let encryption_re = Regex::new(r"salt=(?P<salt>.*)").unwrap();
        
        let p256dh = base64::decode_config("BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
        URL_SAFE).unwrap();
        let auth = base64::decode_config("xS03Fi5ErfTNH_l9WHE9Ig", URL_SAFE).unwrap();
        
        let http_ece = HttpEce::new(ContentEncoding::AesGcm, &p256dh, &auth, vapid_signature);
        let content = "Hello, world!".as_bytes();
        
        let wp_payload = http_ece.encrypt(content).unwrap();
        let mut has_enc = false;
        let mut has_crypto = false;
        let mut authorization = None;
        for kvp in &wp_payload.crypto_headers {
            match kvp.0 {
                "Authorization" => authorization = Some(kvp.1.clone()),
                "Crypto-Key" => {
                    assert!(crypto_re.captures(&kvp.1).is_some());
                    has_crypto = true;
                }
                "Encryption" => {
                    assert!(encryption_re.captures(&kvp.1).is_some());
                    let enc_captures = encryption_re.captures(&kvp.1);
                    assert!(enc_captures.is_some());
                    assert!(&enc_captures.unwrap().name("vapid").is_none());
                    has_enc = true;
                },
                _ => {}
            }
        }
        assert!(has_crypto && has_enc);
        authorization
    }

    #[test]
    fn test_aesgcm_headers_no_vapid(){
        let authorization = test_aesgcm_common_headers(None);
        assert!(authorization.is_none());
    }
    
    #[test]
    fn test_aesgcm_headers_vapid(){
        let auth_re = Regex::new(r"WebPush (?P<sig>.*)").unwrap();
        let vapid_signature = VapidSignature {
            auth_t: String::from("foo"),
            auth_k: String::from("bar"),
        };
        let authorization = test_aesgcm_common_headers(Some(vapid_signature));
        assert!(authorization.is_some());
        let auth_str = authorization.unwrap();
        let auth_cap_opt = auth_re.captures(&auth_str);
        assert!(auth_cap_opt.is_some());
        assert_eq!(&auth_cap_opt.unwrap()["sig"], "foo");
    }
    
    #[test]
    fn test_aes128gcm_headers_no_vapid(){
        todo!()
    }
    
    #[test]
    fn test_aes128gcm_headers_vapid(){
        todo!()
    }
}
