extern crate hyper;
extern crate futures;
extern crate tokio_core;
extern crate tokio_service;
extern crate hyper_tls;
extern crate rustc_serialize;
extern crate ring;
extern crate crypto;
extern crate untrusted;

use hyper::client::Client;
use hyper_tls::HttpsConnector;
use hyper::client::{Request as HttpRequest, Response as HttpResponse};
use hyper::header::{Authorization, ContentLength, RetryAfter};
use hyper::Post;
use futures::{Future, Poll};
use futures::future::{ok, err};
use ring::{hmac, hkdf, agreement, rand, digest, error};
use crypto::aes_gcm::AesGcm;
use crypto::aes::KeySize;
use std::convert::From;
use crypto::aead::AeadEncryptor;
use std::error::Error;
use std::fmt;
use tokio_core::reactor::Handle;
use tokio_service::Service;
use rustc_serialize::base64::{ToBase64, URL_SAFE};
use rustc_serialize::json;
use hyper::status::StatusCode;
use untrusted::Input;

#[derive(PartialEq, Debug)]
pub enum WebPushError {
    Unspecified,
    Unauthorized,
    BadRequest,
    ServerError(Option<RetryAfter>),
    KeyAgreement,
}

#[derive(Debug)]
pub struct WebPushPayload {
    pub content: Vec<u8>,
    pub public_key: Vec<u8>,
    pub salt: Vec<u8>,
}

impl WebPushPayload {
    pub fn new(content: Vec<u8>, public_key: Vec<u8>, salt: Vec<u8>) -> WebPushPayload {
        WebPushPayload {
            content: content,
            public_key: public_key,
            salt: salt,
        }
    }
}

#[derive(Debug)]
pub struct WebPushMessage {
    pub gcm_key: Option<String>,
    pub endpoint: String,
    pub ttl: Option<u32>,
    pub payload: Option<WebPushPayload>,
}

pub struct WebPushMessageBuilder<'a> {
    gcm_key: Option<&'a str>,
    endpoint: &'a str,
    auth: &'a [u8],
    p256dh: &'a [u8],
    payload: Option<&'a [u8]>,
    ttl: Option<u32>,
}

impl From<error::Unspecified> for WebPushError {
    fn from(e: error::Unspecified) -> WebPushError {
        println!("{:?}", e);
        WebPushError::Unspecified
    }
}

impl Error for WebPushError {
    fn description(&self) -> &str {
        match self {
            _ => "An unknown error",
        }
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

impl fmt::Display for WebPushError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl<'a> WebPushMessageBuilder<'a> {
    pub fn new(endpoint: &'a str, auth: &'a [u8], p256dh: &'a [u8]) -> WebPushMessageBuilder<'a> {
        WebPushMessageBuilder {
            endpoint: endpoint,
            auth: auth,
            p256dh: p256dh,
            ttl: None,
            gcm_key: None,
            payload: None,
        }
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = Some(ttl);
    }

    pub fn set_gcm_key(&mut self, gcm_key: &'a str) {
        self.gcm_key = Some(gcm_key);
    }

    pub fn set_payload(&mut self, payload: &'a [u8]) {
        self.payload = Some(payload);
    }

    pub fn build(self) -> Result<WebPushMessage, WebPushError> {
        if let Some(payload) = self.payload {
            let rng               = rand::SystemRandom::new();
            let private_key       = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
            let mut public_key    = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
            let public_key        = &mut public_key[..private_key.public_key_len()];
            let mut random_bytes  = [0u8; 16];

            rng.fill(&mut random_bytes)?;

            let salt = hmac::SigningKey::new(&digest::SHA256, &random_bytes);

            private_key.compute_public_key(public_key)?;

            agreement::agree_ephemeral(private_key, &agreement::ECDH_P256, Input::from(self.p256dh), WebPushError::KeyAgreement, |shared_secret| {
                let client_auth_secret = hmac::SigningKey::new(&digest::SHA256, self.auth);

                let mut auth_info: Vec<u8> = Vec::new();
                auth_info.extend_from_slice("WebPush: info".as_bytes());
                auth_info.push(0);
                auth_info.extend_from_slice(self.p256dh);
                auth_info.extend_from_slice(public_key);
                auth_info.push(1);

                let mut prk = [0u8; 32];
                hkdf::extract_and_expand(&client_auth_secret, &shared_secret, &auth_info, &mut prk);

                let mut content_encryption_info: Vec<u8> = Vec::new();
                content_encryption_info.extend_from_slice("Content-Encoding: aes128gcm".as_bytes());
                content_encryption_info.push(0);
                content_encryption_info.push(1);

                let mut content_encryption_key = [0u8; 16];
                hkdf::extract_and_expand(&salt, &prk, &content_encryption_info, &mut content_encryption_key);

                let mut nonce_info: Vec<u8> = Vec::new();
                nonce_info.extend_from_slice("Content-Encoding: nonce".as_bytes());
                nonce_info.push(0);
                nonce_info.push(1);
                let mut nonce = [0u8; 12];
                hkdf::extract_and_expand(&salt, &prk, &nonce_info, &mut nonce);

                //let mut padded_payload = [0u8; 4080];
                //Self::pad(payload, &mut padded_payload);

                let mut aes_gcm = AesGcm::new(KeySize::KeySize128, &shared_secret, &nonce, "".as_bytes());
                let mut encrypted_payload = [0u8; 4080];
                let mut encrypted_payload = &mut encrypted_payload[..payload.len()];
                let mut tag = [0u8; 16];

                aes_gcm.encrypt(&payload, &mut encrypted_payload, &mut tag);

                let mut full_payload = Vec::with_capacity(encrypted_payload.len() + tag.len());
                full_payload.extend_from_slice(&encrypted_payload);
                full_payload.extend_from_slice(&tag);

                let web_push_payload = WebPushPayload::new(full_payload, public_key.to_vec(), random_bytes.to_vec());

                Ok(WebPushMessage {
                    gcm_key: self.gcm_key.map(|k| k.to_string()),
                    endpoint: self.endpoint.to_string(),
                    ttl: self.ttl,
                    payload: Some(web_push_payload),
                })
            })
        } else {
            Ok(WebPushMessage {
                gcm_key: self.gcm_key.map(|k| k.to_string()),
                endpoint: self.endpoint.to_string(),
                ttl: self.ttl,
                payload: None,
            })
        }
    }

    fn pad(payload: &[u8], output: &mut [u8]) {
        let payload_len = payload.len();
        let max_payload = output.len() - 2;
        let padding_size = max_payload - payload.len();

        output[0] = (padding_size >> 8) as u8;
        output[1] = (padding_size & 0xff) as u8;

        for i in 0..payload_len {
            output[i + 2 + padding_size] = payload[i];
        }
    }

    fn create_info(&self, hkdf_type: &str, public_key: &[u8]) -> Vec<u8> {
        let mut info: Vec<u8> = Vec::with_capacity(hkdf_type.len() + 159);

        info.extend_from_slice("Content-Encoding: ".as_bytes());
        info.extend_from_slice(hkdf_type.as_bytes());
        info.push(0);
        info.extend_from_slice("P-256".as_bytes());
        info.push(0);
        info.push((self.p256dh.len() >> 8) as u8);
        info.push((self.p256dh.len() & 0xff) as u8);
        info.extend_from_slice(self.p256dh);
        info.push((public_key.len() >> 8) as u8);
        info.push((public_key.len() & 0xff) as u8);
        info.extend_from_slice(public_key);

        info
    }
}

pub struct FutureResponse(Box<Future<Item=(), Error=WebPushError> + 'static>);

impl fmt::Debug for FutureResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.pad("Future<Response>")
    }
}

impl Future for FutureResponse {
    type Item = ();
    type Error = WebPushError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

pub struct WebPushSender {
    client: Client<HttpsConnector>,
}

/*
#[derive(RustcDecodable, RustcEncodable)]
struct GcmData {
    registration_ids: Vec<String>,
    raw_data: Option<String>,
    time_to_live: Option<u32>,
}

impl GcmData {
    pub fn new(registration_ids: Vec<String>) -> GcmData {
        GcmData {
            registration_ids: registration_ids,
            raw_data: None,
            time_to_live: None,
        }
    }

    pub fn set_raw_data(&mut self, raw_data: Vec<u8>) {
        self.raw_data = Some(raw_data);
    }

    pub fn set_time_to_live(&mut self, ttl: u32) {
        self.time_to_live = Some(ttl);
    }
}
*/

impl WebPushSender {
    pub fn new(handle: &Handle) -> WebPushSender {
        let client = Client::configure()
            .connector(HttpsConnector::new(4, handle))
            .keep_alive(true)
            .build(handle);

        WebPushSender {
            client: client,
        }
    }

    pub fn send(&self, message: WebPushMessage) -> FutureResponse {
        self.call(message)
    }
}

impl Service for WebPushSender {
    type Request = WebPushMessage;
    type Response = ();
    type Error = WebPushError;
    type Future = FutureResponse;

    fn call(&self, message: Self::Request) -> Self::Future {
        let mut request = HttpRequest::new(Post, message.endpoint.parse().unwrap());

        if let Some(payload) = message.payload {
            request.headers_mut().set_raw("content-encoding", "aesgcm");
            request.headers_mut().set(ContentLength(payload.content.len() as u64));
            request.headers_mut().set_raw("encryption", format!("keyid=p256dh;salt={}", payload.salt.to_base64(URL_SAFE)));
            request.headers_mut().set_raw("crypto-key", format!("keyid=p256dh;dh={}", payload.public_key.to_base64(URL_SAFE)));

            request.set_body(payload.content);
        }

        if let Some(ttl) = message.ttl {
            request.headers_mut().set_raw("TTL", format!("{}", ttl));
        }

        let request_f = self.client.request(request).map_err(|_| { WebPushError::Unspecified });

        let push_f = request_f.and_then(move |response: HttpResponse| {
            let retry_after = response.headers().get::<RetryAfter>().map(|ra| *ra);

            match *response.status() {
                status if status.is_success() =>
                    ok(()),
                StatusCode::Unauthorized =>
                    err(WebPushError::Unauthorized),
                StatusCode::BadRequest =>
                    err(WebPushError::BadRequest),
                status if status.is_server_error() =>
                    err(WebPushError::ServerError(retry_after)),
                status => {
                    println!("{:?}", status);
                    err(WebPushError::Unspecified)
                }
            }
        });

        FutureResponse(Box::new(push_f))
    }
}
