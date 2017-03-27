extern crate hyper;
extern crate futures;
extern crate tokio_core;
extern crate tokio_service;
extern crate hyper_tls;
extern crate btls;
extern crate rustc_serialize;
extern crate rand;

use hyper::client::Client;
use hyper_tls:HttpsConnector;
use hyper::client::{Response};
use futures::{Future};
use rustc_serialize::base64::{URL_SAFE, ToBase64};
use rand::os::OsRng;

#[derive(PartialEq, Debug)]
pub enum WebPushError {
    Unknown
}

#[derive(PartialEq, Debug)]
pub enum ContentEncoding {
    AESGCM,
    AES128GCM,
}

pub struct WebPushMessage {
    secret: LocalKeyPair,
    ec_group: EcGroup,
    ec_key: EcKey,
    endpoint: String,
    auth: String,
    p256dh: String,
    data: Option<String>
    ttl: Option<u32>,
    exp: Option<u64>,
    sub: Option<String>,
}

impl WebPushMessage {
    pub fn new<S>(endpoint: S, auth: S, p256dh: S)
        where S: Into<String> -> WebPushMessage {

        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(group.deref()).unwrap();
        let private_key = ec_key.private_key_to_der().unwrap();

        WebPushMessage {
            secret: LocalKeyPair::new(&mut Cursor::new(private_key.as_slice()), "web_push_keypair"),
            ec_group: group,
            ec_key: ec_key,
            endpoint: endpoint.into(),
            auth: auth.into(),
            p256dh: p256dh.into(),
            ttl: None,
            exp: None,
            sub: None,
        }
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = Some(ttl);
    }

    pub fn set_gcm_key<S>(&mut self, gcm_key: S) where S: Into<String> {
        self.gcm_key = Some(gcm_key.into());
    }

    pub fn set_exp(&mut self, exp: u64) {
        self.exp = Some(exp);
    }

    pub fn set_sub<S>(&mut self, sub: S) where S: Into<String> {
        self.sub = Some(sub.into());
    }

    pub fn set_data<S>(&mut self, data: S) where S: Into<String> {
        self.data = Some(data);
    }

    pub fn crypto_key(&self) -> String {
        let public_key = self.ec_key.public_key().unwrap()
            .to_bytes(self.group.deref(), ec::POINT_CONVERSION_UNCOMPRESSED, BigNumContext::new().unwrap().deref())
            .unwrap();

        format!("dh={},p256ecdsa={}", self.p256dh, public_key.to_base64(base64::URL_SAFE))
    }

    pub fn authorization(&self) -> Result<String, WebPushError> {
        let mut headers: BTreeMap<String, JsonNode> = BTreeMap::new();
        if let Some(ttl) = self.ttl { headers.insert("exp".to_string(), JsonNode::Number(ttl)); }
        headers.insert("alg".to_string(), JsonNode::String("ES256".to_string()));

        let mut payload: BTreeMap<String, JsonNode> = BTreeMap::new();
        if let Some(exp) = self.exp { payload.insert("exp".to_string(), JsonNode::Number(exp)); }
        if let Some(sub) = self.sub { payload.insert("sub".to_string(), JsonNode::String(sub.clone())); }
        payload.insert("aud".to_string(), JsonNode::String(self.endpoint.clone()));

        let jwt_headers = JsonNode::Dictionary(headers);
        let jwt_payload = JsonNode::Dictionary(payload).serialize();

        match sign_jws(&jwt_headers, jwt_payload.as_bytes(), &self.secret, SIG_ECDSA_SHA256).read() {
            Ok(Ok(token)) => Ok(format!("WebPush {}", token)),
            _ => Err(WebPushError::Unknown)
        }
    }

    pub fn payload(&self) -> Result<String, WebPushError> {
        
    }
}

pub struct FutureResponse(Box<Future<Item=Response, Error=WebPushError> 'static>);

impl fmt::Debug for FutureResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.pad("Future<Response>")
    }
}

impl Future for FutureResponse {
    type Item = Response;
    type Error = WebPushError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

pub struct Sender {
    client: Client<HttpsConnector>,
}

impl Sender {
    pub fn new(handle: &Handle) -> Sender {
        let client = Client::configure()
            .connector(HttpsConnector::new(4, handle))
            .keep_alive(true)
            .build(handle);

        Sender {
            client: client,
        }
    }
}

impl Service for Sender {
    type Request = WebPushMessage;
    type Response = Response;
    type Error = WebPushError;
    type Future = FutureResponse;

    fn call(&self, message: Self::Request) -> Self::Future {
    }
}
