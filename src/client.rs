use hyper::client::Client;
use hyper_tls::HttpsConnector;
use hyper::client::{Request as HttpRequest, Response as HttpResponse};
use hyper::header::{ContentLength, RetryAfter, Authorization, ContentType};
use hyper::{Post, Uri};
use futures::{Future, Poll};
use futures::future::{ok, err};
use rustc_serialize::base64::{ToBase64, STANDARD};
use rustc_serialize::json;
use tokio_core::reactor::Handle;
use tokio_service::Service;
use hyper::status::StatusCode;
use std::fmt;

use error::WebPushError;
use message::WebPushMessage;

pub struct WebPushResponse(Box<Future<Item=(), Error=WebPushError> + 'static>);

#[derive(RustcDecodable, RustcEncodable)]
struct GcmData {
    registration_ids: Vec<String>,
    raw_data: Option<String>,
}

impl fmt::Debug for WebPushResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.pad("Future<Response>")
    }
}

impl Future for WebPushResponse {
    type Item = ();
    type Error = WebPushError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

pub struct WebPushClient {
    client: Client<HttpsConnector>,
}

impl WebPushClient {
    pub fn new(handle: &Handle) -> WebPushClient {
        let client = Client::configure()
            .connector(HttpsConnector::new(4, handle))
            .keep_alive(true)
            .build(handle);

        WebPushClient {
            client: client,
        }
    }

    /// A future which sends a web push notification.
    pub fn send(&self, message: WebPushMessage) -> WebPushResponse {
        self.call(message)
    }

    fn build_gcm_request(message: &WebPushMessage) -> HttpRequest {
        let mut request = HttpRequest::new(Post, "https://android.googleapis.com/gcm/send".parse().unwrap());

        if let Some(ref gcm_key) = message.gcm_key {
            request.headers_mut().set(Authorization(format!("key={}", gcm_key)));
        }

        let mut registration_ids = Vec::with_capacity(1);

        if let Some(token) = message.endpoint.split("/").last() {
            registration_ids.push(token.to_string());
        }

        let raw_data = match message.payload {
            Some(ref payload) =>
                Some(payload.content.to_base64(STANDARD)),
            None =>
                None,
        };

        let gcm_data = GcmData {
            registration_ids: registration_ids,
            raw_data: raw_data,
        };

        let json_payload = json::encode(&gcm_data).unwrap();

        request.headers_mut().set(ContentType::json());
        request.headers_mut().set(ContentLength(json_payload.len() as u64));

        request.set_body(json_payload);
        request
    }

    fn build_request(message: &WebPushMessage, uri: Uri) -> HttpRequest {
        let mut request = HttpRequest::new(Post, uri);

        if let Some(ttl) = message.ttl {
            request.headers_mut().set_raw("TTL", format!("{}", ttl));
        }

        if let Some(ref payload) = message.payload {
            request.headers_mut().set_raw("Content-Encoding", payload.content_encoding);
            request.headers_mut().set(ContentLength(payload.content.len() as u64));
            request.set_body(payload.content.clone());
        }

        request
    }
}

impl Service for WebPushClient {
    type Request = WebPushMessage;
    type Response = ();
    type Error = WebPushError;
    type Future = WebPushResponse;

    fn call(&self, message: Self::Request) -> Self::Future {
        match message.endpoint.parse() {
            Ok(uri) => {
                let mut request = if message.endpoint.starts_with("https://android.googleapis.com/gcm/send/") {
                    Self::build_gcm_request(&message)
                } else {
                    Self::build_request(&message, uri)
                };

                if let Some(payload) = message.payload {
                    for (k, v) in payload.crypto_headers.into_iter() {
                        request.headers_mut().set_raw(k, v);
                    }
                }

                let request_f = self.client.request(request).map_err(|_| { WebPushError::Unspecified });

                let push_f = request_f.and_then(move |response: HttpResponse| {
                    let retry_after = response.headers().get::<RetryAfter>().map(|ra| *ra);
                    let response_status = response.status().clone();

                    match response_status {
                        status if status.is_success() =>
                            ok(()),
                        StatusCode::Unauthorized =>
                            err(WebPushError::Unauthorized),
                        StatusCode::BadRequest => {
                            err(WebPushError::BadRequest)
                        },
                        status if status.is_server_error() =>
                            err(WebPushError::ServerError(retry_after)),
                        _ => {
                            err(WebPushError::Unspecified)
                        }
                    }
                });

                WebPushResponse(Box::new(push_f))
            },
            Err(_) => {
                WebPushResponse(Box::new(err(WebPushError::InvalidUri)))
            }
        }
    }
}
