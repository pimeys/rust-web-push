use hyper::client::Client;
use hyper_tls::HttpsConnector;
use hyper::client::{Request as HttpRequest, Response as HttpResponse};
use hyper::header::{ContentLength, RetryAfter};
use hyper::Post;
use futures::{Future, Poll};
use futures::future::{ok, err};
use rustc_serialize::base64::{ToBase64, URL_SAFE};
use tokio_core::reactor::Handle;
use tokio_service::Service;
use hyper::status::StatusCode;
use std::fmt;

use error::WebPushError;
use message::WebPushMessage;

pub struct WebPushResponse(Box<Future<Item=(), Error=WebPushError> + 'static>);

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

    pub fn send(&self, message: WebPushMessage) -> WebPushResponse {
        self.call(message)
    }
}

impl Service for WebPushClient {
    type Request = WebPushMessage;
    type Response = ();
    type Error = WebPushError;
    type Future = WebPushResponse;

    fn call(&self, message: Self::Request) -> Self::Future {
        let mut request = HttpRequest::new(Post, message.endpoint.parse().unwrap());

        if let Some(payload) = message.payload {
            request.headers_mut().set_raw("Content-Encoding", "aesgcm");
            request.headers_mut().set_raw("Crypto-Key", format!("keyid=p256dh;dh={}", payload.public_key.to_base64(URL_SAFE)));
            request.headers_mut().set_raw("Encryption", format!("keyid=p256dh;salt={}", payload.salt.to_base64(URL_SAFE)));
            request.headers_mut().set(ContentLength(payload.content.len() as u64));
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

        WebPushResponse(Box::new(push_f))
    }
}
