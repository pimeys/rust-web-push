use message::WebPushMessage;
use hyper::client::Request;
use hyper::{Post, StatusCode};
use error::WebPushError;
use hyper::header::ContentLength;
use rustc_serialize::json;

#[derive(RustcDecodable, RustcEncodable, Debug, PartialEq)]
struct ErrorInfo {
    code: u16,
    errno: u16,
    error: String,
    message: String,
}

pub fn build_request(message: WebPushMessage) -> Request {
    let mut request = Request::new(Post, message.endpoint);

    if let Some(ttl) = message.ttl {
        request.headers_mut().set_raw("TTL", format!("{}", ttl));
    }

    if let Some(payload) = message.payload {
        request.headers_mut().set_raw("Content-Encoding", payload.content_encoding);
        request.headers_mut().set(ContentLength(payload.content.len() as u64));
        request.set_body(payload.content.clone());

        for (k, v) in payload.crypto_headers.into_iter() {
            request.headers_mut().set_raw(k, v);
        }
    }

    request
}

pub fn parse_response(response_status: StatusCode, body: Vec<u8>) -> Result<(), WebPushError> {
    match response_status {
        status if status.is_success()      => Ok(()),
        StatusCode::Unauthorized           => Err(WebPushError::Unauthorized),
        StatusCode::Gone                   => Err(WebPushError::EndpointNotValid),
        StatusCode::NotFound               => Err(WebPushError::EndpointNotFound),
        StatusCode::PayloadTooLarge        => Err(WebPushError::PayloadTooLarge),
        status if status.is_server_error() => Err(WebPushError::ServerError(None)),

        StatusCode::BadRequest => {
            match String::from_utf8(body) {
                Err(_)       => Err(WebPushError::BadRequest(None)),
                Ok(body_str) => match json::decode::<ErrorInfo>(&body_str) {
                    Ok(error_info) => Err(WebPushError::BadRequest(Some(error_info.error))),
                    Err(_)         => Err(WebPushError::BadRequest(None)),
                },
            }
        },

        e => Err(WebPushError::Other(format!("{:?}", e))),
    }
}

#[cfg(test)]
mod tests {
    use services::autopush::*;
    use hyper::StatusCode;
    use http_ece::ContentEncoding;
    use error::WebPushError;
    use message::WebPushMessageBuilder;
    use hyper::Uri;
    use rustc_serialize::base64::FromBase64;

    #[test]
    fn builds_a_correct_request_with_empty_payload() {
        let p256dh = "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8".from_base64().unwrap();
        let auth = "xS03Fi5ErfTNH_l9WHE9Ig".from_base64().unwrap();
        let mut builder = WebPushMessageBuilder::new("http://google.com", &auth, &p256dh).unwrap();

        builder.set_ttl(420);

        let request = build_request(builder.build().unwrap());
        let ttl = String::from_utf8(request
                                    .headers()
                                    .get_raw("TTL")
                                    .unwrap()
                                    .one()
                                    .unwrap()
                                    .to_vec()).unwrap();
        let expected_uri: Uri = "http://google.com".parse().unwrap();

        assert_eq!("420", ttl);
        assert_eq!(expected_uri.host(), request.uri().host());
    }

    #[test]
    fn builds_a_correct_request_with_payload() {
        let p256dh = "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8".from_base64().unwrap();
        let auth = "xS03Fi5ErfTNH_l9WHE9Ig".from_base64().unwrap();
        let mut builder = WebPushMessageBuilder::new("http://google.com", &auth, &p256dh).unwrap();

        builder.set_payload(ContentEncoding::AesGcm, "test".as_bytes());

        let request = build_request(builder.build().unwrap());
        let encoding = String::from_utf8(request
                                         .headers()
                                         .get_raw("Content-Encoding")
                                         .unwrap()
                                         .one()
                                         .unwrap()
                                         .to_vec()).unwrap();
        let length = request.headers().get::<ContentLength>().unwrap();
        let expected_uri: Uri = "http://google.com".parse().unwrap();

        assert_eq!(&ContentLength(3818), length);
        assert_eq!("aesgcm", encoding);
        assert_eq!(expected_uri.host(), request.uri().host());
    }

    #[test]
    fn parses_a_successful_response_correctly() {
        assert_eq!(Ok(()), parse_response(StatusCode::Ok, vec![]))
    }

    #[test]
    fn parses_an_unauthorized_response_correctly() {
        assert_eq!(Err(WebPushError::Unauthorized), parse_response(StatusCode::Unauthorized, vec![]))
    }

    #[test]
    fn parses_a_gone_response_correctly() {
        assert_eq!(Err(WebPushError::EndpointNotValid), parse_response(StatusCode::Gone, vec![]))
    }

    #[test]
    fn parses_a_not_found_response_correctly() {
        assert_eq!(Err(WebPushError::EndpointNotFound), parse_response(StatusCode::NotFound, vec![]))
    }

    #[test]
    fn parses_a_payload_too_large_response_correctly() {
        assert_eq!(Err(WebPushError::PayloadTooLarge), parse_response(StatusCode::PayloadTooLarge, vec![]))
    }

    #[test]
    fn parses_a_server_error_response_correctly() {
        assert_eq!(Err(WebPushError::ServerError(None)), parse_response(StatusCode::InternalServerError, vec![]))
    }

    #[test]
    fn parses_a_bad_request_response_with_no_body_correctly() {
        assert_eq!(Err(WebPushError::BadRequest(None)), parse_response(StatusCode::BadRequest, vec![]))
    }

    #[test]
    fn parses_a_bad_request_response_with_body_correctly() {
        let json = r#"
            {
                "code": 404,
                "errno": 103,
                "error": "FooBar",
                "message": "No message found"
            }
        "#;

        assert_eq!(Err(WebPushError::BadRequest(Some(String::from("FooBar")))), parse_response(StatusCode::BadRequest, json.as_bytes().to_vec()))
    }
}
