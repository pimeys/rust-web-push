use crate::message::WebPushMessage;

use hyper::{Body, Request, StatusCode};

use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE};

use crate::error::WebPushError;
use serde_json;

#[derive(Deserialize, Serialize, Debug, PartialEq)]
struct ErrorInfo {
    code: u16,
    errno: u16,
    error: String,
    message: String,
}

pub fn build_request(message: WebPushMessage) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(message.endpoint)
        .header("TTL", format!("{}", message.ttl).as_bytes());

    if let Some(payload) = message.payload {
        builder = builder
            .header(CONTENT_ENCODING, payload.content_encoding)
            .header(
                CONTENT_LENGTH,
                format!("{}", payload.content.len() as u64).as_bytes(),
            )
            .header(CONTENT_TYPE, "application/octet-stream");

        for (k, v) in payload.crypto_headers.into_iter() {
            let v: &str = v.as_ref();
            builder = builder.header(k, v);
        }

        builder.body(payload.content.into()).unwrap()
    } else {
        builder.body("".into()).unwrap()
    }
}

pub fn parse_response(response_status: StatusCode, body: Vec<u8>) -> Result<(), WebPushError> {
    match response_status {
        status if status.is_success() => Ok(()),
        status if status.is_server_error() => Err(WebPushError::ServerError(None)),

        StatusCode::UNAUTHORIZED => Err(WebPushError::Unauthorized),
        StatusCode::GONE => Err(WebPushError::EndpointNotValid),
        StatusCode::NOT_FOUND => Err(WebPushError::EndpointNotFound),
        StatusCode::PAYLOAD_TOO_LARGE => Err(WebPushError::PayloadTooLarge),

        StatusCode::BAD_REQUEST => match String::from_utf8(body) {
            Err(_) => Err(WebPushError::BadRequest(None)),
            Ok(body_str) => match serde_json::from_str::<ErrorInfo>(&body_str) {
                Ok(error_info) => Err(WebPushError::BadRequest(Some(error_info.error))),
                Err(_) if body_str != "" => Err(WebPushError::BadRequest(Some(body_str))),
                Err(_) => Err(WebPushError::BadRequest(None)),
            },
        },

        e => Err(WebPushError::Other(format!("{:?}", e))),
    }
}

#[cfg(test)]
mod tests {
    use crate::error::WebPushError;
    use crate::http_ece::ContentEncoding;
    use hyper::StatusCode;
    use hyper::Uri;
    use crate::message::{SubscriptionInfo, WebPushMessageBuilder};
    use crate::services::autopush::*;

    #[test]
    fn builds_a_correct_request_with_empty_payload() {
        let info = SubscriptionInfo::new(
            "http://google.com",
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            "xS03Fi5ErfTNH_l9WHE9Ig"
        );

        let mut builder = WebPushMessageBuilder::new(&info).unwrap();

        builder.set_ttl(420);

        let request = build_request(builder.build().unwrap());
        let ttl = request.headers().get("TTL").unwrap().to_str().unwrap();
        let expected_uri: Uri = "http://google.com".parse().unwrap();

        assert_eq!("420", ttl);
        assert_eq!(expected_uri.host(), request.uri().host());
    }

    #[test]
    fn builds_a_correct_request_with_payload() {
        let info = SubscriptionInfo::new(
            "http://google.com",
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            "xS03Fi5ErfTNH_l9WHE9Ig"
        );

        let mut builder = WebPushMessageBuilder::new(&info).unwrap();

        builder.set_payload(ContentEncoding::AesGcm, "test".as_bytes());

        let request = build_request(builder.build().unwrap());

        let encoding = request
            .headers()
            .get("Content-Encoding")
            .unwrap()
            .to_str()
            .unwrap();

        let length = request.headers().get("Content-Length").unwrap();
        let expected_uri: Uri = "http://google.com".parse().unwrap();

        assert_eq!("3086", length);
        assert_eq!("aesgcm", encoding);
        assert_eq!(expected_uri.host(), request.uri().host());
    }

    #[test]
    fn parses_a_successful_response_correctly() {
        assert_eq!(Ok(()), parse_response(StatusCode::OK, vec![]))
    }

    #[test]
    fn parses_an_unauthorized_response_correctly() {
        assert_eq!(
            Err(WebPushError::Unauthorized),
            parse_response(StatusCode::UNAUTHORIZED, vec![])
        )
    }

    #[test]
    fn parses_a_gone_response_correctly() {
        assert_eq!(
            Err(WebPushError::EndpointNotValid),
            parse_response(StatusCode::GONE, vec![])
        )
    }

    #[test]
    fn parses_a_not_found_response_correctly() {
        assert_eq!(
            Err(WebPushError::EndpointNotFound),
            parse_response(StatusCode::NOT_FOUND, vec![])
        )
    }

    #[test]
    fn parses_a_payload_too_large_response_correctly() {
        assert_eq!(
            Err(WebPushError::PayloadTooLarge),
            parse_response(StatusCode::PAYLOAD_TOO_LARGE, vec![])
        )
    }

    #[test]
    fn parses_a_server_error_response_correctly() {
        assert_eq!(
            Err(WebPushError::ServerError(None)),
            parse_response(StatusCode::INTERNAL_SERVER_ERROR, vec![])
        )
    }

    #[test]
    fn parses_a_bad_request_response_with_no_body_correctly() {
        assert_eq!(
            Err(WebPushError::BadRequest(None)),
            parse_response(StatusCode::BAD_REQUEST, vec![])
        )
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

        assert_eq!(
            Err(WebPushError::BadRequest(Some(String::from("FooBar")))),
            parse_response(StatusCode::BAD_REQUEST, json.as_bytes().to_vec())
        )
    }
}
