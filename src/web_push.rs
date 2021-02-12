use crate::{
    error::{RetryAfter, WebPushError},
    message::WebPushMessage,
};
use http_types::{Method, Request, Response, StatusCode};
use serde_json;

#[derive(Deserialize, Serialize, Debug, PartialEq)]
struct ErrorInfo {
    code: u16,
    errno: u16,
    error: String,
    message: String,
}

pub fn build_request(message: WebPushMessage) -> Request {
    let mut builder = Request::new(Method::Post, message.endpoint);
    builder.insert_header("TTL", format!("{}", message.ttl));

    if let Some(payload) = message.payload {
        builder.insert_header("Content-Encoding", payload.content_encoding);
        builder.insert_header("Content-Length", format!("{}", payload.content.len()));
        builder.insert_header("Content-Type", "application/octet-stream");

        for (k, v) in payload.crypto_headers.into_iter() {
            builder.insert_header(k, v);
        }

        builder.set_body(payload.content);
    }

    builder
}

/// Read a web push response, particularly to find ot whether it errored
pub async fn read_response(mut response: Response) -> Result<(), WebPushError> {
    let retry_after = response
        .header("Retry-After")
        .map(|h| h.last().as_str())
        .and_then(RetryAfter::from_str);

    let response_status = response.status();

    trace!("Response status: {}", response_status);

    let body = response.body_bytes().await?;

    trace!("Body: {:?}", body);
    trace!("Body text: {:?}", std::str::from_utf8(&body));

    let response = parse_response(response_status, body.to_vec());

    debug!("Response: {:?}", response);

    if let Err(WebPushError::ServerError(None)) = response {
        Err(WebPushError::ServerError(retry_after))
    } else {
        Ok(response?)
    }
}

pub fn parse_response(response_status: StatusCode, body: Vec<u8>) -> Result<(), WebPushError> {
    match response_status {
        status if status.is_success() => Ok(()),
        status if status.is_server_error() => Err(WebPushError::ServerError(None)),

        StatusCode::Unauthorized => Err(WebPushError::Unauthorized),
        StatusCode::Gone => Err(WebPushError::EndpointNotValid),
        StatusCode::NotFound => Err(WebPushError::EndpointNotFound),
        StatusCode::PayloadTooLarge => Err(WebPushError::PayloadTooLarge),

        StatusCode::BadRequest => match String::from_utf8(body) {
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
    use crate::{
        error::WebPushError,
        http_ece::ContentEncoding,
        message::{SubscriptionInfo, WebPushMessageBuilder},
        web_push::*,
    };
    use http_types::{StatusCode, Url};

    #[test]
    fn builds_a_correct_request_with_empty_payload() {
        let info = SubscriptionInfo::new(
            "http://google.com",
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            "xS03Fi5ErfTNH_l9WHE9Ig",
        );

        let mut builder = WebPushMessageBuilder::new(&info).unwrap();

        builder.set_ttl(420);

        let request = build_request(builder.build().unwrap());
        let ttl = request.header("TTL").unwrap().as_str();
        let expected_uri: Url = "http://google.com".parse().unwrap();

        assert_eq!("420", ttl);
        assert_eq!(expected_uri.host(), request.url().host());
    }

    #[test]
    fn builds_a_correct_request_with_payload() {
        let info = SubscriptionInfo::new(
            "http://google.com",
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            "xS03Fi5ErfTNH_l9WHE9Ig",
        );

        let mut builder = WebPushMessageBuilder::new(&info).unwrap();

        builder.set_payload(ContentEncoding::AesGcm, "test".as_bytes());

        let request = build_request(builder.build().unwrap());
        let encoding = request.header("Content-Encoding").unwrap().as_str();
        let length = request.header("Content-Length").unwrap().as_str();
        let expected_uri: Url = "http://google.com".parse().unwrap();

        assert_eq!("3070", length);
        assert_eq!("aesgcm", encoding);
        assert_eq!(expected_uri.host(), request.url().host());
    }

    #[test]
    fn parses_a_successful_response_correctly() {
        assert_eq!(Ok(()), parse_response(StatusCode::Ok, vec![]))
    }

    #[test]
    fn parses_an_unauthorized_response_correctly() {
        assert_eq!(
            Err(WebPushError::Unauthorized),
            parse_response(StatusCode::Unauthorized, vec![])
        )
    }

    #[test]
    fn parses_a_gone_response_correctly() {
        assert_eq!(
            Err(WebPushError::EndpointNotValid),
            parse_response(StatusCode::Gone, vec![])
        )
    }

    #[test]
    fn parses_a_not_found_response_correctly() {
        assert_eq!(
            Err(WebPushError::EndpointNotFound),
            parse_response(StatusCode::NotFound, vec![])
        )
    }

    #[test]
    fn parses_a_payload_too_large_response_correctly() {
        assert_eq!(
            Err(WebPushError::PayloadTooLarge),
            parse_response(StatusCode::PayloadTooLarge, vec![])
        )
    }

    #[test]
    fn parses_a_server_error_response_correctly() {
        assert_eq!(
            Err(WebPushError::ServerError(None)),
            parse_response(StatusCode::InternalServerError, vec![])
        )
    }

    #[test]
    fn parses_a_bad_request_response_with_no_body_correctly() {
        assert_eq!(
            Err(WebPushError::BadRequest(None)),
            parse_response(StatusCode::BadRequest, vec![])
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
            parse_response(StatusCode::BadRequest, json.as_bytes().to_vec())
        )
    }
}
