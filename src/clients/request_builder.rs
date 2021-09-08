//! Functions used to send and consume push http messages.
//! This module can be used to build custom clients.

use http::{Request, StatusCode};
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE};

use crate::{error::WebPushError, message::WebPushMessage};

#[derive(Deserialize, Serialize, Debug, PartialEq)]
struct ErrorInfo {
    code: u16,
    errno: u16,
    error: String,
    message: String,
}

/// Builds the request to send to the push service.
///
/// This function is generic over the request body, this means that you can swap out client implementations
/// even if they use different body types.
///
/// # Example
///
/// ```no_run
/// # use web_push::{SubscriptionInfo, WebPushMessageBuilder};
/// # use web_push::request_builder::build_request;
/// let info = SubscriptionInfo::new(
///  "http://google.com",
///  "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
///  "xS03Fi5ErfTNH_l9WHE9Ig",
///  );
///
///  let mut builder = WebPushMessageBuilder::new(&info).unwrap();
///
///  //Build the request for isahc
///  let request = build_request::<isahc::Body>(builder.build().unwrap());
///  //Send using a http client
/// ```
pub fn build_request<T>(message: WebPushMessage) -> Request<T>
where
    T: From<Vec<u8>> + From<&'static str>, //This bound can be reduced to a &[u8] instead of str if needed
{
    let mut builder = Request::builder()
        .method("POST")
        .uri(message.endpoint)
        .header("TTL", format!("{}", message.ttl).as_bytes());

    if let Some(payload) = message.payload {
        builder = builder
            .header(CONTENT_ENCODING, payload.content_encoding)
            .header(CONTENT_LENGTH, format!("{}", payload.content.len() as u64).as_bytes())
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

/// Parses the response from the push service, and will return `Err` if the request was bad.
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
                Err(_) if body_str.is_empty() => Err(WebPushError::BadRequest(None)),
                Err(_) => Err(WebPushError::BadRequest(None)),
            },
        },

        e => Err(WebPushError::Other(format!("{:?}", e))),
    }
}

#[cfg(test)]
mod tests {
    use http::Uri;

    use crate::clients::request_builder::*;
    use crate::error::WebPushError;
    use crate::http_ece::ContentEncoding;
    use crate::message::WebPushMessageBuilder;

    #[test]
    fn builds_a_correct_request_with_empty_payload() {
        //This *was* a real token
        let sub = serde_json::json!({"endpoint":"https://fcm.googleapis.com/fcm/send/eKClHsXFm9E:APA91bH2x3gNOMv4dF1lQfCgIfOet8EngqKCAUS5DncLOd5hzfSUxcjigIjw9ws-bqa-KmohqiTOcgepAIVO03N39dQfkEkopubML_m3fyvF03pV9_JCB7SxpUjcFmBSVhCaWS6m8l7x",
            "expirationTime":null,
            "keys":{"p256dh":
                "BGa4N1PI79lboMR_YrwCiCsgp35DRvedt7opHcf0yM3iOBTSoQYqQLwWxAfRKE6tsDnReWmhsImkhDF_DBdkNSU",
                "auth":"EvcWjEgzr4rbvhfi3yds0A"}
        });

        let info = serde_json::from_value(sub).unwrap();

        let mut builder = WebPushMessageBuilder::new(&info).unwrap();

        builder.set_ttl(420);

        let request = build_request::<isahc::Body>(builder.build().unwrap());
        let ttl = request.headers().get("TTL").unwrap().to_str().unwrap();
        let expected_uri: Uri = "fcm.googleapis.com".parse().unwrap();

        assert_eq!("420", ttl);
        assert_eq!(expected_uri.host(), request.uri().host());
    }

    #[test]
    fn builds_a_correct_request_with_payload() {
        //This *was* a real token
        let sub = serde_json::json!({"endpoint":"https://fcm.googleapis.com/fcm/send/eKClHsXFm9E:APA91bH2x3gNOMv4dF1lQfCgIfOet8EngqKCAUS5DncLOd5hzfSUxcjigIjw9ws-bqa-KmohqiTOcgepAIVO03N39dQfkEkopubML_m3fyvF03pV9_JCB7SxpUjcFmBSVhCaWS6m8l7x",
            "expirationTime":null,
            "keys":{"p256dh":
                "BGa4N1PI79lboMR_YrwCiCsgp35DRvedt7opHcf0yM3iOBTSoQYqQLwWxAfRKE6tsDnReWmhsImkhDF_DBdkNSU",
                "auth":"EvcWjEgzr4rbvhfi3yds0A"}
        });

        let info = serde_json::from_value(sub).unwrap();

        let mut builder = WebPushMessageBuilder::new(&info).unwrap();

        builder.set_payload(ContentEncoding::Aes128Gcm, "test".as_bytes());

        let request = build_request::<isahc::Body>(builder.build().unwrap());

        let encoding = request.headers().get("Content-Encoding").unwrap().to_str().unwrap();

        let length = request.headers().get("Content-Length").unwrap();
        let expected_uri: Uri = "fcm.googleapis.com".parse().unwrap();

        assert_eq!("230", length);
        assert_eq!("aes128gcm", encoding);
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
