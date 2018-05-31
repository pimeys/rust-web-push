use message::WebPushMessage;

use hyper::{
    Request,
    StatusCode,
    Body,
};

use http::{
    header::{
        CONTENT_LENGTH,
        CONTENT_TYPE,
        AUTHORIZATION,
    },
};

use error::WebPushError;
use serde_json;
use base64;

#[derive(Deserialize, Serialize, Debug)]
pub enum GcmError {
    MissingRegistration,
    InvalidRegistration,
    NotRegistered,
    InvalidPackageName,
    MismatchSenderId,
    InvalidParameters,
    MessageTooBig,
    InvalidDataKey,
    InvalidTtl,
    Unavailable,
    InternalServerError,
    DeviceMessageRateExceeded,
    TopicsMessageRateExceeded,
    InvalidApnsCredential,
}

impl<'a> From<&'a GcmError> for WebPushError {
    fn from(e: &GcmError) -> WebPushError {
        match e {
            &GcmError::MissingRegistration => WebPushError::EndpointNotFound,
            &GcmError::InvalidRegistration => WebPushError::EndpointNotValid,
            &GcmError::NotRegistered       => WebPushError::EndpointNotValid,
            &GcmError::InvalidPackageName  => WebPushError::InvalidPackageName,
            &GcmError::MessageTooBig       => WebPushError::PayloadTooLarge,
            &GcmError::InvalidTtl          => WebPushError::InvalidTtl,
            &GcmError::Unavailable         => WebPushError::ServerError(None),
            &GcmError::InternalServerError => WebPushError::ServerError(None),
            e                              => WebPushError::Other(format!("{:?}", e)),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct GcmResponse {
    pub message_id: Option<u64>,
    pub error: Option<GcmError>,
    pub multicast_id: Option<i64>,
    pub success: Option<u64>,
    pub failure: Option<u64>,
    pub canonical_ids: Option<u64>,
    pub results: Option<Vec<MessageResult>>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct MessageResult {
    pub message_id: Option<String>,
    pub registration_id: Option<String>,
    pub error: Option<GcmError>,
}

#[derive(Deserialize, Serialize)]
struct GcmData {
    registration_ids: Vec<String>,
    raw_data: Option<String>,
}

pub fn build_request(message: WebPushMessage) -> Request<Body> {
    let uri = match message.endpoint.host() {
        Some("fcm.googleapis.com") =>
            "https://fcm.googleapis.com/fcm/send",
        _ =>
            "https://android.googleapis.com/gcm/send",
    };

    let mut builder = Request::builder();
    builder.method("POST");
    builder.uri(uri);

    if let Some(ref gcm_key) = message.gcm_key {
        builder.header(
            AUTHORIZATION,
            format!("key={}", gcm_key).as_bytes(),
        );
    }

    let mut registration_ids = Vec::with_capacity(1);

    if let Some(token) = message.endpoint.path().split("/").last() {
        registration_ids.push(token.to_string());
    }

    let raw_data = match message.payload {
        Some(payload) => {
            for (k, v) in payload.crypto_headers.into_iter() {
                let v: &str = v.as_ref();
                builder.header(k, v);
            }

            Some(base64::encode(&payload.content))
        },
        None =>
            None,
    };

    let gcm_data = GcmData {
        registration_ids: registration_ids,
        raw_data: raw_data,
    };

    let json_payload = serde_json::to_string(&gcm_data).unwrap();

    builder.header(
        CONTENT_TYPE,
        "application/json",
    );

    builder.header(
        CONTENT_LENGTH,
        format!("{}", json_payload.len() as u64).as_bytes(),
    );

    builder.body(json_payload.into()).unwrap()
}

pub fn parse_response(response_status: StatusCode, body: Vec<u8>) -> Result<(), WebPushError> {
    match response_status {
        StatusCode::OK => {
            let body_str                  = String::from_utf8(body)?;
            let gcm_response: GcmResponse = serde_json::from_str(&body_str)?;

            if let Some(0) = gcm_response.failure {
                Ok(())
            } else {
                match gcm_response.results {
                    Some(results) => match results.first() {
                        Some(result) => {
                            match result.error {
                                Some(ref error) => Err(WebPushError::from(error)),
                                _               => Err(WebPushError::Other(String::from("UnknownError")))
                            }
                        },
                        _ => Err(WebPushError::Other(String::from("UnknownError")))
                    },
                    _ => Err(WebPushError::Other(String::from("UnknownError")))
                }
            }
        },
        StatusCode::UNAUTHORIZED           => Err(WebPushError::Unauthorized),
        StatusCode::BAD_REQUEST            => {
            let body_str                  = String::from_utf8(body)?;
            let gcm_response: GcmResponse = serde_json::from_str(&body_str)?;

            match gcm_response.error {
                Some(e) => Err(WebPushError::from(&e)),
                _       => Err(WebPushError::BadRequest(None))
            }
        },
        status if status.is_server_error() => Err(WebPushError::ServerError(None)),
        e                                  => Err(WebPushError::Other(format!("{:?}", e))),
    }
}

#[cfg(test)]
mod tests {
    use services::firebase::*;
    use hyper::StatusCode;
    use http_ece::ContentEncoding;
    use error::WebPushError;
    use message::{WebPushMessageBuilder, SubscriptionInfo};
    use hyper::Uri;

    #[test]
    fn builds_a_correct_request_with_empty_payload() {
        let info = SubscriptionInfo::new(
            "https://android.googleapis.com/gcm/send/device_token_2",
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            "xS03Fi5ErfTNH_l9WHE9Ig"
        );

        let mut builder = WebPushMessageBuilder::new(&info).unwrap();

        builder.set_gcm_key("test_key");
        builder.set_ttl(420);
        builder.set_payload(ContentEncoding::AesGcm, "test".as_bytes());

        let request = build_request(builder.build().unwrap());

        let authorization = request
            .headers()
            .get("Authorization")
            .unwrap()
            .to_str()
            .unwrap();

        let expected_uri: Uri = "https://android.googleapis.com/gcm/send".parse().unwrap();

        assert_eq!("key=test_key", authorization);
        assert_eq!(expected_uri.host(), request.uri().host());
        assert_eq!(expected_uri.path(), request.uri().path());
    }

    #[test]
    fn builds_a_correct_request_with_a_payload() {
        let info = SubscriptionInfo::new(
            "https://fcm.googleapis.com/gcm/send/device_token_2",
            "BLMbF9ffKBiWQLCKvTHb6LO8Nb6dcUh6TItC455vu2kElga6PQvUmaFyCdykxY2nOSSL3yKgfbmFLRTUaGv4yV8",
            "xS03Fi5ErfTNH_l9WHE9Ig"
        );

        let mut builder = WebPushMessageBuilder::new(&info).unwrap();

        builder.set_gcm_key("test_key");
        builder.set_ttl(420);
        builder.set_payload(ContentEncoding::AesGcm, "test".as_bytes());

        let request = build_request(builder.build().unwrap());

        let authorization = request
            .headers()
            .get("Authorization")
            .unwrap()
            .to_str()
            .unwrap();

        let expected_uri: Uri = "https://fcm.googleapis.com/fcm/send".parse().unwrap();
        let length = request.headers().get("Content-Length").unwrap();

        assert_eq!("key=test_key", authorization);
        assert_eq!(expected_uri.host(), request.uri().host());
        assert_eq!(expected_uri.path(), request.uri().path());
        assert_eq!("4149", length);
    }

    #[test]
    fn parses_a_successful_response_correctly() {
        let response = r#"
        {
            "message_id": 12,
            "multicast_id": 33,
            "success": 1,
            "failure": 0
        }
        "#;
        assert_eq!(Ok(()), parse_response(StatusCode::OK, response.as_bytes().to_vec()))
    }

    #[test]
    fn parses_a_missing_registration_response_correctly() {
        let response = r#"
        {
            "message_id": 12,
            "multicast_id": 33,
            "success": 0,
            "failure": 1,
            "results": [{"error":"MissingRegistration"}]
        }
        "#;
        assert_eq!(Err(WebPushError::EndpointNotFound),
                   parse_response(StatusCode::OK, response.as_bytes().to_vec()))
    }

    #[test]
    fn parses_a_invalid_registration_response_correctly() {
        let response = r#"
        {
            "message_id": 12,
            "multicast_id": 33,
            "success": 0,
            "failure": 1,
            "results": [{"error":"InvalidRegistration"}]
        }
        "#;
        assert_eq!(Err(WebPushError::EndpointNotValid),
                   parse_response(StatusCode::OK, response.as_bytes().to_vec()))
    }

    #[test]
    fn parses_a_not_registered_response_correctly() {
        let response = r#"
        {
            "message_id": 12,
            "multicast_id": 33,
            "success": 0,
            "failure": 1,
            "results": [{"error":"NotRegistered"}]
        }
        "#;
        assert_eq!(Err(WebPushError::EndpointNotValid),
                   parse_response(StatusCode::OK, response.as_bytes().to_vec()))
    }

    #[test]
    fn parses_an_invalid_package_name_response_correctly() {
        let response = r#"
        {
            "message_id": 12,
            "multicast_id": 33,
            "success": 0,
            "failure": 1,
            "results": [{"error":"InvalidPackageName"}]
        }
        "#;
        assert_eq!(Err(WebPushError::InvalidPackageName),
                   parse_response(StatusCode::OK, response.as_bytes().to_vec()))
    }

    #[test]
    fn parses_a_message_too_big_response_correctly() {
        let response = r#"
        {
            "message_id": 12,
            "multicast_id": 33,
            "success": 0,
            "failure": 1,
            "results": [{"error":"MessageTooBig"}]
        }
        "#;
        assert_eq!(Err(WebPushError::PayloadTooLarge),
                   parse_response(StatusCode::OK, response.as_bytes().to_vec()))
    }

    #[test]
    fn parses_an_invalid_data_key_response_correctly() {
        let response = r#"
        {
            "message_id": 12,
            "multicast_id": 33,
            "success": 0,
            "failure": 1,
            "results": [{"error":"InvalidDataKey"}]
        }
        "#;
        assert_eq!(Err(WebPushError::Other(String::from("InvalidDataKey"))),
                   parse_response(StatusCode::OK, response.as_bytes().to_vec()))
    }

    #[test]
    fn parses_an_invalid_ttl_response_correctly() {
        let response = r#"
        {
            "message_id": 12,
            "multicast_id": 33,
            "success": 0,
            "failure": 1,
            "results": [{"error":"InvalidTtl"}]
        }
        "#;
        assert_eq!(Err(WebPushError::InvalidTtl),
                   parse_response(StatusCode::OK, response.as_bytes().to_vec()))
    }

    #[test]
    fn parses_an_unavailable_response_correctly() {
        let response = r#"
        {
            "message_id": 12,
            "multicast_id": 33,
            "success": 0,
            "failure": 1,
            "results": [{"error":"Unavailable"}]
        }
        "#;
        assert_eq!(Err(WebPushError::ServerError(None)),
                   parse_response(StatusCode::OK, response.as_bytes().to_vec()))
    }

    #[test]
    fn parses_an_internal_server_error_response_correctly() {
        let response = r#"
        {
            "message_id": 12,
            "multicast_id": 33,
            "success": 0,
            "failure": 1,
            "results": [{"error":"InternalServerError"}]
        }
        "#;
        assert_eq!(Err(WebPushError::ServerError(None)),
                   parse_response(StatusCode::OK, response.as_bytes().to_vec()))
    }
}
