use http_types::Response;

use crate::{error::RetryAfter, message::WebPushService, services::*, WebPushError};

/// Read a web push response, particularly to find ot whether it errored
pub async fn read_response(mut response: Response, service: WebPushService) -> Result<(), WebPushError> {
    let retry_after = response
        .header("Retry-After")
        .map(|h| h.last().as_str())
        .and_then(RetryAfter::from_str);

    let response_status = response.status();

    trace!("Response status: {}", response_status);

    let body = response.body_bytes().await?;

    trace!("Body: {:?}", body);
    trace!("Body text: {:?}", std::str::from_utf8(&body));

    let response = match service {
        #[cfg(feature = "firebase")]
        WebPushService::Firebase => firebase::parse_response(response_status, body.to_vec()),
        _ => autopush::parse_response(response_status, body.to_vec()),
    };

    debug!("Response: {:?}", response);

    if let Err(WebPushError::ServerError(None)) = response {
        Err(WebPushError::ServerError(retry_after))
    } else {
        Ok(response?)
    }
}
