//! Narrow acknowledgement of a public PipeWire probe, not MFi-SAP authentication.

use std::time::Duration;

use super::handlers_ap1::RaopConnection;
use crate::error::ProtocolError;
use crate::net::server::RequestBodyPolicy;
use crate::proto::http::{HttpRequest, HttpResponse};

// PipeWire b0b792fa72451fd9a068c1a8f877d21d4c67cd3f, rtsp_do_post_auth_setup.
// Kept independent of the test fixture; this public constant is not a credential.
const PIPEWIRE_PROBE: [u8; 33] = [
    0x01, 0x59, 0x02, 0xed, 0xe9, 0x0d, 0x4e, 0xf2, 0xbd, 0x4c, 0xb6, 0x8a, 0x63, 0x30, 0x03, 0x82,
    0x07, 0xa9, 0x4d, 0xbd, 0x50, 0xd8, 0xaa, 0x46, 0x5b, 0x5d, 0x8c, 0x01, 0x2a, 0x0c, 0x7e, 0x1d,
    0x4e,
];
const BODY_TIMEOUT: Duration = Duration::from_secs(5);
const CONTENT_TYPE: &str = "application/octet-stream";

fn has_expected_content_type(request: &HttpRequest) -> bool {
    request.header("content-type").is_some_and(|value| {
        value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(CONTENT_TYPE)
    })
}

pub(super) fn body_policy(request: &HttpRequest) -> Result<RequestBodyPolicy, ProtocolError> {
    // The shared parser already rejects malformed/duplicate lengths and transfer framing.
    let length = request
        .header("content-length")
        .and_then(|value| value.parse::<usize>().ok());
    if length != Some(PIPEWIRE_PROBE.len()) {
        return Err(ProtocolError::InvalidRtsp(
            "invalid PipeWire probe length".into(),
        ));
    }
    Ok(RequestBodyPolicy {
        max_bytes: PIPEWIRE_PROBE.len(),
        completion_timeout: Some(BODY_TIMEOUT),
    })
}

pub(super) fn handle(
    _conn: &mut RaopConnection,
    request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let valid_type = has_expected_content_type(request);
    if !valid_type || request.data() != Some(PIPEWIRE_PROBE.as_slice()) {
        *response =
            super::rtsp::new_response(400, "Bad Request", request.header("CSeq").unwrap_or("0"));
        response.add_header("Connection", "close");
        response.set_disconnect(true);
    }
    response.add_header("Content-Length", "0");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with_headers(headers: &str) -> HttpRequest {
        let mut req = HttpRequest::new();
        let wire = format!("POST /auth-setup RTSP/1.0\r\n{headers}\r\n");
        req.add_data(wire.as_bytes()).unwrap();
        req
    }

    #[test]
    fn body_policy_accepts_expected_headers() {
        let req = request_with_headers(
            "Content-Length: 33\r\nContent-Type: application/octet-stream\r\n",
        );
        let policy = body_policy(&req).unwrap();
        assert_eq!(policy.max_bytes, PIPEWIRE_PROBE.len());
        assert_eq!(policy.completion_timeout, Some(BODY_TIMEOUT));
    }

    #[test]
    fn body_policy_rejects_invalid_length_only() {
        let wrong_len = request_with_headers(
            "Content-Length: 32\r\nContent-Type: application/octet-stream\r\n",
        );
        assert!(body_policy(&wrong_len).is_err());
    }

    #[test]
    fn content_type_validation_is_still_strict() {
        let wrong_type = request_with_headers(
            "Content-Length: 33\r\nContent-Type: text/plain\r\n",
        );
        assert!(!has_expected_content_type(&wrong_type));
    }

    #[test]
    fn body_policy_accepts_content_type_with_case_and_whitespace() {
        let req = request_with_headers(
            "Content-Length: 33\r\nContent-Type:\tApplication/Octet-Stream\t\r\n",
        );
        assert!(body_policy(&req).is_ok());
    }
}
