//! HTTP Digest authentication (RFC 2617) for optional password protection.

use md5::{Digest, Md5};
use rand::Rng;
use subtle::ConstantTimeEq;

fn md5_to_hex(hash: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for &b in hash {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Compute the Digest auth response hash.
/// response = MD5(MD5(username:realm:password):nonce:MD5(method:uri))
fn get_response(
    username: &str,
    realm: &str,
    password: &str,
    nonce: &str,
    method: &str,
    uri: &str,
) -> String {
    // HA1 = MD5(username:realm:password)
    let mut h = Md5::new();
    h.update(username.as_bytes());
    h.update(b":");
    h.update(realm.as_bytes());
    h.update(b":");
    h.update(password.as_bytes());
    let ha1: [u8; 16] = h.finalize().into();
    let ha1_hex = md5_to_hex(&ha1);

    // HA2 = MD5(method:uri)
    let mut h = Md5::new();
    h.update(method.as_bytes());
    h.update(b":");
    h.update(uri.as_bytes());
    let ha2: [u8; 16] = h.finalize().into();
    let ha2_hex = md5_to_hex(&ha2);

    // response = MD5(HA1:nonce:HA2)
    let mut h = Md5::new();
    h.update(ha1_hex.as_bytes());
    h.update(b":");
    h.update(nonce.as_bytes());
    h.update(b":");
    h.update(ha2_hex.as_bytes());
    let result: [u8; 16] = h.finalize().into();
    md5_to_hex(&result)
}

/// Generate a random hex nonce string. Equivalent to digest_generate_nonce.
pub fn generate_nonce(len: usize) -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.r#gen()).collect();
    let mut h = Md5::new();
    h.update(&bytes);
    let hash: [u8; 16] = h.finalize().into();
    let hex = md5_to_hex(&hash);
    hex[..len.min(32)].to_string()
}

/// Validate an HTTP Digest Authorization header. Equivalent to digest_is_valid.
pub fn is_valid(
    realm: &str,
    password: &str,
    nonce: &str,
    method: &str,
    uri: &str,
    authorization: Option<&str>,
) -> bool {
    let auth = match authorization {
        Some(a) => a.trim(),
        None => return false,
    };

    let Some((scheme, params)) = auth.split_once(char::is_whitespace) else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("Digest") {
        return false;
    }
    let params = params.trim_start();
    if params.is_empty() {
        return false;
    }

    let mut username = None;
    let mut auth_realm = None;
    let mut auth_nonce = None;
    let mut auth_uri = None;
    let mut response = None;

    for part in split_quoted_csv(params) {
        let part = part.trim();
        if let Some(val) = extract_quoted(part, "username") {
            username = Some(val);
        } else if let Some(val) = extract_quoted(part, "realm") {
            auth_realm = Some(val);
        } else if let Some(val) = extract_quoted(part, "nonce") {
            auth_nonce = Some(val);
        } else if let Some(val) = extract_quoted(part, "uri") {
            auth_uri = Some(val);
        } else if let Some(val) = extract_quoted(part, "response") {
            response = Some(val);
        }
    }

    let (username, auth_realm, auth_nonce, auth_uri, response) =
        match (username, auth_realm, auth_nonce, auth_uri, response) {
            (Some(u), Some(r), Some(n), Some(i), Some(p)) => (u, r, n, i, p),
            _ => return false,
        };

    if auth_realm != realm || auth_nonce != nonce || auth_uri != uri {
        return false;
    }

    let our_response = get_response(username, realm, password, nonce, method, uri);
    // Constant-time comparison to avoid leaking the expected digest via timing.
    response.as_bytes().ct_eq(our_response.as_bytes()).into()
}

/// Extract a quoted value from a "key=\"value\"" pair.
fn extract_quoted<'a>(part: &'a str, key: &str) -> Option<&'a str> {
    let (lhs, rhs) = part.split_once('=')?;
    if !lhs.trim().eq_ignore_ascii_case(key) {
        return None;
    }
    let rhs = rhs.trim();
    if rhs.len() < 2 || !rhs.starts_with('"') || !rhs.ends_with('"') {
        return None;
    }
    Some(&rhs[1..rhs.len() - 1])
}

/// Split a comma-separated auth parameter string without breaking quoted commas.
fn split_quoted_csv(input: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_quotes = false;
    let mut start = 0usize;

    for (idx, ch) in input.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                out.push(&input[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    out.push(&input[start..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_digest_with_mixed_case_scheme_and_spaced_keys() {
        let realm = "raop";
        let password = "secret";
        let nonce = "0011223344556677";
        let method = "SETUP";
        let uri = "/stream";
        let username = "alice";
        let response = get_response(username, realm, password, nonce, method, uri);
        let auth = format!(
            "digest username = \"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\""
        );

        assert!(is_valid(
            realm,
            password,
            nonce,
            method,
            uri,
            Some(&auth)
        ));
    }

    #[test]
    fn rejects_scheme_prefix_confusion() {
        let auth = "DigestX username=\"u\", realm=\"r\", nonce=\"n\", uri=\"/\", response=\"x\"";
        assert!(!is_valid("r", "p", "n", "GET", "/", Some(auth)));
    }

    #[test]
    fn supports_commas_inside_quoted_values() {
        let realm = "raop";
        let password = "secret";
        let nonce = "0011223344556677";
        let method = "POST";
        let uri = "/announce";
        let username = "alice,bob";
        let response = get_response(username, realm, password, nonce, method, uri);
        let auth = format!(
            "Digest username=\"{username}\",realm=\"{realm}\",nonce=\"{nonce}\",uri=\"{uri}\",response=\"{response}\""
        );

        assert!(is_valid(
            realm,
            password,
            nonce,
            method,
            uri,
            Some(&auth)
        ));
    }

    #[test]
    fn nonce_generation_is_hex_and_capped() {
        let short = generate_nonce(8);
        assert_eq!(short.len(), 8);
        assert!(short.chars().all(|c| c.is_ascii_hexdigit()));

        let capped = generate_nonce(128);
        assert_eq!(capped.len(), 32);
        assert!(capped.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
