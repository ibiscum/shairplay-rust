//! RSA key handling for the well-known AirPort Express private key.

use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::SignatureEncoding;
use rsa::signature::hazmat::PrehashSigner;
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPrivateKey};
use std::path::Path;

use base64::Engine as _;

use crate::error::CryptoError;

/// Standard-alphabet base64 used by RAOP: unpadded on encode, and padding-indifferent
/// plus trailing-bit-lenient on decode — matching the original RTSP base64 behaviour
/// (accepts both padded and unpadded peer input).
const B64: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    base64::engine::GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

pub(crate) const RSA_KEY_PEM_ENV: &str = "SHAIRPLAY_RSA_KEY_PEM";
pub(crate) const RSA_KEY_PATH_ENV: &str = "SHAIRPLAY_RSA_KEY_PATH";

/// RSA key for RAOP authentication. Equivalent to rsakey_t.
pub(crate) struct RsaKey {
    key: RsaPrivateKey,
}

impl RsaKey {
    /// Load an RSA private key from a PEM string. Equivalent to rsakey_init_pem.
    pub(crate) fn from_pem(pem: &str) -> Result<Self, CryptoError> {
        let key = RsaPrivateKey::from_pkcs1_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs8_pem(pem))
            .map_err(|e| CryptoError::RsaKey(e.to_string()))?;
        Ok(Self { key })
    }

    /// Load the RSA key from a PEM string env var or PEM file path.
    ///
    /// Resolution order:
    /// 1) `path_override` argument (if provided)
    /// 2) `SHAIRPLAY_RSA_KEY_PEM` (supports `\\n` escaped newlines)
    /// 3) `SHAIRPLAY_RSA_KEY_PATH`
    pub(crate) fn from_env(path_override: Option<&Path>) -> Result<Self, CryptoError> {
        let _ = dotenvy::dotenv();

        if let Some(path) = path_override {
            let pem = std::fs::read_to_string(path)
                .map_err(|_| CryptoError::RsaKey("failed to read RSA key file".into()))?;
            return Self::from_pem(&pem);
        }

        if let Ok(pem_raw) = std::env::var(RSA_KEY_PEM_ENV) {
            let pem = pem_raw.replace("\\n", "\n");
            return Self::from_pem(&pem);
        }

        if let Ok(path) = std::env::var(RSA_KEY_PATH_ENV) {
            let pem = std::fs::read_to_string(path)
                .map_err(|_| CryptoError::RsaKey("failed to read RSA key file".into()))?;
            return Self::from_pem(&pem);
        }

        Err(CryptoError::RsaKey(
            "missing RSA key: set SHAIRPLAY_RSA_KEY_PEM or SHAIRPLAY_RSA_KEY_PATH".into(),
        ))
    }

    /// Sign an Apple-Challenge for the `Apple-Response` RAOP auth header.
    /// Equivalent to rsakey_sign.
    ///
    /// The signed payload is `challenge ‖ ip_addr ‖ hw_addr` — the base64-decoded
    /// challenge, then the receiver's IP address, then its hardware (MAC) address,
    /// concatenated in exactly that order and zero-padded to a minimum of 32 bytes.
    /// The client reconstructs the same byte layout to validate the response, so the
    /// field order and padding must match the AirPort/shairport reference exactly.
    /// Signed with PKCS#1 v1.5 (type 1 padding, no hash-OID prefix); returns the
    /// base64-encoded signature.
    pub(crate) fn sign_challenge(
        &self,
        b64_challenge: &str,
        ip_addr: &[u8],
        hw_addr: &[u8],
    ) -> Result<String, CryptoError> {
        if hw_addr.len() != 6 {
            return Err(CryptoError::RsaKey("invalid hw_addr length".into()));
        }
        if ip_addr.len() != 4 && ip_addr.len() != 16 {
            return Err(CryptoError::RsaKey("invalid ip_addr length".into()));
        }

        let challenge = B64
            .decode(b64_challenge)
            .map_err(|_| CryptoError::RsaKey("invalid base64 challenge".into()))?;

        // Build the data to sign: challenge + ip + hwaddr, min 32 bytes
        let mut data = Vec::with_capacity(32);
        data.extend_from_slice(&challenge);
        data.extend_from_slice(ip_addr);
        data.extend_from_slice(hw_addr);
        // Pad with zeros to minimum 32 bytes (matching C behavior)
        if data.len() < 32 {
            data.resize(32, 0);
        }

        // PKCS#1 v1.5 sign without hash OID prefix (matching C's manual padding)
        let signing_key: SigningKey<sha1::Sha1> = SigningKey::new_unprefixed(self.key.clone());
        let signature = signing_key
            .sign_prehash(&data)
            .map_err(|e| CryptoError::RsaKey(e.to_string()))?;

        Ok(B64.encode(signature.to_vec()))
    }

    /// Base64-decode and RSA-OAEP-decrypt (SHA-1) to extract an AES key.
    /// Equivalent to rsakey_decrypt.
    pub(crate) fn decrypt(&self, b64_input: &str) -> Result<Vec<u8>, CryptoError> {
        let ciphertext = B64.decode(b64_input).map_err(|_| CryptoError::RsaDecrypt)?;

        let key_len = self.key.n().bits() / 8;
        // Reject ciphertext larger than the modulus: it cannot be a valid RSA
        // block, and copying it into the modulus-sized buffer below would panic.
        if ciphertext.len() > key_len {
            return Err(CryptoError::RsaDecrypt);
        }
        // Pad ciphertext to key length (matching C: memcpy to end of buffer)
        let mut padded = vec![0u8; key_len];
        let offset = key_len.saturating_sub(ciphertext.len());
        padded[offset..offset + ciphertext.len()].copy_from_slice(&ciphertext);

        let padding = Oaep::new::<sha1::Sha1>();
        self.key
            .decrypt(padding, &padded)
            .map_err(|_| CryptoError::RsaDecrypt)
    }

    /// Base64-decode only (no decryption). Equivalent to rsakey_decode.
    pub(crate) fn decode(&self, b64_input: &str) -> Result<Vec<u8>, CryptoError> {
        B64.decode(b64_input)
            .map_err(|_| CryptoError::RsaKey("invalid base64 input".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
    use rsa::rand_core::OsRng;
    use rsa::RsaPublicKey;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_path(prefix: &str, suffix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}{suffix}", std::process::id()))
    }

    fn generate_test_pem() -> String {
        let key = RsaPrivateKey::new(&mut OsRng, 2048).expect("test RSA key generation");
        key.to_pkcs1_pem(LineEnding::LF)
            .expect("encode test key to pkcs1 pem")
            .to_string()
    }

    #[test]
    fn from_env_loads_key_from_path_override() {
        let pem = generate_test_pem();
        let key_path = unique_test_path("shairplay-rsa", ".pem");
        fs::write(&key_path, pem).expect("write key file");

        let loaded = RsaKey::from_env(Some(&key_path));

        let _ = fs::remove_file(&key_path);
        assert!(loaded.is_ok(), "from_env should load key from explicit path");
    }

    #[test]
    fn from_env_loads_key_after_dotenv_file_is_loaded() {
        let pem = generate_test_pem();
        let escaped_pem = pem.replace('\n', "\\n");
        let dotenv_path = unique_test_path("shairplay-rsa", ".env");
        fs::write(
            &dotenv_path,
            format!("{}=\"{}\"\n", RSA_KEY_PEM_ENV, escaped_pem),
        )
        .expect("write dotenv file");

        dotenvy::from_filename_override(&dotenv_path).expect("load dotenv file");
        let loaded = RsaKey::from_env(None);

        let _ = fs::remove_file(&dotenv_path);
        assert!(loaded.is_ok(), "from_env should load key from dotenv env var");
    }

    #[test]
    fn from_env_none_returns_missing_key_error_when_vars_unset() {
        let current_exe = std::env::current_exe().expect("resolve test binary path");
        let output = Command::new(current_exe)
            .arg("--exact")
            .arg("from_env_none_returns_missing_key_error_when_vars_unset_helper")
            .arg("--ignored")
            .env_remove(RSA_KEY_PEM_ENV)
            .env_remove(RSA_KEY_PATH_ENV)
            .output()
            .expect("spawn isolated test process");

        assert!(
            output.status.success(),
            "isolated helper test failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "helper for isolated env-missing check"]
    fn from_env_none_returns_missing_key_error_when_vars_unset_helper() {
        let result = RsaKey::from_env(None);
        match result {
            Err(CryptoError::RsaKey(message)) => {
                assert!(
                    message.contains("missing RSA key"),
                    "unexpected error message: {message}"
                );
            }
            Ok(_) => panic!("expected missing-key error, got successful key load"),
            Err(other) => panic!("expected CryptoError::RsaKey, got: {other}"),
        }
    }

    #[test]
    fn sign_challenge_rejects_invalid_lengths() {
        let key = RsaKey::from_env(None).expect("RSA key from env valid");
        let challenge = B64.encode(b"abc");

        assert!(
            key.sign_challenge(&challenge, &[127, 0, 0], &[0, 1, 2, 3, 4, 5])
                .is_err()
        );
        assert!(
            key.sign_challenge(&challenge, &[127, 0, 0, 1], &[0, 1, 2, 3, 4])
                .is_err()
        );
    }

    #[test]
    fn sign_challenge_accepts_ipv4_and_ipv6_lengths() {
        let key = RsaKey::from_env(None).expect("RSA key from env valid");
        let challenge = B64.encode(b"abcd");
        let mac = [0, 1, 2, 3, 4, 5];

        let sig4 = key
            .sign_challenge(&challenge, &[127, 0, 0, 1], &mac)
            .expect("valid IPv4 signing");
        let sig6 = key
            .sign_challenge(&challenge, &[0u8; 16], &mac)
            .expect("valid IPv6 signing");

        assert_eq!(B64.decode(sig4).expect("valid base64").len(), 256);
        assert_eq!(B64.decode(sig6).expect("valid base64").len(), 256);
    }

    #[test]
    fn decrypt_rejects_oversized_ciphertext() {
        let key = RsaKey::from_env(None).expect("RSA key from env valid");
        // 1024 base64 chars decode to 768 bytes, far larger than the 256-byte
        // RSA-2048 modulus. Must return Err rather than panic copying into the
        // modulus-sized buffer.
        let oversized = "A".repeat(1024);
        assert!(key.decrypt(&oversized).is_err());
    }

    #[test]
    fn decrypt_roundtrip_oaep_sha1() {
        let key = RsaKey::from_env(None).expect("RSA key from env valid");
        let public = RsaPublicKey::from(&key.key);
        let plaintext = b"0123456789abcdef";
        let ciphertext = public
            .encrypt(
                &mut rand::thread_rng(),
                Oaep::new::<sha1::Sha1>(),
                plaintext,
            )
            .expect("encrypt with airport public key");
        let b64 = B64.encode(ciphertext);

        let decrypted = key.decrypt(&b64).expect("decrypt should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_rejects_invalid_base64() {
        let key = RsaKey::from_env(None).expect("RSA key from env valid");
        assert!(key.decrypt("!!!").is_err());
    }

    #[test]
    fn decrypt_rejects_valid_b64_invalid_ciphertext() {
        let key = RsaKey::from_env(None).expect("RSA key from env valid");
        // 16 zero bytes are valid base64-decoded data but not a valid OAEP block.
        let invalid = B64.encode([0u8; 16]);
        assert!(key.decrypt(&invalid).is_err());
    }

    // --- base64 engine parity (was src/util/base64.rs, C base64_encode/decode vectors) ---

    #[test]
    fn b64_encode_is_unpadded_standard() {
        assert_eq!(B64.encode(b"Hello, AirPlay!"), "SGVsbG8sIEFpclBsYXkh");
        assert_eq!(B64.encode(b"AB"), "QUI"); // unpadded (C: use_padding = false)
        assert_eq!(B64.encode(b"ABC"), "QUJD");
        assert_eq!(B64.encode([0xff]), "/w");
        assert_eq!(B64.encode(b""), "");
    }

    #[test]
    fn b64_decode_is_padding_indifferent() {
        assert_eq!(
            B64.decode("SGVsbG8sIEFpclBsYXkh").unwrap(),
            b"Hello, AirPlay!"
        );
        // Accepts both unpadded and padded forms of the same input.
        assert_eq!(B64.decode("QUI").unwrap(), b"AB");
        assert_eq!(B64.decode("QUI=").unwrap(), b"AB");
    }

    #[test]
    fn b64_decode_rejects_invalid() {
        assert!(B64.decode("!!!").is_err());
    }
}
