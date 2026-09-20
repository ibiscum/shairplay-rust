//! AP2 screen-mirroring video key derivation (SHA-512 based).
//!
//! Derivation scheme (from SteeBono/airplayreceiver):
//! - `eaesKey   = SHA-512(fairplay_key ‖ ecdh_shared)[0..16]`
//! - `streamKey = SHA-512("AirPlayStreamKey{id}" ‖ seed)[0..16]`
//! - `streamIV  = SHA-512("AirPlayStreamIV{id}"  ‖ seed)[0..16]`
//!
//! where `seed` is either the audio AES key directly (Stage-3 path) or `eaesKey`
//! (full FairPlay + ECDH path). See `AP2-STATUS.md` for the protocol background.

use sha2::{Digest, Sha512};

fn sha512_16(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Derive the intermediate `eaesKey` from the FairPlay-decrypted key and the
/// pair-verify ECDH shared secret: `SHA-512(fairplay_key ‖ ecdh)[0..16]`.
pub(crate) fn derive_eaes_key(fairplay_key: &[u8; 16], ecdh_shared: &[u8; 32]) -> [u8; 16] {
    sha512_16(&[fairplay_key, ecdh_shared])
}

/// Derive the per-stream `(key, iv)` for a video stream from a 16-byte `seed`
/// (either the audio AES key or [`derive_eaes_key`]) and the stream connection id.
pub(crate) fn derive_stream_key_iv(
    seed: &[u8; 16],
    stream_connection_id: u64,
) -> ([u8; 16], [u8; 16]) {
    let key = sha512_16(&[
        format!("AirPlayStreamKey{stream_connection_id}").as_bytes(),
        seed,
    ]);
    let iv = sha512_16(&[
        format!("AirPlayStreamIV{stream_connection_id}").as_bytes(),
        seed,
    ]);
    (key, iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_eaes_key_vector() {
        let fairplay_key = *b"0123456789abcdef";
        let ecdh_shared = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";

        let got = derive_eaes_key(&fairplay_key, &ecdh_shared);
        assert_eq!(hex::encode(got), "eef98dc329d37f68929fb9564ed24ad3");
    }

    #[test]
    fn derive_stream_key_iv_vector() {
        let seed = *b"0123456789abcdef";
        let (key, iv) = derive_stream_key_iv(&seed, 42);

        assert_eq!(hex::encode(key), "732fb8cfca771985310cbfbf976e7487");
        assert_eq!(hex::encode(iv), "28a0ca55a13f0c21252d8727227b9fc1");
    }
}
