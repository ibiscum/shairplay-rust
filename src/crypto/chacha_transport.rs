//! ChaCha20-Poly1305 encrypted transport for AirPlay 2 RTSP sessions.
//!
//! After pair-setup/pair-verify, all RTSP traffic is encrypted in blocks:
//! `[u16 LE: block_len] [ciphertext: block_len bytes] [auth_tag: 16 bytes]`
//!
//! The block_len (plaintext size) is used as AAD. Max block size is 1024 bytes.
//! Nonce: `[0,0,0,0, counter_u64_LE]`, counter increments per block.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha512;

use crate::error::CryptoError;

const MAX_BLOCK_LEN: usize = 0x400; // 1024
const TAG_LEN: usize = 16;

/// Encrypted channel (one direction: either encrypt or decrypt).
pub struct CipherContext {
    key: [u8; 32],
    counter: u64,
}

impl CipherContext {
    /// Create a new encryption context from a 256-bit key.
    pub(crate) fn new(key: [u8; 32]) -> Self {
        Self { key, counter: 0 }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..12].copy_from_slice(&self.counter.to_le_bytes());
        n
    }

    /// Encrypt plaintext into framed blocks. Returns the full wire bytes.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if plaintext.is_empty() {
            return Ok(Vec::new());
        }

        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let nblocks = plaintext.len().div_ceil(MAX_BLOCK_LEN);
        let mut out = Vec::with_capacity(plaintext.len() + nblocks * (2 + TAG_LEN));

        for chunk in plaintext.chunks(MAX_BLOCK_LEN) {
            if self.counter == u64::MAX {
                return Err(CryptoError::Transport(
                    "nonce counter exhausted before encryption".into(),
                ));
            }

            let block_len = (chunk.len() as u16).to_le_bytes();
            let nonce = self.nonce();

            let ct = cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: chunk,
                        aad: &block_len,
                    },
                )
                .map_err(|_| CryptoError::Transport("ChaCha20 encrypt failed".into()))?;

            // ct includes ciphertext + 16-byte tag appended by the AEAD
            out.extend_from_slice(&block_len);
            out.extend_from_slice(&ct);
            self.counter += 1;
        }
        Ok(out)
    }

    /// Decrypt framed blocks. Returns (plaintext, bytes_consumed).
    /// May consume less than input if a block is incomplete.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<(Vec<u8>, usize), CryptoError> {
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let mut plain = Vec::new();
        let mut pos = 0;

        while pos + 2 <= ciphertext.len() {
            let block_len = u16::from_le_bytes([ciphertext[pos], ciphertext[pos + 1]]) as usize;
            let frame_len = 2 + block_len + TAG_LEN;
            if pos + frame_len > ciphertext.len() {
                break; // Incomplete block
            }

            if self.counter == u64::MAX {
                return Err(CryptoError::Transport(
                    "nonce counter exhausted before decryption".into(),
                ));
            }
            if block_len == 0 {
                return Err(CryptoError::Transport(
                    "invalid framed block length: 0".into(),
                ));
            }

            let block_len_bytes = [ciphertext[pos], ciphertext[pos + 1]];
            let ct_with_tag = &ciphertext[pos + 2..pos + 2 + block_len + TAG_LEN];
            let nonce = self.nonce();

            let pt = cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: ct_with_tag,
                        aad: &block_len_bytes,
                    },
                )
                .map_err(|_| CryptoError::Transport("ChaCha20 decrypt failed".into()))?;

            plain.extend_from_slice(&pt);
            pos += frame_len;
            self.counter += 1;
        }
        Ok((plain, pos))
    }
}

/// Bidirectional encrypted channel for an RTSP connection.
pub struct EncryptedChannel {
    /// Encrypts outgoing RTSP responses.
    pub encrypt_ctx: CipherContext,
    /// Decrypts incoming RTSP requests.
    pub decrypt_ctx: CipherContext,
}

impl EncryptedChannel {
    /// Create from shared secret + HKDF salt/info pairs for write and read keys.
    pub fn new(
        shared_secret: &[u8],
        write_salt: &str,
        write_info: &str,
        read_salt: &str,
        read_info: &str,
    ) -> Result<Self, CryptoError> {
        let mut write_key = [0u8; 32];
        let mut read_key = [0u8; 32];

        let hk = Hkdf::<Sha512>::new(Some(write_salt.as_bytes()), shared_secret);
        hk.expand(write_info.as_bytes(), &mut write_key)
            .map_err(|_| CryptoError::Transport("HKDF write key failed".into()))?;

        let hk = Hkdf::<Sha512>::new(Some(read_salt.as_bytes()), shared_secret);
        hk.expand(read_info.as_bytes(), &mut read_key)
            .map_err(|_| CryptoError::Transport("HKDF read key failed".into()))?;

        Ok(Self {
            encrypt_ctx: CipherContext::new(write_key),
            decrypt_ctx: CipherContext::new(read_key),
        })
    }

    /// Create a control channel (channel 3 = server-side control).
    pub(crate) fn control(shared_secret: &[u8]) -> Result<Self, CryptoError> {
        Self::new(
            shared_secret,
            "Control-Salt",
            "Control-Read-Encryption-Key",
            "Control-Salt",
            "Control-Write-Encryption-Key",
        )
    }

    /// Create an event channel (channel 4 = server-side events).
    pub(crate) fn events(shared_secret: &[u8]) -> Result<Self, CryptoError> {
        Self::new(
            shared_secret,
            "Events-Salt",
            "Events-Write-Encryption-Key",
            "Events-Salt",
            "Events-Read-Encryption-Key",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_key() -> [u8; 32] {
        rand::random::<[u8; 32]>()
    }

    fn random_secret() -> [u8; 64] {
        let mut secret = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut secret);
        secret
    }

    fn encrypt_expected_frame(key: [u8; 32], counter: u64, plain: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new((&key).into());
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        let block_len = (plain.len() as u16).to_le_bytes();
        let ct = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plain,
                    aad: &block_len,
                },
            )
            .expect("reference encrypt should succeed");

        let mut out = Vec::with_capacity(2 + ct.len());
        out.extend_from_slice(&block_len);
        out.extend_from_slice(&ct);
        out
    }

    fn encrypt_expected_frames(key: [u8; 32], mut counter: u64, plain: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in plain.chunks(MAX_BLOCK_LEN) {
            out.extend_from_slice(&encrypt_expected_frame(key, counter, chunk));
            counter += 1;
        }
        out
    }

    #[test]
    fn roundtrip_single_block() {
        let key = random_key();
        let mut enc = CipherContext::new(key);
        let mut dec = CipherContext::new(key);

        let plain = b"Hello, AirPlay 2!";
        let ct = enc.encrypt(plain).unwrap();
        let (pt, consumed) = dec.decrypt(&ct).unwrap();
        assert_eq!(pt, plain);
        assert_eq!(consumed, ct.len());
    }

    #[test]
    fn roundtrip_multi_block() {
        let key = random_key();
        let mut enc = CipherContext::new(key);
        let mut dec = CipherContext::new(key);

        // 2500 bytes → 3 blocks (1024 + 1024 + 452)
        let plain: Vec<u8> = (0u16..2500).map(|i| (i & 0xff) as u8).collect();
        let ct = enc.encrypt(&plain).unwrap();
        assert_eq!(enc.counter, 3);

        let (pt, consumed) = dec.decrypt(&ct).unwrap();
        assert_eq!(pt, plain);
        assert_eq!(consumed, ct.len());
        assert_eq!(dec.counter, 3);
    }

    #[test]
    fn incremental_decrypt() {
        let key = random_key();
        let mut enc = CipherContext::new(key);
        let mut dec = CipherContext::new(key);

        let ct = enc.encrypt(b"test data here").unwrap();

        // Feed partial data — should consume 0
        let (pt, consumed) = dec.decrypt(&ct[..5]).unwrap();
        assert!(pt.is_empty());
        assert_eq!(consumed, 0);

        // Feed full data
        let (pt, consumed) = dec.decrypt(&ct).unwrap();
        assert_eq!(pt, b"test data here");
        assert_eq!(consumed, ct.len());
    }

    #[test]
    fn corrupted_tag_rejected() {
        let key = random_key();
        let mut enc = CipherContext::new(key);
        let mut dec = CipherContext::new(key);

        let mut ct = enc.encrypt(b"secret").unwrap();
        // Corrupt the auth tag (last byte)
        let last = ct.len() - 1;
        ct[last] ^= 0xff;

        assert!(dec.decrypt(&ct).is_err());
    }

    #[test]
    fn encrypted_channel_control() {
        let secret = random_secret();
        let server = EncryptedChannel::control(&secret).unwrap();
        assert_ne!(server.encrypt_ctx.key, [0u8; 32]);
        assert_ne!(server.decrypt_ctx.key, [0u8; 32]);
        assert_ne!(server.encrypt_ctx.key, server.decrypt_ctx.key);
    }

    #[test]
    fn encrypted_channel_events() {
        let secret = random_secret();
        let server = EncryptedChannel::events(&secret).unwrap();
        assert_ne!(server.encrypt_ctx.key, [0u8; 32]);
        assert_ne!(server.decrypt_ctx.key, [0u8; 32]);
        assert_ne!(server.encrypt_ctx.key, server.decrypt_ctx.key);
    }

    #[test]
    fn encrypt_empty_plaintext_is_noop() {
        let key = random_key();
        let mut enc = CipherContext::new(key);
        let ct = enc.encrypt(&[]).unwrap();
        assert!(ct.is_empty());
        assert_eq!(enc.counter, 0);
    }

    #[test]
    fn decrypt_rejects_zero_length_frame() {
        let key = random_key();
        let mut dec = CipherContext::new(key);
        // Complete frame for block_len=0: [len(2)] + [tag(16)].
        let mut frame = vec![0u8; 2 + TAG_LEN];
        frame[0] = 0;
        frame[1] = 0;
        assert!(matches!(
            dec.decrypt(&frame),
            Err(CryptoError::Transport(msg)) if msg.contains("block length: 0")
        ));
    }

    #[test]
    fn encrypt_rejects_counter_exhaustion() {
        let key = random_key();
        let mut enc = CipherContext::new(key);
        enc.counter = u64::MAX;
        assert!(matches!(
            enc.encrypt(b"x"),
            Err(CryptoError::Transport(msg)) if msg.contains("counter exhausted")
        ));
    }

    #[test]
    fn decrypt_rejects_counter_exhaustion() {
        let key = random_key();
        let mut enc = CipherContext::new(key);
        let frame = enc.encrypt(b"x").unwrap();

        let mut dec = CipherContext::new(key);
        dec.counter = u64::MAX;
        assert!(matches!(
            dec.decrypt(&frame),
            Err(CryptoError::Transport(msg)) if msg.contains("counter exhausted")
        ));
    }

    // --- Reference-checked framing/encryption behavior ---

    #[test]
    fn c_vector_single_block() {
        let key = random_key();
        let mut enc = CipherContext::new(key);
        let plain = b"Hello, AirPlay 2!";
        let ct = enc.encrypt(plain).unwrap();
        let expected = encrypt_expected_frame(key, 0, plain);
        assert_eq!(ct, expected);
    }

    #[test]
    fn c_vector_counter_0() {
        let key = random_key();
        let mut enc = CipherContext::new(key);
        let plain: Vec<u8> = (0u8..100).collect();
        let ct = enc.encrypt(&plain).unwrap();
        let expected = encrypt_expected_frames(key, 0, &plain);
        assert_eq!(ct, expected);
    }

    #[test]
    fn c_vector_counter_1() {
        let key = random_key();
        let mut enc = CipherContext::new(key);
        enc.counter = 1; // Skip to counter=1
        let plain: Vec<u8> = (0u8..100).collect();
        let ct = enc.encrypt(&plain).unwrap();
        let expected = encrypt_expected_frames(key, 1, &plain);
        assert_eq!(ct, expected);
    }
}
