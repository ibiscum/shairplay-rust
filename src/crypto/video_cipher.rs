//! AES-128-CTR streaming cipher for video packet decryption.
//!
//! Video packets use AES-CTR with a key derived from the FairPlay session.
//! The cipher maintains partial block state across packets (streaming mode).

use aes::Aes128;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};

/// Streaming AES-128-CTR cipher that maintains state across packets.
pub(crate) struct VideoCipher {
    cipher: Ctr128BE<Aes128>,
    /// Leftover keystream bytes from the previous partial block.
    leftover: [u8; 16],
    /// Number of leftover bytes to apply before resuming CTR.
    leftover_count: usize,
}

impl VideoCipher {
    /// Create a new video cipher from a 16-byte key and 16-byte IV.
    pub(crate) fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            cipher: Ctr128BE::<Aes128>::new(key.into(), iv.into()),
            leftover: [0u8; 16],
            leftover_count: 0,
        }
    }

    /// Decrypt a video payload in-place, maintaining streaming CTR state.
    pub(crate) fn decrypt(&mut self, payload: &mut [u8]) {
        debug_assert!(self.leftover_count <= 15);

        let mut offset = 0usize;
        let n = self.leftover_count;

        // Apply leftover keystream from previous partial block
        if n > 0 {
            let apply = n.min(payload.len());
            let start = 16 - n;
            for (p, &k) in payload[..apply]
                .iter_mut()
                .zip(&self.leftover[start..start + apply])
            {
                *p ^= k;
            }
            if apply < n {
                self.leftover_count = n - apply;
                debug_assert!(self.leftover_count <= 15);
                return;
            }
            self.leftover_count = 0;
            offset = apply;
        }

        // Decrypt full blocks
        let remaining = payload.len() - offset;
        let full_len = (remaining / 16) * 16;
        self.cipher
            .apply_keystream(&mut payload[offset..offset + full_len]);

        // Handle trailing partial block
        let rest_len = remaining % 16;
        if rest_len > 0 {
            let rest_start = payload.len() - rest_len;
            self.leftover = [0u8; 16];
            self.leftover[..rest_len].copy_from_slice(&payload[rest_start..]);
            self.cipher.apply_keystream(&mut self.leftover);
            payload[rest_start..].copy_from_slice(&self.leftover[..rest_len]);
            self.leftover_count = 16 - rest_len;
            debug_assert!(self.leftover_count <= 15);
        } else {
            self.leftover_count = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_full_blocks() {
        let key = [0x01u8; 16];
        let iv = [0x00u8; 16];
        let mut cipher1 = VideoCipher::new(&key, &iv);
        let mut cipher2 = VideoCipher::new(&key, &iv);

        // Encrypt with cipher1, decrypt with cipher2
        let original = vec![0xAA; 32];
        let mut data = original.clone();
        cipher1.decrypt(&mut data); // "encrypt" (CTR is symmetric)
        assert_ne!(data, original);
        cipher2.decrypt(&mut data); // decrypt
        assert_eq!(data, original);
    }

    #[test]
    fn decrypt_partial_blocks_streaming() {
        let key = [0x42u8; 16];
        let iv = [0x00u8; 16];

        // Single cipher, two chunks that don't align to 16 bytes
        let mut cipher_a = VideoCipher::new(&key, &iv);
        let mut chunk1 = vec![0u8; 10];
        let mut chunk2 = vec![0u8; 22]; // 10 + 22 = 32 = 2 full blocks
        cipher_a.decrypt(&mut chunk1);
        cipher_a.decrypt(&mut chunk2);

        // Same key, one 32-byte chunk
        let mut cipher_b = VideoCipher::new(&key, &iv);
        let mut full = vec![0u8; 32];
        cipher_b.decrypt(&mut full);

        // Results must match
        assert_eq!(&chunk1[..], &full[..10]);
        assert_eq!(&chunk2[..], &full[10..]);
    }

    #[test]
    fn decrypt_tiny_chunks_matches_single_pass() {
        let key = [0x21u8; 16];
        let iv = [0x10u8; 16];

        // Build deterministic input and process it in many tiny chunks to hit
        // repeated "apply < leftover" paths.
        let original: Vec<u8> = (0u8..40).collect();
        let mut chunked = original.clone();

        let mut cipher_a = VideoCipher::new(&key, &iv);
        let mut pos = 0usize;
        for &size in &[1usize, 1, 1, 5, 2, 8, 3, 4, 15] {
            let end = (pos + size).min(chunked.len());
            cipher_a.decrypt(&mut chunked[pos..end]);
            pos = end;
            if pos == chunked.len() {
                break;
            }
        }

        let mut single = original.clone();
        let mut cipher_b = VideoCipher::new(&key, &iv);
        cipher_b.decrypt(&mut single);

        assert_eq!(chunked, single);
    }

    #[test]
    fn decrypt_empty_payload_keeps_state() {
        let key = [0xABu8; 16];
        let iv = [0xCDu8; 16];
        let mut cipher = VideoCipher::new(&key, &iv);

        // Seed leftover state with a partial block.
        let mut one = [0u8; 1];
        cipher.decrypt(&mut one);
        let before = cipher.leftover_count;

        let mut empty: [u8; 0] = [];
        cipher.decrypt(&mut empty);

        assert_eq!(cipher.leftover_count, before);
    }
}
