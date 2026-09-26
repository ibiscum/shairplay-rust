//! AES-128-CTR utilities for AP1 audio stream decryption.

use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};

const BLOCK_SIZE: usize = 16;

/// Streaming AES-128-CTR cipher context. Equivalent to AES_CTR_CTX in aes_ctr.h.
///
/// Manually implements CTR mode to exactly match the C code's behavior:
/// encrypts counter with AES-ECB (the C code uses CBC with zeroed IV, which is
/// equivalent to ECB for a single block), XORs with plaintext, increments counter.
pub struct AesCtr {
    cipher: Aes128,
    counter: [u8; BLOCK_SIZE],
    state: [u8; BLOCK_SIZE],
    available: usize,
}

impl AesCtr {
    /// Initialize with a 128-bit key and 128-bit nonce/IV.
    /// Equivalent to AES_ctr_set_key with AES_MODE_128.
    pub fn new(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let cipher = Aes128::new(key.into());
        let mut counter = [0u8; BLOCK_SIZE];
        counter.copy_from_slice(nonce);
        Self {
            cipher,
            counter,
            state: [0u8; BLOCK_SIZE],
            available: 0,
        }
    }

    /// Increment the 128-bit counter (big-endian). Equivalent to ctr128_inc.
    fn inc_counter(&mut self) {
        let mut carry: u16 = 1;
        for i in (0..BLOCK_SIZE).rev() {
            carry += self.counter[i] as u16;
            self.counter[i] = carry as u8;
            carry >>= 8;
        }
    }

    /// Encrypt (or decrypt) data in-place. Equivalent to AES_ctr_encrypt.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        let mut idx = 0;
        while idx < data.len() {
            if self.available == 0 {
                // Encrypt counter block (ECB = CBC with zero IV on single block)
                let mut block = Array::from(self.counter);
                self.cipher.encrypt_block(&mut block);
                self.state.copy_from_slice(&block);
                self.available = BLOCK_SIZE;
                self.inc_counter();
            }
            let offset = BLOCK_SIZE - self.available;
            let n = self.available.min(data.len() - idx);
            for i in 0..n {
                data[idx] ^= self.state[offset + i];
                idx += 1;
            }
            self.available -= n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key_nonce() -> ([u8; 16], [u8; 16]) {
        (rand::random::<[u8; 16]>(), rand::random::<[u8; 16]>())
    }

    fn inc_counter_be(counter: &mut [u8; BLOCK_SIZE]) {
        let mut carry: u16 = 1;
        for i in (0..BLOCK_SIZE).rev() {
            carry += counter[i] as u16;
            counter[i] = carry as u8;
            carry >>= 8;
        }
    }

    #[test]
    fn aes_ctr_empty_input_is_noop() {
        let (key, nonce) = random_key_nonce();
        let mut ctr = AesCtr::new(&key, &nonce);
        let mut data = Vec::<u8>::new();
        ctr.encrypt(&mut data);
        assert!(data.is_empty());
        assert_eq!(ctr.available, 0);
    }

    #[test]
    fn aes_ctr_counter_carry_matches_manual_keystream() {
        // Start at ..FF so the second block checks carry propagation into the
        // next byte (..00 with carry into byte 14).
        let key = rand::random::<[u8; 16]>();
        let mut counter = [0u8; 16];
        counter[15] = 0xFF;

        let mut ctr_data = [0u8; 32];
        AesCtr::new(&key, &counter).encrypt(&mut ctr_data);

        let cipher = Aes128::new((&key).into());
        let mut expected = [0u8; 32];

        let mut c0 = Array::from(counter);
        cipher.encrypt_block(&mut c0);
        expected[..16].copy_from_slice(&c0);

        inc_counter_be(&mut counter);
        let mut c1 = Array::from(counter);
        cipher.encrypt_block(&mut c1);
        expected[16..].copy_from_slice(&c1);

        assert_eq!(ctr_data, expected);
    }
}
