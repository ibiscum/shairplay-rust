//! Cryptographic primitives for AirPlay authentication and encryption.

pub mod aes;
pub mod fairplay;
mod fairplay_garble;
mod fairplay_tables;
pub mod pairing;
pub mod rsa;

#[cfg(feature = "ap2")]
pub mod chacha_transport;
#[cfg(feature = "ap2")]
pub mod pairing_homekit;
#[cfg(feature = "ap2")]
pub mod tlv;
// `video` implies `ap2` in Cargo features; keep both gates here so this
// dependency remains explicit at the module boundary.
#[cfg(all(feature = "ap2", feature = "video"))]
pub mod video_cipher;
#[cfg(all(feature = "ap2", feature = "video"))]
pub mod video_key;
