//! Protocol labels/constants used for AP2 key derivation.

#[cfg(feature = "ap2")]
pub(crate) const CONTROL_SALT: &str = "Control-Salt";
#[cfg(feature = "ap2")]
pub(crate) const CONTROL_READ_KEY_INFO: &str = "Control-Read-Encryption-Key";
#[cfg(feature = "ap2")]
pub(crate) const CONTROL_WRITE_KEY_INFO: &str = "Control-Write-Encryption-Key";

#[cfg(feature = "ap2")]
pub(crate) const EVENTS_SALT: &str = "Events-Salt";
#[cfg(feature = "ap2")]
pub(crate) const EVENTS_READ_KEY_INFO: &str = "Events-Read-Encryption-Key";
#[cfg(feature = "ap2")]
pub(crate) const EVENTS_WRITE_KEY_INFO: &str = "Events-Write-Encryption-Key";

#[cfg(all(feature = "ap2", feature = "video"))]
pub(crate) const VIDEO_STREAM_KEY_LABEL: &str = "AirPlayStreamKey";
#[cfg(all(feature = "ap2", feature = "video"))]
pub(crate) const VIDEO_STREAM_IV_LABEL: &str = "AirPlayStreamIV";
