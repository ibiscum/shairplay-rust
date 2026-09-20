//! Networking layer — TCP server and mDNS discovery.
//!
//! Feature-gated additions:
//! - `ap2`: AirPlay 2 feature flags and PTP timing support.
//! - `diagnostic-headers`: request/response header diagnostics.

#[cfg(feature = "ap2")]
pub mod features;
pub mod mdns;
#[cfg(feature = "diagnostic-headers")]
pub(crate) mod protocol_diagnostics;
#[cfg(feature = "ap2")]
pub(crate) mod ptp;
pub(crate) mod server;
