//! RAOP/AirPlay server core — connection handling, audio pipeline, and public API.

pub use crate::proto::dmap::TrackMetadata;

#[cfg(feature = "ap2")]
pub mod audio_pipeline;
#[cfg(feature = "pipewire-auth-setup-compat")]
mod auth_setup;
pub mod buffer;
#[cfg(feature = "ap2")]
pub mod buffered_audio;
#[cfg(feature = "ap2")]
pub(crate) mod event_channel;
pub(crate) mod handlers_ap1;
#[cfg(feature = "ap2")]
pub(crate) mod handlers_ap2;
#[cfg(feature = "hls")]
pub(crate) mod handlers_hls;
#[cfg(feature = "hls")]
pub mod hls;
pub(crate) mod ntp;
#[cfg(feature = "ap2")]
pub(crate) mod realtime_audio;
pub(crate) mod rtp;
mod rtsp;
#[cfg(feature = "video")]
pub mod video;
#[cfg(feature = "video")]
pub(crate) mod video_stream;

pub(crate) mod config;

/// Maximum hardware address length in bytes.
pub(crate) const MAX_HWADDR_LEN: usize = 6;
/// Maximum password length in bytes.
pub(crate) const MAX_PASSWORD_LEN: usize = 64;
/// Maximum HTTP Digest nonce length in bytes.
pub(crate) const MAX_NONCE_LEN: usize = 32;

mod types;
pub use types::*;

mod connection;
mod server;
pub use server::{RaopServer, RaopServerBuilder};

pub(crate) struct DacpRemoteControl {
    client: crate::dacp::DacpClient,
}

fn ip_addr_from_remote(remote_addr: &[u8]) -> Option<std::net::IpAddr> {
    match remote_addr.len() {
        4 => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            remote_addr[0],
            remote_addr[1],
            remote_addr[2],
            remote_addr[3],
        ))),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(remote_addr);
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

impl DacpRemoteControl {
    /// Create a new DACP remote control client for the given iPhone.
    pub(crate) fn new(dacp_id: &str, active_remote: &str, remote_addr: &[u8]) -> Self {
        let mut client = crate::dacp::DacpClient::new(dacp_id, active_remote);
        if let Some(ip) = ip_addr_from_remote(remote_addr) {
            client.discover_from_remote(ip);
        } else {
            tracing::warn!(
                len = remote_addr.len(),
                "Invalid DACP remote address length"
            );
        }
        Self { client }
    }
}

impl RemoteControl for DacpRemoteControl {
    fn send_command(&self, cmd: RemoteCommand) -> Result<(), crate::error::ShairplayError> {
        let result = match cmd {
            RemoteCommand::Play | RemoteCommand::Pause => self.client.play_pause_blocking(),
            RemoteCommand::NextTrack => self.client.next_blocking(),
            RemoteCommand::PreviousTrack => self.client.prev_blocking(),
            RemoteCommand::SetVolume(v) => self.client.set_volume_blocking(v),
            RemoteCommand::ToggleShuffle => self.client.set_shuffle_blocking(true),
            RemoteCommand::ToggleRepeat => self.client.set_repeat_blocking(1),
            RemoteCommand::Stop => self.client.stop_blocking(),
        };
        result.map_err(crate::error::ShairplayError::Network)
    }

    fn available_commands(&self) -> Vec<RemoteCommand> {
        vec![
            RemoteCommand::Play,
            RemoteCommand::Pause,
            RemoteCommand::NextTrack,
            RemoteCommand::PreviousTrack,
            RemoteCommand::SetVolume(0),
            RemoteCommand::ToggleShuffle,
            RemoteCommand::ToggleRepeat,
            RemoteCommand::Stop,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_addr_from_remote_parses_ipv4() {
        let ip = ip_addr_from_remote(&[192, 168, 1, 9]);
        assert_eq!(
            ip,
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, 1, 9
            )))
        );
    }

    #[test]
    fn ip_addr_from_remote_parses_ipv6() {
        let ip = ip_addr_from_remote(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            ip,
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001, 0x0db8, 0, 0, 0, 0, 0, 1
            )))
        );
    }

    #[test]
    fn ip_addr_from_remote_rejects_invalid_lengths() {
        assert_eq!(ip_addr_from_remote(&[]), None);
        assert_eq!(ip_addr_from_remote(&[127, 0, 0]), None);
        assert_eq!(ip_addr_from_remote(&[0u8; 15]), None);
        assert_eq!(ip_addr_from_remote(&[0u8; 17]), None);
    }

    #[test]
    fn dacp_available_commands_exposes_expected_controls() {
        let remote = DacpRemoteControl::new("deadbeef", "123456", &[127, 0, 0, 1]);
        let cmds = remote.available_commands();

        assert!(cmds.contains(&RemoteCommand::Play));
        assert!(cmds.contains(&RemoteCommand::Pause));
        assert!(cmds.contains(&RemoteCommand::NextTrack));
        assert!(cmds.contains(&RemoteCommand::PreviousTrack));
        assert!(cmds.contains(&RemoteCommand::SetVolume(0)));
        assert!(cmds.contains(&RemoteCommand::ToggleShuffle));
        assert!(cmds.contains(&RemoteCommand::ToggleRepeat));
        assert!(cmds.contains(&RemoteCommand::Stop));
        assert_eq!(cmds.len(), 8);
    }
}
