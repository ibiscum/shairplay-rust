//! DACP (Digital Audio Control Protocol) client for remote-controlling Apple devices.
//!
//! When an iPhone/iPad/Mac streams audio via AirPlay, it advertises a `_dacp._tcp` mDNS
//! service. This module discovers that service and sends HTTP commands back to control
//! playback (play/pause, next, previous, volume, etc.).

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use crate::error::NetworkError;
use tracing::debug;

/// Default DACP port, used when mDNS discovery of the `_dacp._tcp` service fails.
const DACP_DEFAULT_PORT: u16 = 3689;

const PLAY_PAUSE_PATH: &str = "/ctrl-int/1/playpause";
const NEXT_PATH: &str = "/ctrl-int/1/nextitem";
const PREVIOUS_PATH: &str = "/ctrl-int/1/previtem";
const STOP_PATH: &str = "/ctrl-int/1/stop";

fn volume_path(volume: u8) -> String {
    format!("/ctrl-int/1/setproperty?dmcp.volume={}", volume.min(100))
}

fn shuffle_path(on: bool) -> String {
    let state = if on { 1 } else { 0 };
    format!("/ctrl-int/1/setproperty?dacp.shufflestate={state}")
}

fn repeat_path(state: u8) -> String {
    format!("/ctrl-int/1/setproperty?dacp.repeatstate={}", state.min(2))
}

/// Browse `_dacp._tcp` via mDNS and return the port for the given DACP-ID.
/// Returns None if not found within 2 seconds.
#[cfg(not(target_os = "macos"))]
fn discover_dacp_port(dacp_id: &str, _remote_ip: std::net::IpAddr) -> Option<u16> {
    let daemon = mdns_sd::ServiceDaemon::new().ok()?;
    let receiver = daemon.browse("_dacp._tcp.local.").ok()?;
    let target = dacp_id.to_uppercase();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);

    while std::time::Instant::now() < deadline {
        let timeout = deadline.saturating_duration_since(std::time::Instant::now());
        match receiver.recv_timeout(timeout) {
            Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) => {
                if info.get_fullname().to_uppercase().contains(&target) {
                    let port = info.get_port();
                    let _ = daemon.shutdown();
                    return Some(port);
                }
            }
            Err(_) => break,
            _ => {}
        }
    }
    let _ = daemon.shutdown();
    None
}

/// Browse `_dacp._tcp` via Bonjour and return the port for the given DACP-ID.
/// Always returns None on macOS — astro-dnssd doesn't expose a synchronous
/// browse+resolve API. The caller falls back to port 3689.
#[cfg(target_os = "macos")]
fn discover_dacp_port(dacp_id: &str, _remote_ip: std::net::IpAddr) -> Option<u16> {
    let _ = dacp_id;
    None
}

/// Client for sending DACP remote control commands to an Apple device.
///
/// Created from the DACP ID and Active-Remote header received by the AirPlay session.
///
/// # Example
/// ```text
/// let mut client = DacpClient::new("7711DA8B47838CB5", "1986535575");
/// client.discover_from_remote("192.168.1.5".parse().unwrap());
/// // Then from a synchronous remote-control callback:
/// // client.play_pause_blocking().ok();
/// ```
/// HTTP client for sending DACP playback commands to the iPhone.
#[derive(Debug)]
pub(crate) struct DacpClient {
    /// DACP-ID from the RTSP session. Identifies the `_dacp._tcp` mDNS service.
    dacp_id: String,
    active_remote: String,
    addr: Option<SocketAddr>,
}

impl DacpClient {
    /// Create a new DACP client from the values received in the AirPlay session.
    pub(crate) fn new(dacp_id: &str, active_remote: &str) -> Self {
        Self {
            dacp_id: dacp_id.to_string(),
            active_remote: active_remote.to_string(),
            addr: None,
        }
    }

    /// Discover the Apple device's DACP service via mDNS.
    ///
    /// Browses `_dacp._tcp.local.` for a service matching the DACP-ID,
    /// with a 2-second timeout. Falls back to port 3689 on the remote IP
    /// if mDNS discovery fails.
    pub(crate) fn discover_from_remote(&mut self, remote_ip: std::net::IpAddr) {
        self.addr = match discover_dacp_port(&self.dacp_id, remote_ip) {
            Some(port) => {
                debug!(port, dacp_id = %self.dacp_id, "DACP service discovered via mDNS");
                Some(SocketAddr::new(remote_ip, port))
            }
            None => {
                debug!(dacp_id = %self.dacp_id, "DACP mDNS discovery failed, falling back to port 3689");
                Some(SocketAddr::new(remote_ip, DACP_DEFAULT_PORT))
            }
        };
    }

    /// Send a raw DACP command from synchronous callbacks.
    pub(crate) fn command_blocking(&self, path: &str) -> Result<(), NetworkError> {
        let addr = self.addr.ok_or_else(|| {
            NetworkError::Mdns("DACP not discovered yet — call discover_from_remote() first".into())
        })?;

        let mut stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        let request = self.command_request(path, addr);
        stream.write_all(request.as_bytes())?;

        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(NetworkError::Mdns(
                "DACP command returned empty response".into(),
            ));
        }
        let status = std::str::from_utf8(&buf[..n]).unwrap_or_default();
        if !(status.starts_with("HTTP/1.1 2") || status.starts_with("HTTP/1.0 2")) {
            return Err(NetworkError::Mdns("DACP command failed".into()));
        }
        Ok(())
    }

    pub(crate) fn play_pause_blocking(&self) -> Result<(), NetworkError> {
        self.command_blocking(PLAY_PAUSE_PATH)
    }

    pub(crate) fn next_blocking(&self) -> Result<(), NetworkError> {
        self.command_blocking(NEXT_PATH)
    }

    pub(crate) fn prev_blocking(&self) -> Result<(), NetworkError> {
        self.command_blocking(PREVIOUS_PATH)
    }

    pub(crate) fn stop_blocking(&self) -> Result<(), NetworkError> {
        self.command_blocking(STOP_PATH)
    }

    pub(crate) fn set_volume_blocking(&self, volume: u8) -> Result<(), NetworkError> {
        self.command_blocking(&volume_path(volume))
    }

    pub(crate) fn set_shuffle_blocking(&self, on: bool) -> Result<(), NetworkError> {
        self.command_blocking(&shuffle_path(on))
    }

    pub(crate) fn set_repeat_blocking(&self, state: u8) -> Result<(), NetworkError> {
        self.command_blocking(&repeat_path(state))
    }

    fn command_request(&self, path: &str, addr: SocketAddr) -> String {
        format!(
            "GET {path} HTTP/1.1\r\nActive-Remote: {}\r\nHost: {addr}\r\nConnection: close\r\n\r\n",
            self.active_remote
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn spawn_dacp_server(response: Vec<u8>, captured: Arc<Mutex<Vec<u8>>>) -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept client");
            let mut buf = [0u8; 2048];
            let n = socket.read(&mut buf).expect("read request");
            captured
                .lock()
                .expect("capture mutex")
                .extend_from_slice(&buf[..n]);
            if !response.is_empty() {
                socket.write_all(&response).expect("write response");
            }
        });
        addr
    }

    #[test]
    fn volume_and_repeat_paths_clamp() {
        assert_eq!(volume_path(55), "/ctrl-int/1/setproperty?dmcp.volume=55");
        assert_eq!(volume_path(200), "/ctrl-int/1/setproperty?dmcp.volume=100");
        assert_eq!(shuffle_path(true), "/ctrl-int/1/setproperty?dacp.shufflestate=1");
        assert_eq!(shuffle_path(false), "/ctrl-int/1/setproperty?dacp.shufflestate=0");

        assert_eq!(repeat_path(0), "/ctrl-int/1/setproperty?dacp.repeatstate=0");
        assert_eq!(repeat_path(2), "/ctrl-int/1/setproperty?dacp.repeatstate=2");
        assert_eq!(repeat_path(9), "/ctrl-int/1/setproperty?dacp.repeatstate=2");
    }

    #[test]
    fn command_request_contains_required_headers() {
        let client = DacpClient::new("DACP", "1234");
        let req = client.command_request(
            PLAY_PAUSE_PATH,
            "127.0.0.1:3689".parse().expect("valid socket addr"),
        );
        assert!(req.starts_with("GET /ctrl-int/1/playpause HTTP/1.1\r\n"));
        assert!(req.contains("Active-Remote: 1234\r\n"));
        assert!(req.contains("Host: 127.0.0.1:3689\r\n"));
        assert!(req.contains("Connection: close\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn command_requires_discovery_first() {
        let client = DacpClient::new("DACP", "1234");
        let err = client
            .command_blocking(PLAY_PAUSE_PATH)
            .expect_err("command should fail without discovery");
        assert!(err.to_string().contains("discover_from_remote()"));
    }

    #[test]
    fn command_blocking_accepts_http_1_1_2xx_and_sends_request() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let addr = spawn_dacp_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
            Arc::clone(&captured),
        );

        let mut client = DacpClient::new("DACP", "4321");
        client.addr = Some(addr);
        client
            .command_blocking(NEXT_PATH)
            .expect("2xx response should succeed");

        let request = String::from_utf8(captured.lock().expect("capture mutex").clone())
            .expect("utf8 request");
        assert!(request.starts_with("GET /ctrl-int/1/nextitem HTTP/1.1\r\n"));
        assert!(request.contains("Active-Remote: 4321\r\n"));
    }

    #[test]
    fn command_blocking_accepts_http_1_0_2xx() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let addr = spawn_dacp_server(
            b"HTTP/1.0 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec(),
            captured,
        );

        let mut client = DacpClient::new("DACP", "4321");
        client.addr = Some(addr);
        client
            .command_blocking(PREVIOUS_PATH)
            .expect("HTTP/1.0 2xx should succeed");
    }

    #[test]
    fn command_blocking_rejects_empty_response() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let addr = spawn_dacp_server(Vec::new(), captured);

        let mut client = DacpClient::new("DACP", "4321");
        client.addr = Some(addr);
        let err = client
            .command_blocking(STOP_PATH)
            .expect_err("empty response should fail");
        assert!(err.to_string().contains("empty response"));
    }

    #[test]
    fn command_blocking_rejects_non_2xx_status() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let addr = spawn_dacp_server(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_vec(),
            captured,
        );

        let mut client = DacpClient::new("DACP", "4321");
        client.addr = Some(addr);
        let err = client
            .command_blocking(PLAY_PAUSE_PATH)
            .expect_err("non-2xx should fail");
        assert!(err.to_string().contains("DACP command failed"));
    }

    #[test]
    fn wrapper_methods_send_expected_paths() {
        let scenarios: Vec<(&str, Box<dyn Fn(&DacpClient) -> Result<(), NetworkError>>)> = vec![
            (PLAY_PAUSE_PATH, Box::new(|c| c.play_pause_blocking())),
            (NEXT_PATH, Box::new(|c| c.next_blocking())),
            (PREVIOUS_PATH, Box::new(|c| c.prev_blocking())),
            (STOP_PATH, Box::new(|c| c.stop_blocking())),
            (
                "/ctrl-int/1/setproperty?dmcp.volume=100",
                Box::new(|c| c.set_volume_blocking(200)),
            ),
            (
                "/ctrl-int/1/setproperty?dacp.shufflestate=1",
                Box::new(|c| c.set_shuffle_blocking(true)),
            ),
            (
                "/ctrl-int/1/setproperty?dacp.repeatstate=2",
                Box::new(|c| c.set_repeat_blocking(9)),
            ),
        ];

        for (expected_path, call) in scenarios {
            let captured = Arc::new(Mutex::new(Vec::new()));
            let addr = spawn_dacp_server(
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
                Arc::clone(&captured),
            );
            let mut client = DacpClient::new("DACP", "4321");
            client.addr = Some(addr);
            call(&client).expect("wrapper command should succeed");

            let request = String::from_utf8(captured.lock().expect("capture mutex").clone())
                .expect("utf8 request");
            assert!(request.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")));
        }
    }
}
