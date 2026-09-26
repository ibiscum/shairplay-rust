//! Video stream receiver for AirPlay 2 screen mirroring (stream type 110).
//!
//! Accepts a TCP connection, reads 128-byte headers + variable-length payloads,
//! classifies packets, decrypts Payload types, and delivers to VideoSession.

use std::time::Duration;

use bytes::BytesMut;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, trace, warn};

use crate::crypto::video_cipher::VideoCipher;
use crate::raop::video::{PacketKind, VideoPacket, VideoSession};

const VIDEO_HEADER_LEN: usize = 128;
const MAX_VIDEO_PAYLOAD_LEN: usize = 32 * 1024 * 1024;
/// Drop a video connection whose peer stalls mid-read, freeing the task and port.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
struct VideoHeader {
    payload_len: usize,
    packet_type: u16,
    timestamp: u64,
}

fn peer_ip_matches(expected: std::net::IpAddr, actual: std::net::SocketAddr) -> bool {
    expected == actual.ip()
}

fn parse_header(header: &[u8; VIDEO_HEADER_LEN]) -> VideoHeader {
    VideoHeader {
        payload_len: u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize,
        packet_type: u16::from_le_bytes([header[4], header[5]]),
        timestamp: u64::from_le_bytes([
            header[8], header[9], header[10], header[11], header[12], header[13], header[14],
            header[15],
        ]),
    }
}

fn classify_packet(packet_type: u16, payload: &[u8]) -> PacketKind {
    match packet_type {
        1 if payload.len() >= 8 && &payload[4..8] == b"hvc1" => PacketKind::HvcC,
        1 => PacketKind::AvcC,
        0 | 4096 => PacketKind::Payload,
        5 => PacketKind::Plist,
        other => PacketKind::Other(other),
    }
}

async fn read_with_timeout(stream: &mut TcpStream, buffer: &mut [u8], part: &str) -> bool {
    match tokio::time::timeout(READ_TIMEOUT, stream.read_exact(buffer)).await {
        Ok(Ok(_)) => true,
        Ok(Err(_)) => {
            debug!(part, "Video stream ended during read");
            false
        }
        Err(_) => {
            debug!(part, "Video stream read timed out");
            false
        }
    }
}

/// Run the video stream receiver. Accepts one TCP connection and processes packets.
pub(crate) async fn run(
    listener: TcpListener,
    expected_peer_ip: std::net::IpAddr,
    cipher: VideoCipher,
    session: Box<dyn VideoSession>,
) {
    let (stream, addr) = loop {
        match listener.accept().await {
            Ok((stream, addr)) if peer_ip_matches(expected_peer_ip, addr) => break (stream, addr),
            Ok((_, addr)) => {
                warn!(%addr, expected = %expected_peer_ip, "Video stream connection from unexpected peer");
            }
            Err(e) => {
                warn!("Video stream accept failed: {e}");
                return;
            }
        }
    };
    info!(%addr, "Video stream client connected");
    process(stream, cipher, session).await;
}

async fn process(
    mut stream: TcpStream,
    mut cipher: VideoCipher,
    mut session: Box<dyn VideoSession>,
) {
    let mut header = [0u8; VIDEO_HEADER_LEN];

    loop {
        if !read_with_timeout(&mut stream, &mut header, "header").await {
            break;
        }
        let metadata = parse_header(&header);
        if metadata.payload_len == 0 {
            continue;
        }
        if metadata.payload_len > MAX_VIDEO_PAYLOAD_LEN {
            warn!(
                payload_len = metadata.payload_len,
                "Video payload exceeds maximum allowed size"
            );
            break;
        }

        let mut payload = BytesMut::zeroed(metadata.payload_len);
        if !read_with_timeout(&mut stream, &mut payload, "payload").await {
            break;
        }
        let kind = classify_packet(metadata.packet_type, &payload);
        if matches!(kind, PacketKind::Payload) {
            cipher.decrypt(&mut payload);
        }

        trace!(
            ?kind,
            timestamp = metadata.timestamp,
            payload_len = metadata.payload_len,
            "Video packet"
        );
        session.on_video(VideoPacket {
            kind,
            timestamp: metadata.timestamp,
            payload: payload.freeze(),
        });
    }
    session.on_video_end();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use tokio::io::AsyncWriteExt;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedPacket {
        kind: PacketKind,
        timestamp: u64,
        payload: Vec<u8>,
    }

    struct RecordingSession {
        packets: Arc<Mutex<Vec<RecordedPacket>>>,
        ended: Arc<AtomicBool>,
    }

    impl VideoSession for RecordingSession {
        fn on_video(&mut self, packet: VideoPacket) {
            self.packets
                .lock()
                .expect("recording session mutex poisoned")
                .push(RecordedPacket {
                    kind: packet.kind,
                    timestamp: packet.timestamp,
                    payload: packet.payload.to_vec(),
                });
        }

        fn on_video_end(&mut self) {
            self.ended.store(true, Ordering::SeqCst);
        }
    }

    fn make_header(payload_len: u32, packet_type: u16, timestamp: u64) -> [u8; VIDEO_HEADER_LEN] {
        let mut header = [0u8; VIDEO_HEADER_LEN];
        header[..4].copy_from_slice(&payload_len.to_le_bytes());
        header[4..6].copy_from_slice(&packet_type.to_le_bytes());
        header[8..16].copy_from_slice(&timestamp.to_le_bytes());
        header
    }

    async fn connected_tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client_task = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        let client = client_task.await.unwrap();
        (server, client)
    }

    fn deterministic_key_iv(key_label: &str, iv_label: &str) -> ([u8; 16], [u8; 16]) {
        let key_byte =
            u8::from_str_radix(key_label, 16).expect("deterministic key label must be hex");
        let iv_byte =
            u8::from_str_radix(iv_label, 16).expect("deterministic iv label must be hex");
        ([key_byte; 16], [iv_byte; 16])
    }

    #[test]
    fn parses_little_endian_header_fields() {
        let mut header = [0u8; VIDEO_HEADER_LEN];
        header[..4].copy_from_slice(&0x1234_u32.to_le_bytes());
        header[4..6].copy_from_slice(&0x5678_u16.to_le_bytes());
        header[8..16].copy_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());

        let parsed = parse_header(&header);
        assert_eq!(parsed.payload_len, 0x1234);
        assert_eq!(parsed.packet_type, 0x5678);
        assert_eq!(parsed.timestamp, 0x0102_0304_0506_0708);
    }

    #[test]
    fn classifies_supported_packet_types() {
        assert_eq!(classify_packet(1, b"....hvc1"), PacketKind::HvcC);
        assert_eq!(classify_packet(1, b"short"), PacketKind::AvcC);
        assert_eq!(classify_packet(0, b""), PacketKind::Payload);
        assert_eq!(classify_packet(4096, b""), PacketKind::Payload);
        assert_eq!(classify_packet(5, b""), PacketKind::Plist);
        assert_eq!(classify_packet(42, b""), PacketKind::Other(42));
    }

    #[test]
    fn peer_ip_matches_accepts_same_ip() {
        let expected: std::net::IpAddr = "192.168.1.10".parse().unwrap();
        let actual: std::net::SocketAddr = "192.168.1.10:7000".parse().unwrap();
        assert!(peer_ip_matches(expected, actual));
    }

    #[test]
    fn peer_ip_matches_rejects_different_ip() {
        let expected: std::net::IpAddr = "192.168.1.10".parse().unwrap();
        let actual: std::net::SocketAddr = "192.168.1.11:7000".parse().unwrap();
        assert!(!peer_ip_matches(expected, actual));
    }

    #[tokio::test]
    async fn process_decrypts_payload_skips_empty_and_ends_on_oversized_payload() {
        let (key, iv) = deterministic_key_iv("11", "22");

        let (server, mut client) = connected_tcp_pair().await;

        // Empty packet should be ignored.
        client
            .write_all(&make_header(0, 0, 1))
            .await
            .expect("write empty packet header");

        // Encrypted payload packet should be decrypted and forwarded.
        let plaintext = b"video payload".to_vec();
        let mut encrypted = plaintext.clone();
        let mut sender_cipher = VideoCipher::new(&key, &iv);
        sender_cipher.decrypt(&mut encrypted);
        client
            .write_all(&make_header(encrypted.len() as u32, 0, 2))
            .await
            .expect("write payload header");
        client
            .write_all(&encrypted)
            .await
            .expect("write encrypted payload");

        // Oversized payload should terminate the stream loop.
        client
            .write_all(&make_header((MAX_VIDEO_PAYLOAD_LEN as u32) + 1, 0, 3))
            .await
            .expect("write oversized header");
        client.shutdown().await.expect("shutdown test client");

        let packets = Arc::new(Mutex::new(Vec::new()));
        let ended = Arc::new(AtomicBool::new(false));
        let session = RecordingSession {
            packets: Arc::clone(&packets),
            ended: Arc::clone(&ended),
        };

        process(server, VideoCipher::new(&key, &iv), Box::new(session)).await;

        let got = packets
            .lock()
            .expect("recording session mutex poisoned")
            .clone();
        assert_eq!(
            got,
            vec![RecordedPacket {
                kind: PacketKind::Payload,
                timestamp: 2,
                payload: plaintext,
            }]
        );
        assert!(ended.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn run_accepts_expected_peer_and_processes_stream() {
        let (key, iv) = deterministic_key_iv("33", "44");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let packets = Arc::new(Mutex::new(Vec::new()));
        let ended = Arc::new(AtomicBool::new(false));
        let session = RecordingSession {
            packets: Arc::clone(&packets),
            ended: Arc::clone(&ended),
        };

        let run_task = tokio::spawn(run(
            listener,
            "127.0.0.1".parse().unwrap(),
            VideoCipher::new(&key, &iv),
            Box::new(session),
        ));

        let mut client = TcpStream::connect(addr).await.unwrap();
        let plaintext = b"abc123".to_vec();
        let mut encrypted = plaintext.clone();
        let mut sender_cipher = VideoCipher::new(&key, &iv);
        sender_cipher.decrypt(&mut encrypted);

        client
            .write_all(&make_header(encrypted.len() as u32, 0, 99))
            .await
            .expect("write packet header");
        client
            .write_all(&encrypted)
            .await
            .expect("write encrypted packet");
        client.shutdown().await.expect("shutdown test client");

        run_task.await.expect("run task join");

        let got = packets
            .lock()
            .expect("recording session mutex poisoned")
            .clone();
        assert_eq!(
            got,
            vec![RecordedPacket {
                kind: PacketKind::Payload,
                timestamp: 99,
                payload: plaintext,
            }]
        );
        assert!(ended.load(Ordering::SeqCst));
    }
}
