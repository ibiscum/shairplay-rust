//! AirPlay 2 encrypted event and remote control channels.
//!
//! After initial SETUP, the client connects to the event TCP port.
//! All traffic is encrypted with ChaCha20-Poly1305 using HKDF-derived keys.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::crypto::chacha_transport::EncryptedChannel;
use crate::error::NetworkError;

/// Upper bound for buffered encrypted event-channel bytes.
const MAX_ENCRYPTED_EVENT_BUFFER_LEN: usize = 1024 * 1024;

/// Handle for sending commands through the event channel.
#[derive(Clone)]
pub(crate) struct EventSender {
    // Load-bearing AND the outbound channel: holding this keeps the mpsc open for
    // the connection's lifetime (stored in `RaopConnection::event_sender`), and
    // `send()` pushes events through it. Currently unwired beyond the initial
    // `updateInfo` queued at SETUP — see AP2-STATUS.md.
    #[allow(dead_code)]
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl EventSender {
    /// Create from an existing channel sender.
    pub(crate) fn from_tx(tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self { tx }
    }

    /// Push an event to the controller over the encrypted AP2 event channel.
    ///
    /// Scaffolding for receiver-initiated outbound events (volume, now-playing,
    /// progress). Today only the initial `updateInfo` is sent at SETUP time via
    /// the raw channel sender; wiring this on receiver-side state changes would
    /// enable fuller AP2 event reporting. Unwired — see AP2-STATUS.md.
    #[allow(dead_code)] // unwired outbound-event API — see AP2-STATUS.md
    pub(crate) fn send(&self, data: Vec<u8>) -> Result<(), NetworkError> {
        self.tx
            .send(data)
            .map_err(|_| NetworkError::Mdns("event channel closed".into()))
    }
}

/// Async event channel that accepts one encrypted TCP connection.
pub(crate) struct EventChannel;

impl EventChannel {
    /// Handle a connected event channel stream (public for use from handlers).
    pub(crate) async fn handle_stream(
        stream: TcpStream,
        channel: EncryptedChannel,
        cmd_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        Self::handle(stream, channel, cmd_rx).await;
    }

    async fn handle(
        mut stream: TcpStream,
        mut channel: EncryptedChannel,
        mut cmd_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let mut buf = vec![0u8; 4096];
        let mut encrypted_buf = Vec::new();
        loop {
            tokio::select! {
                result = stream.read(&mut buf) => {
                    match result {
                        Ok(0) => { debug!("Event channel closed by client"); break; }
                        Ok(n) => {
                            encrypted_buf.extend_from_slice(&buf[..n]);
                            if encrypted_buf.len() > MAX_ENCRYPTED_EVENT_BUFFER_LEN {
                                warn!(
                                    len = encrypted_buf.len(),
                                    "Event channel encrypted buffer exceeded limit"
                                );
                                break;
                            }
                            debug!(n, "Event channel data received");
                            match channel.decrypt_ctx.decrypt(&encrypted_buf) {
                                Ok((plain, consumed)) => {
                                    if consumed > 0 { encrypted_buf.drain(..consumed); }
                                    if !plain.is_empty() {
                                        debug!(len = plain.len(), "Event channel message received");
                                    }
                                }
                                Err(e) => {
                                    warn!("Event channel decrypt error: {e}");
                                    break;
                                }
                            }
                        }
                        Err(e) => { warn!("Event channel read error: {e}"); break; }
                    }
                }
                Some(data) = cmd_rx.recv() => {
                    debug!(len = data.len(), "Sending on event channel");
                    let encrypted = match channel.encrypt_ctx.encrypt(&data) {
                        Ok(e) => e,
                        Err(e) => { warn!("Event channel encrypt error: {e}"); break; }
                    };
                    if let Err(e) = stream.write_all(&encrypted).await {
                        warn!("Event channel write error: {e}"); break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};

    fn server_event_channel(secret: &[u8; 64]) -> EncryptedChannel {
        EncryptedChannel::events(secret).expect("server event channel")
    }

    fn client_event_channel(secret: &[u8; 64]) -> EncryptedChannel {
        // Invert read/write labels relative to the server channel.
        EncryptedChannel::new(
            secret,
            "Events-Salt",
            "Events-Read-Encryption-Key",
            "Events-Salt",
            "Events-Write-Encryption-Key",
        )
        .expect("client event channel")
    }

    async fn connected_stream_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let client_task = tokio::spawn(async move {
            TcpStream::connect(addr).await.expect("connect to listener")
        });
        let (server_stream, _) = listener.accept().await.expect("accept client");
        let client_stream = client_task.await.expect("join client task");
        (server_stream, client_stream)
    }

    #[test]
    fn event_sender_send_reports_closed_channel() {
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        drop(rx);
        let sender = EventSender::from_tx(tx);
        let err = sender.send(vec![1, 2, 3]).expect_err("channel is closed");
        assert!(err.to_string().contains("event channel closed"));
    }

    #[tokio::test]
    async fn handle_stream_sends_encrypted_outbound_data() {
        let secret = [0x44u8; 64];
        let (server_stream, mut client_stream) = connected_stream_pair().await;

        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let server = tokio::spawn(EventChannel::handle_stream(
            server_stream,
            server_event_channel(&secret),
            rx,
        ));

        let payload = b"update-info-payload".to_vec();
        tx.send(payload.clone()).expect("queue outbound event");

        let mut encrypted = vec![0u8; 256];
        let n = timeout(Duration::from_secs(1), client_stream.read(&mut encrypted))
            .await
            .expect("timely read")
            .expect("socket read");
        assert!(n > 0);

        let mut client_channel = client_event_channel(&secret);
        let (plain, consumed) = client_channel
            .decrypt_ctx
            .decrypt(&encrypted[..n])
            .expect("decrypt outbound frame");
        assert_eq!(consumed, n);
        assert_eq!(plain, payload);

        drop(tx);
        client_stream.shutdown().await.expect("shutdown client stream");
        timeout(Duration::from_secs(1), server)
            .await
            .expect("server exits promptly")
            .expect("server join");
    }

    #[tokio::test]
    async fn handle_stream_stops_on_decrypt_error() {
        let secret = [0x77u8; 64];
        let (server_stream, mut client_stream) = connected_stream_pair().await;

        let (_tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let server = tokio::spawn(EventChannel::handle_stream(
            server_stream,
            server_event_channel(&secret),
            rx,
        ));

        // Complete framed block with block_len=0 triggers decrypt error path.
        let bad_frame = vec![0u8; 2 + 16];
        client_stream
            .write_all(&bad_frame)
            .await
            .expect("send malformed frame");

        timeout(Duration::from_secs(1), server)
            .await
            .expect("server exits on decrypt error")
            .expect("server join");
    }

    #[tokio::test]
    async fn handle_stream_stops_when_encrypted_buffer_exceeds_limit() {
        let secret = [0x99u8; 64];
        let (server_stream, mut client_stream) = connected_stream_pair().await;

        let (_tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let server = tokio::spawn(EventChannel::handle_stream(
            server_stream,
            server_event_channel(&secret),
            rx,
        ));

        // Make decrypt() consume nothing while the encrypted buffer grows.
        let mut oversized = Vec::with_capacity(MAX_ENCRYPTED_EVENT_BUFFER_LEN + 1024);
        oversized.extend_from_slice(&[0xff, 0xff]);
        oversized.resize(MAX_ENCRYPTED_EVENT_BUFFER_LEN + 1024, 0u8);
        client_stream
            .write_all(&oversized)
            .await
            .expect("send oversized encrypted data");

        timeout(Duration::from_secs(1), server)
            .await
            .expect("server exits on encrypted buffer limit")
            .expect("server join");
    }
}
