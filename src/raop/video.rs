//! Video (screen mirroring) support for AirPlay 2.
//!
//! The library receives encrypted H.264/H.265 video packets, decrypts them,
//! and delivers raw NAL units to the application via [`VideoSession`].
//! The application is responsible for decoding and rendering.

use bytes::Bytes;

/// Classification of a video packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    /// AVC (H.264) decoder configuration record.
    AvcC,
    /// HEVC (H.265) decoder configuration record.
    HvcC,
    /// Encoded video payload (decrypted by the library).
    Payload,
    /// Auxiliary binary plist data.
    Plist,
    /// Unknown packet type.
    Other(u16),
}

/// A decrypted video packet delivered to the application.
#[derive(Debug)]
pub struct VideoPacket {
    /// Packet classification.
    pub kind: PacketKind,
    /// Presentation timestamp (NTP-based, in stream time units).
    pub timestamp: u64,
    /// Packet payload (raw NAL units for Payload, config bytes for AvcC/HvcC).
    pub payload: Bytes,
}

/// Factory for creating video sessions. Implement this to receive video data.
pub trait VideoHandler: Send + Sync + 'static {
    /// Called when a new video stream is established.
    fn video_init(&self) -> Box<dyn VideoSession>;
}

/// Per-stream video session receiving decrypted video packets.
///
/// Created by [`VideoHandler::video_init`]. Dropped when the stream ends.
pub trait VideoSession: Send {
    /// Called for each decrypted video packet.
    fn on_video(&mut self, packet: VideoPacket);

    /// Called when the video stream ends (client disconnected or error).
    fn on_video_end(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use bytes::Bytes;

    struct NonSyncSession {
        // Cell is Send but not Sync, which is fine because VideoSession runs on one task.
        seen: std::cell::Cell<u32>,
    }

    impl VideoSession for NonSyncSession {
        fn on_video(&mut self, _packet: VideoPacket) {
            self.seen.set(self.seen.get().saturating_add(1));
        }
    }

    fn assert_send<T: Send>() {}

    #[test]
    fn video_session_can_be_send_without_sync() {
        assert_send::<NonSyncSession>();
    }

    struct CountingSession {
        seen: Arc<AtomicUsize>,
        ended: Arc<AtomicUsize>,
    }

    impl VideoSession for CountingSession {
        fn on_video(&mut self, _packet: VideoPacket) {
            self.seen.fetch_add(1, Ordering::SeqCst);
        }

        fn on_video_end(&mut self) {
            self.ended.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct CountingHandler {
        seen: Arc<AtomicUsize>,
        ended: Arc<AtomicUsize>,
    }

    impl VideoHandler for CountingHandler {
        fn video_init(&self) -> Box<dyn VideoSession> {
            Box::new(CountingSession {
                seen: Arc::clone(&self.seen),
                ended: Arc::clone(&self.ended),
            })
        }
    }

    #[test]
    fn video_handler_creates_session_that_receives_packets() {
        let seen = Arc::new(AtomicUsize::new(0));
        let ended = Arc::new(AtomicUsize::new(0));
        let handler = CountingHandler {
            seen: Arc::clone(&seen),
            ended: Arc::clone(&ended),
        };

        let mut session = handler.video_init();
        session.on_video(VideoPacket {
            kind: PacketKind::Payload,
            timestamp: 123,
            payload: Bytes::from_static(b"hello"),
        });
        session.on_video_end();

        assert_eq!(seen.load(Ordering::SeqCst), 1);
        assert_eq!(ended.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn video_packet_fields_are_preserved() {
        let packet = VideoPacket {
            kind: PacketKind::HvcC,
            timestamp: 0x0102_0304_0506_0708,
            payload: Bytes::from_static(b"hvcc"),
        };

        assert_eq!(packet.kind, PacketKind::HvcC);
        assert_eq!(packet.timestamp, 0x0102_0304_0506_0708);
        assert_eq!(packet.payload.as_ref(), b"hvcc");
    }
}
