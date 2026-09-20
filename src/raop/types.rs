//! Public types and traits for the AirPlay server.

use std::sync::Arc;

/// Runtime protocol mode selection.
///
/// When the `ap2` feature is enabled, this controls whether the server
/// advertises itself as an AirPlay 1 (classic) or AirPlay 2 receiver.
/// Both modes share the same RTSP listener — the difference is in mDNS
/// advertisement and feature negotiation.
#[cfg(feature = "ap2")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AirPlayMode {
    /// Classic AirPlay 1: ALAC/AAC over RTP, RSA encryption, NTP timing.
    AirPlay1,
    /// AirPlay 2: buffered audio, ChaCha20 encryption, SRP pairing, PTP timing.
    #[default]
    AirPlay2,
}

/// Audio codec type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodec {
    /// Decoded PCM (f32 interleaved). Always delivered regardless of AP1/AP2.
    Pcm,
}

/// AirPlay 1 wire codec advertised in the `_raop._tcp` `cn` TXT record.
///
/// The receiver auto-detects the actual codec per connection from the SDP
/// `rtpmap`; this only controls what is *advertised*. When several are
/// advertised, their order is preserved because sender selection policies vary.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ap1Codec {
    /// Raw linear PCM / `L16` (`cn=0`).
    Pcm,
    /// Apple Lossless (`cn=1`).
    Alac,
}

impl Ap1Codec {
    /// The `cn` TXT record digit for this codec.
    pub(crate) const fn txt_value(self) -> &'static str {
        match self {
            Ap1Codec::Pcm => "0",
            Ap1Codec::Alac => "1",
        }
    }
}

/// AirPlay 1 encryption / authentication mode advertised in the `et` TXT record.
///
/// The receiver auto-dispatches on what a sender actually negotiates (RSA
/// `rsaaeskey`, FairPlay `fpaeskey`, or no key at all); this only controls what
/// is *advertised*. Sender preference rules vary, so advertise only modes the
/// deployment intends to accept.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ap1Encryption {
    /// No encryption (`et=0`). Audio passes through undecrypted.
    None,
    /// RSA session-key exchange (`et=1`, `a=rsaaeskey`).
    Rsa,
    /// FairPlay DRM (`et=3`, `POST /fp-setup` + `a=fpaeskey`).
    FairPlay,
}

impl Ap1Encryption {
    /// The `et` TXT record digit for this mode.
    pub(crate) const fn txt_value(self) -> &'static str {
        match self {
            Ap1Encryption::None => "0",
            Ap1Encryption::Rsa => "1",
            Ap1Encryption::FairPlay => "3",
        }
    }
}

/// Audio format descriptor passed to [`AudioHandler::audio_init`].
#[derive(Debug, Clone, Copy)]
pub struct AudioFormat {
    /// Audio codec (always PCM for decoded output).
    pub codec: AudioCodec,
    /// Bits per sample (always 32 — samples are delivered as `&[f32]`).
    pub bits: u8,
    /// Number of channels.
    pub channels: u8,
    /// Sample rate in Hz.
    pub sample_rate: u32,
}

/// Trait for receiving AirPlay events and creating audio sessions.
///
/// `AudioHandler` is `Send + Sync` — all callbacks can be called from any thread
/// without blocking audio delivery. Metadata, volume, and artwork callbacks are
/// called directly from the RTSP handler thread, never from the audio path.
///
/// A new [`AudioSession`] is created for each audio stream via
/// [`audio_init`](AudioHandler::audio_init). The session only receives PCM samples.
pub trait AudioHandler: Send + Sync + 'static {
    /// Called when a new audio stream starts. Return a session to receive PCM data.
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession>;

    // --- Metadata events (called from RTSP thread, never blocks audio) ---

    /// Volume change in dB (0.0 = max, -144.0 = mute).
    fn on_volume(&self, _volume: f32) {}
    /// Track metadata (parsed from DMAP).
    fn on_metadata(&self, _metadata: &crate::proto::dmap::TrackMetadata) {}
    /// Album artwork (JPEG or PNG).
    fn on_coverart(&self, _coverart: &[u8]) {}
    /// Playback progress (start, current, end in RTP timestamps at 44100 Hz).
    fn on_progress(&self, _start: u32, _current: u32, _end: u32) {}
    /// A remote control interface is available (AP1 DACP).
    fn on_remote_control(&self, _remote: Arc<dyn RemoteControl>) {}

    // --- Connection lifecycle ---

    /// Called when a client connects.
    fn on_client_connected(&self, _addr: &str) {}
    /// Called when a client disconnects.
    fn on_client_disconnected(&self, _addr: &str) {}
    /// Called when the library hits a runtime error on a connection — e.g. a
    /// pairing/pair-verify failure, a FairPlay or session-key decrypt failure, a
    /// rejected stream format, or an audio-decoder init failure. Fired at most
    /// once per failure (never per audio packet). Default: log at warn level.
    fn on_error(&self, error: &crate::error::ShairplayError) {
        tracing::warn!(%error, "AirPlay error");
    }
}

/// Storage for paired device keys. Implement this to persist pairing across restarts.
///
/// Without persistence, iPhones that previously paired will send encrypted data
/// on connect and fail because the server has no cached keys.
#[cfg(feature = "ap2")]
pub trait PairingStore: Send + Sync + 'static {
    /// Look up a paired device's Ed25519 public key by device ID.
    fn get(&self, device_id: &str) -> Option<[u8; 32]>;
    /// Save a paired device's Ed25519 public key.
    fn put(&self, device_id: &str, public_key: [u8; 32]);
    /// Remove a paired device.
    fn remove(&self, device_id: &str);

    /// Returns `true` once at least one controller is paired.
    ///
    /// Used to advertise `OneTimePairingRequired` (statusFlags bit 9) only until
    /// the first successful pairing, so already-paired controllers reconnect via
    /// pair-verify instead of being nudged back into setup. The default returns
    /// `false` (always advertise setup-required when a PIN is configured); the
    /// built-in [`MemoryPairingStore`] overrides it, and persistent stores should
    /// too.
    fn has_any_pairing(&self) -> bool {
        false
    }

    /// Load the accessory's persistent Ed25519 **identity** seed, if one was saved.
    ///
    /// This is the server's *own* long-term secret (distinct from the paired peer
    /// keys handled by [`get`](Self::get)/[`put`](Self::put)). Returning `Some`
    /// keeps the accessory's identity — and therefore its advertised `pk` — stable
    /// across restarts so already-paired devices don't need to re-pair.
    ///
    /// The default returns `None`: the server then generates a fresh random
    /// identity on each start and offers it to [`save_identity`](Self::save_identity).
    /// Implement both methods to persist the identity. (To reproduce the legacy
    /// insecure behaviour, return the zero-padded device id as the seed.)
    fn load_identity(&self) -> Option<[u8; 32]> {
        None
    }

    /// Persist the accessory's Ed25519 identity seed generated at startup.
    ///
    /// The default is a no-op (identity is not persisted). Implement together with
    /// [`load_identity`](Self::load_identity) to keep a stable identity.
    fn save_identity(&self, _seed: [u8; 32]) {}
}

/// In-memory pairing store (lost on process restart).
///
/// Stores paired controller keys and the accessory identity seed in memory for
/// the lifetime of this object. Use for testing or wrap with file I/O for
/// persistence across restarts.
#[cfg(feature = "ap2")]
#[derive(Default)]
pub struct MemoryPairingStore {
    keys: std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>>,
    identity_seed: std::sync::Mutex<Option<[u8; 32]>>,
}

#[cfg(feature = "ap2")]
impl PairingStore for MemoryPairingStore {
    fn get(&self, device_id: &str) -> Option<[u8; 32]> {
        self.keys.lock().ok()?.get(device_id).copied()
    }
    fn put(&self, device_id: &str, public_key: [u8; 32]) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.insert(device_id.to_string(), public_key);
        }
    }
    fn has_any_pairing(&self) -> bool {
        self.keys.lock().map(|k| !k.is_empty()).unwrap_or(false)
    }
    fn load_identity(&self) -> Option<[u8; 32]> {
        self.identity_seed.lock().ok().and_then(|seed| *seed)
    }
    fn save_identity(&self, seed: [u8; 32]) {
        if let Ok(mut identity_seed) = self.identity_seed.lock() {
            *identity_seed = Some(seed);
        }
    }
    fn remove(&self, device_id: &str) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.remove(device_id);
        }
    }
}

/// Per-connection audio session — hot path only.
///
/// Created by [`AudioHandler::audio_init`]. Dropped when the client disconnects.
/// Only receives decoded PCM samples and flush events. All metadata, volume,
/// and artwork events go to [`AudioHandler`] instead.
pub trait AudioSession: Send + Sync {
    /// Receive decoded f32 interleaved PCM audio samples.
    fn audio_process(&mut self, samples: &[f32]);
    /// Flush the audio buffer (e.g. on seek).
    fn audio_flush(&mut self) {}
}

/// Playback command to send to the source device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteCommand {
    /// Start playback.
    Play,
    /// Pause playback.
    Pause,
    /// Skip to next track.
    NextTrack,
    /// Skip to previous track.
    PreviousTrack,
    /// Set volume (0-100).
    SetVolume(u8),
    /// Toggle shuffle mode.
    ToggleShuffle,
    /// Toggle repeat mode.
    ToggleRepeat,
    /// Stop playback.
    Stop,
}

/// Unified remote control interface for AP1 (DACP) and AP2 (MediaRemote).
pub trait RemoteControl: Send + Sync {
    /// Send a playback command to the source device.
    fn send_command(&self, cmd: RemoteCommand) -> Result<(), crate::error::ShairplayError>;
    /// Commands the source device supports. AP1 returns all; AP2 returns advertised set.
    fn available_commands(&self) -> Vec<RemoteCommand>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn ap1_codec_txt_values_match_protocol() {
        assert_eq!(Ap1Codec::Pcm.txt_value(), "0");
        assert_eq!(Ap1Codec::Alac.txt_value(), "1");
    }

    #[test]
    fn ap1_encryption_txt_values_match_protocol() {
        assert_eq!(Ap1Encryption::None.txt_value(), "0");
        assert_eq!(Ap1Encryption::Rsa.txt_value(), "1");
        assert_eq!(Ap1Encryption::FairPlay.txt_value(), "3");
    }

    struct NoopRemote;

    impl RemoteControl for NoopRemote {
        fn send_command(&self, _cmd: RemoteCommand) -> Result<(), crate::error::ShairplayError> {
            Ok(())
        }

        fn available_commands(&self) -> Vec<RemoteCommand> {
            vec![RemoteCommand::Play, RemoteCommand::SetVolume(20)]
        }
    }

    struct TestAudioSession {
        calls: usize,
    }

    impl AudioSession for TestAudioSession {
        fn audio_process(&mut self, samples: &[f32]) {
            self.calls += samples.len();
        }
    }

    struct TestAudioHandler {
        init_count: Mutex<usize>,
    }

    impl AudioHandler for TestAudioHandler {
        fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession> {
            assert_eq!(format.codec, AudioCodec::Pcm);
            assert_eq!(format.bits, 32);
            assert_eq!(format.channels, 2);
            assert_eq!(format.sample_rate, 44_100);
            *self.init_count.lock().expect("init count mutex poisoned") += 1;
            Box::new(TestAudioSession { calls: 0 })
        }
    }

    #[test]
    fn audio_handler_default_callbacks_are_callable() {
        let handler = TestAudioHandler {
            init_count: Mutex::new(0),
        };

        let mut session = handler.audio_init(AudioFormat {
            codec: AudioCodec::Pcm,
            bits: 32,
            channels: 2,
            sample_rate: 44_100,
        });
        session.audio_process(&[0.0, 0.5, -0.5]);
        session.audio_flush();

        handler.on_volume(-12.0);
        handler.on_coverart(b"png");
        handler.on_progress(1, 2, 3);
        handler.on_client_connected("127.0.0.1:7000");
        handler.on_client_disconnected("127.0.0.1:7000");
        handler.on_remote_control(Arc::new(NoopRemote));

        assert_eq!(*handler.init_count.lock().expect("init count mutex poisoned"), 1);
    }

    #[cfg(feature = "ap2")]
    struct EmptyPairingStore;

    #[cfg(feature = "ap2")]
    impl PairingStore for EmptyPairingStore {
        fn get(&self, _device_id: &str) -> Option<[u8; 32]> {
            None
        }

        fn put(&self, _device_id: &str, _public_key: [u8; 32]) {}

        fn remove(&self, _device_id: &str) {}
    }

    #[cfg(feature = "ap2")]
    #[test]
    fn pairing_store_default_methods_are_safe() {
        let store = EmptyPairingStore;
        assert!(!store.has_any_pairing());
        assert_eq!(store.load_identity(), None);
        store.save_identity([7u8; 32]);
        assert_eq!(store.load_identity(), None);
    }

    #[cfg(feature = "ap2")]
    #[test]
    fn memory_pairing_store_roundtrip_and_identity() {
        let store = MemoryPairingStore::default();
        assert!(!store.has_any_pairing());
        assert_eq!(store.load_identity(), None);

        store.put("dev1", [1u8; 32]);
        assert!(store.has_any_pairing());
        assert_eq!(store.get("dev1"), Some([1u8; 32]));

        store.save_identity([9u8; 32]);
        assert_eq!(store.load_identity(), Some([9u8; 32]));

        store.remove("dev1");
        assert_eq!(store.get("dev1"), None);
        assert!(!store.has_any_pairing());
    }

    #[cfg(feature = "ap2")]
    #[test]
    fn airplay_mode_default_is_ap2() {
        assert_eq!(AirPlayMode::default(), AirPlayMode::AirPlay2);
    }
}
