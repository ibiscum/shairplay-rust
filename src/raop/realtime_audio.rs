//! Realtime ALAC audio receiver (stream type 96).
//!
//! Receives UDP packets with RTP headers, decrypts with ChaCha20-Poly1305,
//! decodes ALAC, resamples/mixes down, and delivers f32 PCM immediately.

use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

use crate::error::{NetworkError, ShairplayError};
use crate::raop::audio_pipeline::{NONCE_TRAIL_LEN, RTP_HEADER_LEN, decrypt_rtp_chacha};
use crate::raop::{AudioCodec, AudioFormat, AudioHandler};

#[cfg(feature = "resample")]
use crate::codec::resample::StreamResampler;

/// Output configuration for resampling/mixdown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutputConfig {
    /// Source sample rate from the stream SETUP.
    pub(crate) source_sample_rate: u32,
    /// Source samples per ALAC frame from the stream SETUP.
    pub(crate) samples_per_frame: u32,
    /// Source channel count.
    pub(crate) channels: u8,
    /// Source bit depth.
    pub(crate) bit_depth: u8,
    /// Target sample rate, or None for source native rate.
    pub(crate) sample_rate: Option<u32>,
    /// Maximum output channels, or None to pass through.
    pub(crate) max_channels: Option<u8>,
}

fn normalize_output_config(config: &OutputConfig) -> OutputConfig {
    OutputConfig {
        source_sample_rate: if config.source_sample_rate == 0 {
            44_100
        } else {
            config.source_sample_rate
        },
        samples_per_frame: if config.samples_per_frame == 0 {
            352
        } else {
            config.samples_per_frame
        },
        channels: if config.channels == 0 {
            2
        } else {
            config.channels
        },
        bit_depth: if config.bit_depth == 0 {
            16
        } else {
            config.bit_depth
        },
        sample_rate: config.sample_rate.filter(|&r| r > 0),
        max_channels: config.max_channels.filter(|&c| c > 0),
    }
}

fn alac_decoder_info(config: &OutputConfig) -> [u8; 48] {
    let mut info = [0u8; 48];
    info[24..28].copy_from_slice(&config.samples_per_frame.to_be_bytes());
    info[29] = config.bit_depth;
    info[30] = 40; // pb
    info[31] = 10; // mb
    info[32] = 14; // kb
    info[33] = config.channels;
    info[34..36].copy_from_slice(&255u16.to_be_bytes());
    info[44..48].copy_from_slice(&config.source_sample_rate.to_be_bytes());
    info
}

/// Run the realtime audio receiver loop.
pub(crate) async fn run(
    socket: UdpSocket,
    shk: [u8; 32],
    handler: Arc<dyn AudioHandler>,
    output_config: OutputConfig,
) {
    let cipher = ChaCha20Poly1305::new((&shk).into());
    let mut buf = vec![0u8; 4096];
    let normalized_output_config = normalize_output_config(&output_config);
    if normalized_output_config != output_config {
        warn!(
            ?output_config,
            normalized = ?normalized_output_config,
            "Realtime audio setup contained invalid zero values; using safe defaults"
        );
    }
    let output_config = normalized_output_config;
    let mut decoder: Option<crate::codec::alac::AlacDecoder> = None;
    #[cfg(feature = "resample")]
    let mut resampler: Option<StreamResampler> = None;
    let mut session: Option<Box<dyn crate::raop::AudioSession>> = None;
    #[allow(unused_assignments)]
    let mut src_sr: u32 = 44100;
    let mut src_ch: u8 = 2;
    let mut out_ch: u8 = 2;

    info!("Realtime ALAC receiver started");

    loop {
        let n = match socket.recv(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                warn!("Realtime audio recv error: {e}");
                handler.on_error(&ShairplayError::Network(NetworkError::Io(e)));
                break;
            }
        };

        let packet = &buf[..n];
        if packet.len() <= RTP_HEADER_LEN + NONCE_TRAIL_LEN {
            continue;
        }

        // Lazy init decoder + session on first packet
        if session.is_none() {
            src_sr = output_config.source_sample_rate;
            src_ch = output_config.channels;
            let target_sr = output_config.sample_rate.unwrap_or(src_sr);
            out_ch = output_config
                .max_channels
                .map(|m| src_ch.min(m))
                .unwrap_or(src_ch);

            let mut alac =
                crate::codec::alac::AlacDecoder::new(output_config.bit_depth as i32, src_ch as i32);
            let decoder_info = alac_decoder_info(&output_config);
            alac.set_info(&decoder_info);
            decoder = Some(alac);
            #[cfg(feature = "resample")]
            if target_sr != src_sr {
                resampler = StreamResampler::new(src_sr, target_sr, out_ch as usize);
            }

            let format = AudioFormat {
                codec: AudioCodec::Pcm,
                bits: 32,
                channels: out_ch,
                sample_rate: output_config.sample_rate.unwrap_or(src_sr),
            };
            info!(?format, "Realtime audio session initialized");
            session = Some(handler.audio_init(format));
        }

        // Decrypt the ChaCha20-Poly1305 RTP frame.
        let Some(alac_data) = decrypt_rtp_chacha(&cipher, packet) else {
            debug!("Realtime audio decrypt failed");
            continue;
        };

        // Decode ALAC → f32 PCM
        let Some(mut samples) = decoder
            .as_mut()
            .and_then(|d| d.decode_frame_f32(&alac_data))
        else {
            continue;
        };

        // Mix down + resample to the output format.
        #[cfg(feature = "resample")]
        {
            samples = crate::codec::resample::mixdown_and_resample(
                samples,
                src_ch,
                out_ch,
                &mut resampler,
            );
        }

        // Deliver immediately (realtime = no playout buffer)
        if let Some(ref mut sess) = session {
            sess.audio_process(&samples);
        }
    }

    debug!("Realtime ALAC receiver ended");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::time::{Duration, Instant};

    use crate::raop::audio_pipeline::CHACHA_TAG_LEN;

    #[test]
    fn alac_decoder_info_uses_realtime_setup_values() {
        let info = alac_decoder_info(&OutputConfig {
            source_sample_rate: 48_000,
            samples_per_frame: 352,
            channels: 2,
            bit_depth: 16,
            sample_rate: None,
            max_channels: None,
        });

        assert_eq!(u32::from_be_bytes(info[24..28].try_into().unwrap()), 352);
        assert_eq!(info[29], 16);
        assert_eq!(info[30], 40);
        assert_eq!(info[31], 10);
        assert_eq!(info[32], 14);
        assert_eq!(info[33], 2);
        assert_eq!(u16::from_be_bytes(info[34..36].try_into().unwrap()), 255);
        assert_eq!(u32::from_be_bytes(info[44..48].try_into().unwrap()), 48_000);
    }

    #[test]
    fn normalize_output_config_sanitizes_zero_values() {
        let cfg = normalize_output_config(&OutputConfig {
            source_sample_rate: 0,
            samples_per_frame: 0,
            channels: 0,
            bit_depth: 0,
            sample_rate: Some(0),
            max_channels: Some(0),
        });

        assert_eq!(
            cfg,
            OutputConfig {
                source_sample_rate: 44_100,
                samples_per_frame: 352,
                channels: 2,
                bit_depth: 16,
                sample_rate: None,
                max_channels: None,
            }
        );
    }

    #[test]
    fn normalize_output_config_preserves_valid_values() {
        let original = OutputConfig {
            source_sample_rate: 48_000,
            samples_per_frame: 480,
            channels: 6,
            bit_depth: 24,
            sample_rate: Some(96_000),
            max_channels: Some(2),
        };

        let cfg = normalize_output_config(&original);
        assert_eq!(cfg, original);
    }

    struct CaptureSession {
        process_calls: Arc<AtomicUsize>,
    }

    impl crate::raop::AudioSession for CaptureSession {
        fn audio_process(&mut self, _samples: &[f32]) {
            self.process_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct CaptureHandler {
        init_calls: Arc<AtomicUsize>,
        process_calls: Arc<AtomicUsize>,
        init_format: Arc<Mutex<Option<AudioFormat>>>,
    }

    impl AudioHandler for CaptureHandler {
        fn audio_init(&self, format: AudioFormat) -> Box<dyn crate::raop::AudioSession> {
            self.init_calls.fetch_add(1, Ordering::SeqCst);
            *self
                .init_format
                .lock()
                .expect("init format mutex poisoned") = Some(format);
            Box::new(CaptureSession {
                process_calls: Arc::clone(&self.process_calls),
            })
        }
    }

    #[tokio::test]
    async fn run_ignores_too_short_packets_without_initializing_session() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let init_calls = Arc::new(AtomicUsize::new(0));
        let process_calls = Arc::new(AtomicUsize::new(0));
        let init_format = Arc::new(Mutex::new(None));
        let handler: Arc<dyn AudioHandler> = Arc::new(CaptureHandler {
            init_calls: Arc::clone(&init_calls),
            process_calls: Arc::clone(&process_calls),
            init_format: Arc::clone(&init_format),
        });

        let task = tokio::spawn(run(
            receiver,
            [7u8; 32],
            handler,
            OutputConfig {
                source_sample_rate: 44_100,
                samples_per_frame: 352,
                channels: 2,
                bit_depth: 16,
                sample_rate: None,
                max_channels: None,
            },
        ));

        // len == RTP_HEADER_LEN + NONCE_TRAIL_LEN should be ignored early.
        let short = vec![0u8; RTP_HEADER_LEN + NONCE_TRAIL_LEN];
        sender.send_to(&short, receiver_addr).await.unwrap();

        tokio::time::sleep(Duration::from_millis(30)).await;
        task.abort();

        assert_eq!(init_calls.load(Ordering::SeqCst), 0);
        assert_eq!(process_calls.load(Ordering::SeqCst), 0);
        assert!(
            init_format
                .lock()
                .expect("init format mutex poisoned")
                .is_none()
        );
    }

    #[tokio::test]
    async fn run_initializes_session_before_decrypt_with_expected_format() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let init_calls = Arc::new(AtomicUsize::new(0));
        let process_calls = Arc::new(AtomicUsize::new(0));
        let init_format = Arc::new(Mutex::new(None));
        let handler: Arc<dyn AudioHandler> = Arc::new(CaptureHandler {
            init_calls: Arc::clone(&init_calls),
            process_calls: Arc::clone(&process_calls),
            init_format: Arc::clone(&init_format),
        });

        let task = tokio::spawn(run(
            receiver,
            [9u8; 32],
            handler,
            OutputConfig {
                source_sample_rate: 48_000,
                samples_per_frame: 480,
                channels: 6,
                bit_depth: 24,
                sample_rate: Some(96_000),
                max_channels: Some(2),
            },
        ));

        // Large enough to pass len guard and trigger lazy init, but invalid so decrypt fails.
        let invalid_packet = vec![0u8; RTP_HEADER_LEN + CHACHA_TAG_LEN + NONCE_TRAIL_LEN];
        sender.send_to(&invalid_packet, receiver_addr).await.unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        while init_calls.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        task.abort();

        assert_eq!(init_calls.load(Ordering::SeqCst), 1);
        assert_eq!(process_calls.load(Ordering::SeqCst), 0);

        let format = init_format
            .lock()
            .expect("init format mutex poisoned")
            .expect("audio_init should capture format");
        assert_eq!(format.codec, AudioCodec::Pcm);
        assert_eq!(format.bits, 32);
        assert_eq!(format.channels, 2);
        assert_eq!(format.sample_rate, 96_000);
    }
}
