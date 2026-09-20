//! AirPlay 2 buffered audio processor (stream type 103).
//!
//! Receives encrypted AAC packets over TCP, decrypts with ChaCha20-Poly1305,
//! decodes via symphonia, resamples/mixes down, and delivers F32LE PCM through
//! a timed playout buffer.
//!
//! Three concurrent tasks:
//! - **Receiver** (tokio): accepts TCP, decrypts, decodes, buffers by RTP timestamp
//! - **Command handler** (tokio): processes SetRate/Flush/Stop from RTSP thread
//! - **Delivery** (std::thread): timed playout using anchor-based scheduling

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::codec::aac::{AacDecoder, AudioSsrc};
use crate::error::{CodecError, NetworkError, ShairplayError};
use crate::raop::audio_pipeline::{NONCE_TRAIL_LEN, RTP_HEADER_LEN, decrypt_rtp_chacha};
use crate::raop::{AudioCodec, AudioFormat, AudioHandler};
use crate::util::now_ns;

#[derive(Debug, Clone)]
/// Output configuration passed from the server builder.
pub(crate) struct OutputConfig {
    /// Target sample rate, or None for source native rate.
    pub(crate) sample_rate: Option<u32>,
    /// Maximum output channels, or None to pass through.
    pub(crate) max_channels: Option<u8>,
}

#[derive(Debug)]
/// Commands sent from the RTSP handler thread to the playout engine.
pub enum PlayoutCommand {
    /// Set playback rate and anchor point. rate=0 means pause.
    SetRate {
        /// RTP timestamp at the anchor point.
        anchor_rtp: u32,
        /// Network time at the anchor point (ns).
        anchor_time_ns: u64,
        /// Playback rate (1 = playing, 0 = paused).
        rate: u32,
    },
    /// Flush buffered frames in the given RTP timestamp range.
    Flush {
        /// First timestamp to flush.
        from_seq: u32,
        /// Last timestamp to flush.
        until_seq: u32,
    },
    /// Stop playback and tear down.
    Stop,
}

struct PlayoutState {
    buffer: BTreeMap<u32, Vec<f32>>, // rtp_timestamp → F32 PCM samples
    anchor_rtp: u32,
    anchor_local_ns: u64,
    rate: u32,
    sample_rate: u32,
    channels: u8,
    stopped: bool,
    format_changed: bool,
    flush_pending: bool,
}

fn apply_playout_command(
    s: &mut PlayoutState,
    cmd: PlayoutCommand,
    now_ns_fn: impl FnOnce() -> u64,
) -> bool {
    match cmd {
        PlayoutCommand::SetRate {
            anchor_rtp,
            anchor_time_ns: _,
            rate,
        } => {
            s.anchor_rtp = anchor_rtp;
            let was_paused = s.rate == 0;
            s.rate = rate;
            if rate == 0 {
                info!("Playout paused");
            } else {
                // Set anchor so the earliest buffered frame is deliverable
                // with a small lead time for smooth playback.
                if let Some(&first_ts) = s.buffer.keys().next() {
                    let lead_frames = s.sample_rate / 10; // 100ms lead
                    s.anchor_rtp = first_ts.wrapping_sub(lead_frames);
                }
                s.anchor_local_ns = now_ns_fn();
                let stale: Vec<u32> = s
                    .buffer
                    .keys()
                    .filter(|&&ts| (s.anchor_rtp.wrapping_sub(ts) as i32) > 0)
                    .copied()
                    .collect();
                if !stale.is_empty() {
                    debug!(discarded = stale.len(), "Discarded stale frames");
                }
                for k in stale {
                    s.buffer.remove(&k);
                }
                if was_paused {
                    info!(anchor_rtp, "Playout started");
                }
            }
            true
        }
        PlayoutCommand::Flush {
            from_seq,
            until_seq,
        } => {
            let keys: Vec<u32> = s
                .buffer
                .keys()
                .filter(|&&ts| ts >= from_seq && ts <= until_seq)
                .copied()
                .collect();
            for k in &keys {
                s.buffer.remove(k);
            }
            // Mirror AP1 behavior: propagate RTSP flush to the active
            // audio session even when no queued frame matches.
            s.flush_pending = true;
            debug!(flushed = keys.len(), "Flushed");
            true
        }
        PlayoutCommand::Stop => {
            s.stopped = true;
            s.buffer.clear();
            false
        }
    }
}

/// TCP listener for buffered audio. Binds a port and spawns the processing pipeline.
pub(crate) struct BufferedAudioProcessor {
    /// TCP listener waiting for the iPhone to connect.
    pub(crate) listener: TcpListener,
}

impl BufferedAudioProcessor {
    /// Start the processing pipeline. Returns a command sender for playback control.
    pub(crate) fn start(
        self,
        shk: [u8; 32],
        output_config: OutputConfig,
        handler: Arc<dyn AudioHandler>,
    ) -> tokio::sync::mpsc::UnboundedSender<PlayoutCommand> {
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let default_sr = output_config.sample_rate.unwrap_or(44100);

        let state = Arc::new((
            Mutex::new(PlayoutState {
                buffer: BTreeMap::new(),
                anchor_rtp: 0,
                anchor_local_ns: 0,
                rate: 0,
                sample_rate: default_sr,
                channels: 2,
                stopped: false,
                format_changed: false,
                flush_pending: false,
            }),
            Condvar::new(),
        ));

        // Delivery thread
        let state2 = state.clone();
        let handler2 = handler.clone();
        let output_config2 = output_config.clone();
        std::thread::spawn(move || {
            delivery_loop(state2, handler2, output_config2);
        });

        // Command handler
        let state3 = state.clone();
        let mut cmd_rx = cmd_rx;
        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                let (lock, cvar) = &*state3;
                let mut s = lock.lock().unwrap();
                let keep_running = apply_playout_command(&mut s, cmd, now_ns);
                cvar.notify_all();
                if !keep_running {
                    break;
                }
            }
        });

        // Receiver task
        let state4 = state.clone();

        tokio::spawn(async move {
            let (stream, addr) = match self.listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Buffered audio accept failed: {e}");
                    handler.on_error(&ShairplayError::Network(NetworkError::Io(e)));
                    return;
                }
            };
            info!(%addr, "Buffered audio client connected");
            receive_loop(stream, &shk, output_config, state4, &handler).await;
        });

        cmd_tx
    }
}

/// TCP receive loop: reads length-prefixed packets, decrypts, decodes, buffers.
async fn receive_loop(
    mut stream: TcpStream,
    shk: &[u8; 32],
    output_config: OutputConfig,
    state: Arc<(Mutex<PlayoutState>, Condvar)>,
    handler: &Arc<dyn AudioHandler>,
) {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

    let cipher = ChaCha20Poly1305::new(shk.into());
    let mut len_buf = [0u8; 2];
    let mut decoder: Option<AacDecoder> = None;
    let mut current_ssrc = AudioSsrc::None;
    let mut stream_resampler: Option<crate::codec::resample::StreamResampler> = None;
    let mut source_channels: u8 = 2;
    let mut output_channels: u8 = 2;

    loop {
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let total_len = u16::from_be_bytes(len_buf) as usize;
        if total_len < 2 {
            break;
        }

        let mut packet = vec![0u8; total_len - 2];
        if stream.read_exact(&mut packet).await.is_err() {
            break;
        }
        if packet.len() <= RTP_HEADER_LEN + NONCE_TRAIL_LEN {
            continue;
        }

        let timestamp = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        let ssrc_val = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
        let ssrc = AudioSsrc::from_u32(ssrc_val);

        // Detect format change
        if ssrc != AudioSsrc::None && ssrc != current_ssrc {
            current_ssrc = ssrc;
            let src_sr = ssrc.sample_rate();
            let src_ch = ssrc.channels();
            info!(ssrc = ?ssrc, src_sr, src_ch, "Audio format detected");

            decoder = AacDecoder::new(src_sr, src_ch).ok();
            if decoder.is_none() {
                warn!("Failed to create AAC decoder for {:?}", ssrc);
                handler.on_error(&ShairplayError::Codec(CodecError::UnsupportedFormat(format!(
                    "AAC decoder init failed (ssrc={ssrc:?}, sample_rate={src_sr}, channels={src_ch})"
                ))));
            }

            let target_sr = output_config.sample_rate.unwrap_or(src_sr);
            let target_ch = output_config
                .max_channels
                .map(|max| src_ch.min(max))
                .unwrap_or(src_ch);

            stream_resampler =
                crate::codec::resample::StreamResampler::new(src_sr, target_sr, target_ch as usize);
            if stream_resampler.is_some() {
                debug!(from = src_sr, to = target_sr, "Resampler initialized");
            }

            source_channels = src_ch;
            output_channels = target_ch;

            // Signal format change to delivery thread
            let (lock, cvar) = &*state;
            let mut s = lock.lock().unwrap();
            s.sample_rate = target_sr;
            s.channels = target_ch;
            s.format_changed = true;
            cvar.notify_all();
        }

        // Decrypt the ChaCha20-Poly1305 RTP frame.
        let Some(plaintext) = decrypt_rtp_chacha(&cipher, &packet) else {
            debug!("Audio decrypt failed");
            continue;
        };

        // Decode raw AAC payload by ADTS-framing it in the decoder.
        let pcm = if let Some(dec) = &mut decoder {
            match dec.decode(&plaintext) {
                Ok(pcm) => Some(pcm),
                Err(e) => {
                    debug!(error = %e, ssrc = ?current_ssrc, "AAC decode failed");
                    None
                }
            }
        } else {
            None
        };

        if let Some(pcm_data) = pcm {
            // Convert bytes to f32 samples for processing
            let samples: Vec<f32> = pcm_data
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect();

            // Mix down + resample to the output format.
            let samples = crate::codec::resample::mixdown_and_resample(
                samples,
                source_channels,
                output_channels,
                &mut stream_resampler,
            );

            let (lock, cvar) = &*state;
            let mut s = lock.lock().unwrap();
            s.buffer.insert(timestamp, samples);
            cvar.notify_all();
        }
    }
    debug!("Buffered audio receive loop ended");
    let (lock, cvar) = &*state;
    if let Ok(mut s) = lock.lock() {
        s.stopped = true;
        s.buffer.clear();
        cvar.notify_all();
    }
}

/// Timed playout delivery thread. Wakes on condvar, delivers due frames to AudioSession.
fn delivery_loop(
    state: Arc<(Mutex<PlayoutState>, Condvar)>,
    handler: Arc<dyn AudioHandler>,
    _output_config: OutputConfig,
) {
    let (lock, cvar) = &*state;
    let mut session: Option<Box<dyn crate::raop::AudioSession>> = None;

    loop {
        let mut s = lock.lock().unwrap();

        while !s.stopped && !s.flush_pending && (s.rate == 0 || s.buffer.is_empty()) {
            s = cvar.wait(s).unwrap();
        }
        if s.stopped {
            break;
        }

        // Lazy init or reinit session on format change
        if session.is_none() || s.format_changed {
            s.format_changed = false;
            let format = AudioFormat {
                codec: AudioCodec::Pcm,
                bits: 32,
                channels: s.channels,
                sample_rate: s.sample_rate,
            };
            info!(?format, "Audio session initialized");
            session = Some(handler.audio_init(format));
        }

        let do_flush = s.flush_pending;
        s.flush_pending = false;

        let now = now_ns();
        let elapsed_ns = now.saturating_sub(s.anchor_local_ns);
        let elapsed_frames = (elapsed_ns as u128 * s.sample_rate as u128 / 1_000_000_000) as u32;
        let target_rtp = s.anchor_rtp.wrapping_add(elapsed_frames);

        let ready: Vec<(u32, Vec<f32>)> = s
            .buffer
            .iter()
            .filter(|(ts, _)| (target_rtp.wrapping_sub(**ts) as i32) >= 0)
            .map(|(&ts, data)| (ts, data.clone()))
            .collect();

        for (ts, _) in &ready {
            s.buffer.remove(ts);
        }
        drop(s);

        if let Some(ref mut sess) = session {
            if do_flush {
                sess.audio_flush();
            }
            for (_, frame) in &ready {
                sess.audio_process(frame);
            }
        }

        if ready.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    info!("Delivery loop ended");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    struct CountingSession {
        processed: Arc<AtomicUsize>,
        flushed: Arc<AtomicUsize>,
    }

    impl crate::raop::AudioSession for CountingSession {
        fn audio_process(&mut self, samples: &[f32]) {
            self.processed.fetch_add(samples.len(), Ordering::SeqCst);
        }

        fn audio_flush(&mut self) {
            self.flushed.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct CountingHandler {
        init_calls: Arc<AtomicUsize>,
        processed: Arc<AtomicUsize>,
        flushed: Arc<AtomicUsize>,
    }

    impl AudioHandler for CountingHandler {
        fn audio_init(&self, _format: AudioFormat) -> Box<dyn crate::raop::AudioSession> {
            self.init_calls.fetch_add(1, Ordering::SeqCst);
            Box::new(CountingSession {
                processed: Arc::clone(&self.processed),
                flushed: Arc::clone(&self.flushed),
            })
        }
    }

    fn fresh_state() -> PlayoutState {
        PlayoutState {
            buffer: BTreeMap::new(),
            anchor_rtp: 0,
            anchor_local_ns: 0,
            rate: 0,
            sample_rate: 44_100,
            channels: 2,
            stopped: false,
            format_changed: false,
            flush_pending: false,
        }
    }

    #[test]
    fn apply_playout_command_set_rate_sets_anchor_and_discards_stale() {
        let mut s = fresh_state();
        s.buffer.insert(10_000, vec![0.1; 4]);
        s.buffer.insert(20_000, vec![0.2; 4]);

        let keep = apply_playout_command(
            &mut s,
            PlayoutCommand::SetRate {
                anchor_rtp: 1,
                anchor_time_ns: 0,
                rate: 1,
            },
            || 123,
        );

        assert!(keep);
        // lead_frames = 44100/10 = 4410 => anchor 10000-4410=5590, so 10000/20000 remain fresh
        assert_eq!(s.anchor_rtp, 5_590);
        assert_eq!(s.anchor_local_ns, 123);
        assert_eq!(s.rate, 1);
        assert!(s.buffer.contains_key(&10_000));
        assert!(s.buffer.contains_key(&20_000));
    }

    #[test]
    fn apply_playout_command_flush_and_stop_paths() {
        let mut s = fresh_state();
        s.buffer.insert(100, vec![0.1]);
        s.buffer.insert(200, vec![0.2]);
        s.buffer.insert(300, vec![0.3]);

        let keep = apply_playout_command(
            &mut s,
            PlayoutCommand::Flush {
                from_seq: 150,
                until_seq: 300,
            },
            now_ns,
        );
        assert!(keep);
        assert!(s.flush_pending);
        assert!(s.buffer.contains_key(&100));
        assert!(!s.buffer.contains_key(&200));
        assert!(!s.buffer.contains_key(&300));

        let keep = apply_playout_command(&mut s, PlayoutCommand::Stop, now_ns);
        assert!(!keep);
        assert!(s.stopped);
        assert!(s.buffer.is_empty());
    }

    #[test]
    fn delivery_loop_initializes_session_and_processes_ready_frames_and_flush() {
        let state = Arc::new((Mutex::new(fresh_state()), Condvar::new()));
        let init_calls = Arc::new(AtomicUsize::new(0));
        let processed = Arc::new(AtomicUsize::new(0));
        let flushed = Arc::new(AtomicUsize::new(0));
        let handler: Arc<dyn AudioHandler> = Arc::new(CountingHandler {
            init_calls: Arc::clone(&init_calls),
            processed: Arc::clone(&processed),
            flushed: Arc::clone(&flushed),
        });

        {
            let (lock, _) = &*state;
            let mut s = lock.lock().unwrap();
            s.sample_rate = 10;
            s.channels = 2;
            s.format_changed = true;
            s.rate = 1;
            s.anchor_rtp = 0;
            s.anchor_local_ns = now_ns().saturating_sub(2_000_000_000);
            s.flush_pending = true;
            s.buffer.insert(1, vec![0.1, 0.2]);
            s.buffer.insert(2, vec![0.3, 0.4]);
        }

        let state2 = Arc::clone(&state);
        let handler2 = Arc::clone(&handler);
        let thread = std::thread::spawn(move || {
            delivery_loop(
                state2,
                handler2,
                OutputConfig {
                    sample_rate: None,
                    max_channels: None,
                },
            );
        });

        std::thread::sleep(Duration::from_millis(30));
        {
            let (lock, cvar) = &*state;
            let mut s = lock.lock().unwrap();
            s.stopped = true;
            cvar.notify_all();
        }
        thread.join().unwrap();

        assert!(init_calls.load(Ordering::SeqCst) >= 1);
        assert_eq!(processed.load(Ordering::SeqCst), 4);
        assert!(flushed.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn receive_loop_invalid_short_packet_marks_stopped() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            // total_len = 1 (< 2) -> receiver breaks.
            stream.write_all(&[0, 1]).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let (server_stream, _) = listener.accept().await.unwrap();

        let state = Arc::new((Mutex::new(fresh_state()), Condvar::new()));
        let handler: Arc<dyn AudioHandler> = Arc::new(CountingHandler {
            init_calls: Arc::new(AtomicUsize::new(0)),
            processed: Arc::new(AtomicUsize::new(0)),
            flushed: Arc::new(AtomicUsize::new(0)),
        });

        receive_loop(
            server_stream,
            &[1u8; 32],
            OutputConfig {
                sample_rate: None,
                max_channels: None,
            },
            Arc::clone(&state),
            &handler,
        )
        .await;
        client.await.unwrap();

        let (lock, _) = &*state;
        let s = lock.lock().unwrap();
        assert!(s.stopped);
        assert!(s.buffer.is_empty());
    }
}
