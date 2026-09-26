//! AirPlay 2 buffered audio processor (stream type 103).
//!
//! Receives encrypted AAC packets over TCP, decrypts with ChaCha20-Poly1305,
//! decodes via fdk-aac-rust, resamples/mixes down, and delivers F32LE PCM through
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
    buffer: BTreeMap<u32, BufferedFrame>, // rtp_timestamp → buffered frame + diagnostics
    anchor_rtp: u32,
    anchor_local_ns: u64,
    rate: u32,
    sample_rate: u32,
    channels: u8,
    stopped: bool,
    format_changed: bool,
    flush_pending: bool,
}

#[derive(Clone)]
struct BufferedFrame {
    samples: Vec<f32>,
    ssrc: AudioSsrc,
    decoder_kind: &'static str,
    plaintext_len: usize,
    plaintext_nonzero_bytes: usize,
    plaintext_prefix_hex: String,
    selected_payload_len: usize,
    selected_payload_prefix_hex: String,
    decoded_amp_min: f32,
    decoded_amp_max: f32,
    enqueue_amp_min: f32,
    enqueue_amp_max: f32,
    aac_candidate_count: usize,
    aac_decoded_count: usize,
    aac_non_silent_count: usize,
    aac_best_peak: f32,
}

enum BufferedDecoder {
    Aac(AacDecoder),
    Alac(crate::codec::alac::AlacDecoder),
}

fn alac_decoder_info(sample_rate: u32, bit_depth: u8, channels: u8) -> [u8; 48] {
    let mut info = [0u8; 48];
    let samples_per_frame: u32 = if sample_rate >= 48_000 { 480 } else { 352 };
    info[24..28].copy_from_slice(&samples_per_frame.to_be_bytes());
    info[29] = bit_depth;
    info[30] = 40; // pb
    info[31] = 10; // mb
    info[32] = 14; // kb
    info[33] = channels;
    info[34..36].copy_from_slice(&255u16.to_be_bytes());
    info[44..48].copy_from_slice(&sample_rate.to_be_bytes());
    info
}

fn make_decoder(ssrc: AudioSsrc, src_sr: u32, src_ch: u8) -> Option<BufferedDecoder> {
    if ssrc.is_alac() {
        let bit_depth = ssrc.bit_depth().unwrap_or(16);
        let mut dec = crate::codec::alac::AlacDecoder::new(bit_depth as i32, src_ch as i32);
        let info = alac_decoder_info(src_sr, bit_depth, src_ch);
        dec.set_info(&info);
        return Some(BufferedDecoder::Alac(dec));
    }

    AacDecoder::new(src_sr, src_ch).ok().map(BufferedDecoder::Aac)
}

fn amplitude_min_max(samples: &[f32]) -> (f32, f32) {
    if samples.is_empty() {
        return (0.0, 0.0);
    }

    let mut min = f32::INFINITY;
    let mut max = f32::NEG_INFINITY;
    for &v in samples {
        if v < min {
            min = v;
        }
        if v > max {
            max = v;
        }
    }
    (min, max)
}

fn extract_aac_access_unit(payload: &[u8]) -> Option<&[u8]> {
    // AP2 buffered AAC frames may carry an RFC3640-style AU header section:
    // [AU-headers-length:16b][AU-header...][AAC access unit bytes...].
    // If present, strip it so ADTS wrapping sees a clean AAC frame.
    if payload.len() < 4 {
        return None;
    }

    let au_headers_bits = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    // RFC3640 AU header section must be byte-aligned and reasonably small.
    if au_headers_bits == 0 || !au_headers_bits.is_multiple_of(8) || au_headers_bits > 128 {
        return None;
    }

    let au_headers_bytes = au_headers_bits / 8;
    let data_start = 2 + au_headers_bytes;
    if data_start >= payload.len() {
        return None;
    }

    // First AU-header for AAC-hbr is commonly 16 bits: size(13) + index(3).
    if au_headers_bits >= 16 && payload.len() >= 4 {
        let first_au_header = u16::from_be_bytes([payload[2], payload[3]]);
        let au_size_bits = (first_au_header >> 3) as usize;
        if au_size_bits == 0 {
            return None;
        }

        let au_size_bytes = au_size_bits.div_ceil(8);
        let available = payload.len() - data_start;
        if au_size_bytes <= available {
            return Some(&payload[data_start..data_start + au_size_bytes]);
        }
        return None;
    }

    let au = &payload[data_start..];
    if au.len() >= 8 {
        Some(au)
    } else {
        None
    }
}

fn extract_aac_access_unit_direct_header(payload: &[u8]) -> Option<&[u8]> {
    // Some AP2 senders appear to omit the RFC3640 AU-headers-length field and
    // start directly with one 16-bit AU header: size(13) + index(3).
    if payload.len() < 3 {
        return None;
    }

    let au_header = u16::from_be_bytes([payload[0], payload[1]]);
    let au_size_bits = (au_header >> 3) as usize;
    if au_size_bits == 0 {
        return None;
    }

    let au_size_bytes = au_size_bits.div_ceil(8);
    if au_size_bytes > payload.len().saturating_sub(2) {
        return None;
    }

    let au = &payload[2..2 + au_size_bytes];
    if au.len() >= 8 {
        Some(au)
    } else {
        None
    }
}

fn starts_with_adts_sync(payload: &[u8]) -> bool {
    payload.len() >= 2 && payload[0] == 0xFF && (payload[1] & 0xF0) == 0xF0
}

fn extract_aac_access_unit_shifted(payload: &[u8]) -> Option<(&[u8], &'static str)> {
    // Some senders prepend small side headers ahead of RFC3640 AU headers.
    // Try a small offset window and accept the first plausible AU section.
    for offset in 0..=16 {
        if payload.len() < offset + 4 {
            continue;
        }
        let view = &payload[offset..];
        let Some(au) = extract_aac_access_unit(view) else {
            continue;
        };
        if au.len() < view.len() {
            let label = match offset {
                0 => "aac-au",
                1 => "aac-au+1",
                2 => "aac-au+2",
                3 => "aac-au+3",
                4 => "aac-au+4",
                5 => "aac-au+5",
                6 => "aac-au+6",
                7 => "aac-au+7",
                8 => "aac-au+8",
                9 => "aac-au+9",
                10 => "aac-au+10",
                11 => "aac-au+11",
                12 => "aac-au+12",
                13 => "aac-au+13",
                14 => "aac-au+14",
                15 => "aac-au+15",
                _ => "aac-au+16",
            };
            return Some((au, label));
        }
    }
    None
}

fn aac_au_label_for_offset(offset: usize) -> &'static str {
    match offset {
        0 => "aac-au",
        1 => "aac-au+1",
        2 => "aac-au+2",
        3 => "aac-au+3",
        4 => "aac-au+4",
        5 => "aac-au+5",
        6 => "aac-au+6",
        7 => "aac-au+7",
        8 => "aac-au+8",
        9 => "aac-au+9",
        10 => "aac-au+10",
        11 => "aac-au+11",
        12 => "aac-au+12",
        13 => "aac-au+13",
        14 => "aac-au+14",
        15 => "aac-au+15",
        _ => "aac-au+16",
    }
}

fn aac_au_direct_label_for_offset(offset: usize) -> &'static str {
    match offset {
        0 => "aac-au-direct",
        1 => "aac-au-direct+1",
        2 => "aac-au-direct+2",
        3 => "aac-au-direct+3",
        4 => "aac-au-direct+4",
        5 => "aac-au-direct+5",
        6 => "aac-au-direct+6",
        7 => "aac-au-direct+7",
        8 => "aac-au-direct+8",
        9 => "aac-au-direct+9",
        10 => "aac-au-direct+10",
        11 => "aac-au-direct+11",
        12 => "aac-au-direct+12",
        13 => "aac-au-direct+13",
        14 => "aac-au-direct+14",
        15 => "aac-au-direct+15",
        _ => "aac-au-direct+16",
    }
}

fn aac_raw_label_for_offset(offset: usize) -> &'static str {
    match offset {
        0 => "aac",
        1 => "aac+1",
        2 => "aac+2",
        3 => "aac+3",
        4 => "aac+4",
        5 => "aac+5",
        6 => "aac+6",
        7 => "aac+7",
        8 => "aac+8",
        9 => "aac+9",
        10 => "aac+10",
        11 => "aac+11",
        12 => "aac+12",
        13 => "aac+13",
        14 => "aac+14",
        15 => "aac+15",
        16 => "aac+16",
        17 => "aac+17",
        18 => "aac+18",
        19 => "aac+19",
        20 => "aac+20",
        21 => "aac+21",
        22 => "aac+22",
        23 => "aac+23",
        24 => "aac+24",
        25 => "aac+25",
        26 => "aac+26",
        27 => "aac+27",
        28 => "aac+28",
        29 => "aac+29",
        30 => "aac+30",
        31 => "aac+31",
        _ => "aac+32",
    }
}

fn collect_aac_payload_candidates<'a>(payload: &'a [u8]) -> Vec<(&'a [u8], &'static str)> {
    let mut candidates: Vec<(&'a [u8], &'static str)> = Vec::new();

    // Keep ordering deterministic so logs remain stable between runs.
    if starts_with_adts_sync(payload) && payload.len() > 7 {
        candidates.push((&payload[7..], "aac-adts"));
    }
    if payload.len() > 11 && starts_with_adts_sync(&payload[4..]) {
        candidates.push((&payload[11..], "aac-adts+4"));
    }

    for offset in 0..=16 {
        if payload.len() < offset + 4 {
            continue;
        }
        let view = &payload[offset..];
        if let Some(au) = extract_aac_access_unit(view) {
            candidates.push((au, aac_au_label_for_offset(offset)));
        }
        if let Some(au) = extract_aac_access_unit_direct_header(view) {
            candidates.push((au, aac_au_direct_label_for_offset(offset)));
        }
    }

    for offset in 0..=32 {
        if payload.len() <= offset + 8 {
            continue;
        }
        candidates.push((&payload[offset..], aac_raw_label_for_offset(offset)));
    }

    // De-duplicate equivalent payload slices to avoid redundant decode attempts.
    let mut unique: Vec<(&'a [u8], &'static str)> = Vec::with_capacity(candidates.len());
    for (slice, label) in candidates {
        if slice.len() < 8 {
            continue;
        }
        if unique.iter().any(|(seen, _)| *seen == slice) {
            continue;
        }
        unique.push((slice, label));
    }

    unique
}

fn samples_peak_abs(samples: &[f32]) -> f32 {
    samples
        .iter()
        .map(|v| v.abs())
        .fold(0.0f32, |acc, v| if v > acc { v } else { acc })
}

struct AacProbeOutcome<'a> {
    chosen: Option<(&'a [u8], &'static str, usize, String, f32)>,
    candidate_count: usize,
    decoded_count: usize,
    non_silent_count: usize,
    best_peak: f32,
}

fn probe_aac_candidates<'a>(
    payload: &'a [u8],
    sample_rate: u32,
    channels: u8,
) -> AacProbeOutcome<'a> {
    let candidates = collect_aac_payload_candidates(payload);
    let candidate_count = candidates.len();
    let mut best_non_silent: Option<(&'a [u8], &'static str, usize, String, f32)> = None;
    let mut best_any: Option<(&'a [u8], &'static str, usize, String, f32)> = None;
    let mut decoded_count = 0usize;
    let mut non_silent_count = 0usize;
    let mut best_peak = 0.0f32;

    for (candidate, label) in candidates {
        let Ok(mut probe_decoder) = AacDecoder::new(sample_rate, channels) else {
            break;
        };

        let Ok(samples) = probe_decoder.decode(candidate) else {
            continue;
        };
        decoded_count += 1;

        if samples.is_empty() {
            continue;
        }

        let peak = samples_peak_abs(&samples);
        if peak > best_peak {
            best_peak = peak;
        }
        let record = (
            candidate,
            label,
            candidate.len(),
            prefix_hex(candidate, 16),
            peak,
        );

        if peak > 1.0e-7 {
            non_silent_count += 1;
            if best_non_silent
                .as_ref()
                .map(|(_, _, _, _, best_peak)| peak > *best_peak)
                .unwrap_or(true)
            {
                best_non_silent = Some(record);
            }
        } else if best_any
            .as_ref()
            .map(|(_, _, _, _, best_peak)| peak > *best_peak)
            .unwrap_or(true)
        {
            best_any = Some(record);
        }
    }

    AacProbeOutcome {
        chosen: best_non_silent.or(best_any),
        candidate_count,
        decoded_count,
        non_silent_count,
        best_peak,
    }
}

fn prefix_hex(payload: &[u8], max_len: usize) -> String {
    payload
        .iter()
        .take(max_len)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<String>>()
        .join("")
}

fn select_aac_payload<'a>(payload: &'a [u8]) -> (&'a [u8], &'static str) {
    // If payload already carries an ADTS frame, strip header and keep AAC raw data.
    if starts_with_adts_sync(payload) && payload.len() > 7 {
        return (&payload[7..], "aac-adts");
    }

    if payload.len() > 11 && starts_with_adts_sync(&payload[4..]) {
        return (&payload[11..], "aac-adts+4");
    }

    if let Some((au, label)) = extract_aac_access_unit_shifted(payload) {
        return (au, label);
    }

    if let Some(au) = extract_aac_access_unit_direct_header(payload) {
        return (au, "aac-au-direct");
    }

    (payload, "aac")
}

#[cfg(test)]
fn make_buffered_frame(samples: Vec<f32>) -> BufferedFrame {
    let (decoded_amp_min, decoded_amp_max) = amplitude_min_max(&samples);
    let (enqueue_amp_min, enqueue_amp_max) = amplitude_min_max(&samples);
    BufferedFrame {
        samples,
        ssrc: AudioSsrc::None,
        decoder_kind: "test",
        plaintext_len: 0,
        plaintext_nonzero_bytes: 0,
        plaintext_prefix_hex: String::new(),
        selected_payload_len: 0,
        selected_payload_prefix_hex: String::new(),
        decoded_amp_min,
        decoded_amp_max,
        enqueue_amp_min,
        enqueue_amp_max,
        aac_candidate_count: 0,
        aac_decoded_count: 0,
        aac_non_silent_count: 0,
        aac_best_peak: 0.0,
    }
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
    let mut decoder: Option<BufferedDecoder> = None;
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

            decoder = make_decoder(ssrc, src_sr, src_ch);
            if decoder.is_none() {
                warn!("Failed to create decoder for {:?}", ssrc);
                handler.on_error(&ShairplayError::Codec(CodecError::UnsupportedFormat(format!(
                    "decoder init failed (ssrc={ssrc:?}, sample_rate={src_sr}, channels={src_ch})"
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

        let (samples, decoder_kind, selected_payload_len, selected_payload_prefix_hex, aac_candidate_count, aac_decoded_count, aac_non_silent_count, aac_best_peak) = if let Some(dec) = &mut decoder {
            match dec {
                BufferedDecoder::Aac(dec) => {
                    let probe = probe_aac_candidates(
                        &plaintext,
                        current_ssrc.sample_rate(),
                        current_ssrc.channels(),
                    );

                    if let Some((samples, payload_kind, payload_len, payload_prefix, _selected_peak)) = probe.chosen {
                        match dec.decode(samples) {
                            Ok(decoded_samples) => Some((
                                decoded_samples,
                                payload_kind,
                                payload_len,
                                payload_prefix,
                                probe.candidate_count,
                                probe.decoded_count,
                                probe.non_silent_count,
                                probe.best_peak,
                            )),
                            Err(e) => {
                                debug!(error = %e, ssrc = ?current_ssrc, payload_kind, "AAC decode failed on selected probe candidate");
                                None
                            }
                        }
                    } else {
                        let (aac_payload, payload_kind) = select_aac_payload(&plaintext);
                        let payload_len = aac_payload.len();
                        let payload_prefix = prefix_hex(aac_payload, 16);
                        match dec.decode(aac_payload) {
                            Ok(samples) => Some(
                                (
                                    samples,
                                    payload_kind,
                                    payload_len,
                                    payload_prefix,
                                    probe.candidate_count,
                                    probe.decoded_count,
                                    probe.non_silent_count,
                                    probe.best_peak,
                                ),
                            ),
                            Err(e) => {
                                debug!(error = %e, ssrc = ?current_ssrc, payload_kind, "AAC decode failed");
                                None
                            }
                        }
                    }
                }
                BufferedDecoder::Alac(dec) => {
                    let decoded = dec.decode_frame_f32(&plaintext);
                    if decoded.is_none() {
                        debug!(ssrc = ?current_ssrc, "ALAC decode failed");
                    }
                    decoded.map(|samples| {
                        (
                            samples,
                            "alac",
                            plaintext.len(),
                            prefix_hex(&plaintext, 16),
                            0usize,
                            0usize,
                            0usize,
                            0.0f32,
                        )
                    })
                }
            }
        } else {
            None
        }
        .map_or((None, "none", 0usize, String::new(), 0usize, 0usize, 0usize, 0.0f32), |(samples, kind, payload_len, payload_prefix, candidate_count, decoded_count, non_silent_count, best_peak)| {
            (Some(samples), kind, payload_len, payload_prefix, candidate_count, decoded_count, non_silent_count, best_peak)
        });

        if let Some(samples) = samples {
            let (decoded_amp_min, decoded_amp_max) = amplitude_min_max(&samples);
            // Mix down + resample to the output format.
            let samples = crate::codec::resample::mixdown_and_resample(
                samples,
                source_channels,
                output_channels,
                &mut stream_resampler,
            );

            let (enqueue_amp_min, enqueue_amp_max) = amplitude_min_max(&samples);

            let (lock, cvar) = &*state;
            let mut s = lock.lock().unwrap();
            let plaintext_nonzero_bytes = plaintext.iter().filter(|&&b| b != 0).count();
            s.buffer.insert(
                timestamp,
                BufferedFrame {
                    samples,
                    ssrc: current_ssrc,
                    decoder_kind,
                    plaintext_len: plaintext.len(),
                    plaintext_nonzero_bytes,
                    plaintext_prefix_hex: prefix_hex(&plaintext, 16),
                    selected_payload_len,
                    selected_payload_prefix_hex,
                    decoded_amp_min,
                    decoded_amp_max,
                    enqueue_amp_min,
                    enqueue_amp_max,
                    aac_candidate_count,
                    aac_decoded_count,
                    aac_non_silent_count,
                    aac_best_peak,
                },
            );
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

        let ready: Vec<(u32, BufferedFrame)> = s
            .buffer
            .iter()
            .filter(|(ts, _)| (target_rtp.wrapping_sub(**ts) as i32) >= 0)
            .map(|(&ts, frame)| (ts, frame.clone()))
            .collect();

        for (ts, _) in &ready {
            s.buffer.remove(ts);
        }
        drop(s);

        if let Some(ref mut sess) = session {
            if do_flush {
                sess.audio_flush();
            }
            for (timestamp, frame) in &ready {
                let (process_amp_min, process_amp_max) = amplitude_min_max(&frame.samples);
                debug!(
                    timestamp,
                    ssrc = ?frame.ssrc,
                    decoder_kind = frame.decoder_kind,
                    sample_count = frame.samples.len(),
                    plaintext_len = frame.plaintext_len,
                    plaintext_nonzero_bytes = frame.plaintext_nonzero_bytes,
                    plaintext_prefix_hex = frame.plaintext_prefix_hex,
                    selected_payload_len = frame.selected_payload_len,
                    selected_payload_prefix_hex = frame.selected_payload_prefix_hex,
                    decoded_amp_min = frame.decoded_amp_min,
                    decoded_amp_max = frame.decoded_amp_max,
                    enqueue_amp_min = frame.enqueue_amp_min,
                    enqueue_amp_max = frame.enqueue_amp_max,
                    aac_candidate_count = frame.aac_candidate_count,
                    aac_decoded_count = frame.aac_decoded_count,
                    aac_non_silent_count = frame.aac_non_silent_count,
                    aac_best_peak = frame.aac_best_peak,
                    process_amp_min,
                    process_amp_max,
                    "AP2 buffered frame amplitudes decode/enqueue/process"
                );
                sess.audio_process(&frame.samples);
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
        s.buffer.insert(10_000, make_buffered_frame(vec![0.1; 4]));
        s.buffer.insert(20_000, make_buffered_frame(vec![0.2; 4]));

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
        s.buffer.insert(100, make_buffered_frame(vec![0.1]));
        s.buffer.insert(200, make_buffered_frame(vec![0.2]));
        s.buffer.insert(300, make_buffered_frame(vec![0.3]));

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
            s.buffer.insert(1, make_buffered_frame(vec![0.1, 0.2]));
            s.buffer.insert(2, make_buffered_frame(vec![0.3, 0.4]));
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
