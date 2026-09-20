//! HLS HTTP handlers — /play, /playback-info, /scrub, /rate, /stop, /server-info.

use super::handlers_ap1::RaopConnection;
use crate::proto::http::{HttpRequest, HttpResponse};

/// `GET /server-info` — server capabilities for HLS mode.
pub(crate) fn handle_server_info(
    conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let mac = conn
        .shared
        .hwaddr
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");

    let mut dict = plist::Dictionary::new();
    // Bits 0-6 + 9: video, photo, FairPlay DRM, volume, HLS, slideshow, unknown, audio
    dict.insert("features".into(), plist::Value::Integer(0x27F_i64.into()));
    dict.insert("macAddress".into(), plist::Value::String(mac.clone()));
    dict.insert(
        "model".into(),
        plist::Value::String(crate::raop::config::GLOBAL_MODEL.into()),
    );
    dict.insert(
        "osBuildVersion".into(),
        plist::Value::String("12B435".into()),
    );
    dict.insert("protovers".into(), plist::Value::String("1.0".into()));
    dict.insert(
        "srcvers".into(),
        plist::Value::String(crate::raop::config::AP2_SRCVERS.into()),
    );
    dict.insert("vv".into(), plist::Value::Integer(2_i64.into()));
    dict.insert("deviceid".into(), plist::Value::String(mac));

    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &plist::Value::Dictionary(dict)).ok()?;
    response.add_header("Content-Type", "text/x-apple-plist+xml");
    Some(buf)
}

/// `POST /play` — iPhone sends m3u8 URL to start HLS playback.
pub(crate) fn handle_play(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let data = request.data()?;
    let plist_val: plist::Value = plist::from_bytes(data).ok()?;
    let dict = plist_val.as_dictionary()?;

    let url = dict.get("Content-Location").and_then(|v| v.as_string())?;
    let start_pos = dict
        .get("Start-Position")
        .and_then(|v| v.as_real())
        .unwrap_or(0.0) as f32;

    let session_id = request.header("X-Apple-Session-ID").map(|s| s.to_string());

    tracing::info!(%url, start_pos, "HLS play request");

    let hls_handler = conn.shared.hls_handler.as_ref()?;
    let session = hls_handler.on_play(url, start_pos);

    if let Ok(mut state) = conn.hls_state.lock() {
        state.replace_session(session, session_id);
    }
    None
}

/// `GET /playback-info` — iPhone polls for playback state.
pub(crate) fn handle_playback_info(
    conn: &mut RaopConnection,
    _request: &HttpRequest,
    response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let state = conn.hls_state.lock().ok()?;
    let session = state.session.as_ref()?;

    let duration = session.duration() as f64;
    let position = session.position() as f64;
    let rate = session.rate() as f64;
    let ready = session.ready();
    let loaded_duration = (duration - position).max(0.0);

    let mut dict = plist::Dictionary::new();
    dict.insert("duration".into(), plist::Value::Real(duration));
    dict.insert("position".into(), plist::Value::Real(position));
    dict.insert("rate".into(), plist::Value::Real(rate));
    dict.insert(
        "readyToPlay".into(),
        plist::Value::Integer((ready as i64).into()),
    );
    dict.insert(
        "playbackBufferEmpty".into(),
        plist::Value::Integer(0_i64.into()),
    );
    dict.insert(
        "playbackBufferFull".into(),
        plist::Value::Integer(1_i64.into()),
    );
    dict.insert(
        "playbackLikelyToKeepUp".into(),
        plist::Value::Integer(1_i64.into()),
    );

    // loadedTimeRanges
    let mut loaded = plist::Dictionary::new();
    loaded.insert("start".into(), plist::Value::Real(position));
    loaded.insert("duration".into(), plist::Value::Real(loaded_duration));
    dict.insert(
        "loadedTimeRanges".into(),
        plist::Value::Array(vec![plist::Value::Dictionary(loaded)]),
    );

    // seekableTimeRanges
    let mut seekable = plist::Dictionary::new();
    seekable.insert("start".into(), plist::Value::Real(0.0));
    seekable.insert("duration".into(), plist::Value::Real(duration));
    dict.insert(
        "seekableTimeRanges".into(),
        plist::Value::Array(vec![plist::Value::Dictionary(seekable)]),
    );

    let mut buf = Vec::new();
    plist::to_writer_xml(&mut buf, &plist::Value::Dictionary(dict)).ok()?;
    response.add_header("Content-Type", "text/x-apple-plist+xml");
    Some(buf)
}

/// `POST /scrub?position=X` — seek to position.
pub(crate) fn handle_scrub(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let url = request.url()?;
    let pos = parse_query_float(url, "position")?;
    tracing::debug!(pos, "HLS scrub");
    if let Ok(mut state) = conn.hls_state.lock()
        && let Some(session) = state.session.as_mut()
    {
        session.seek(pos);
    }
    None
}

/// `POST /rate?value=X` — set playback rate (0=pause, 1=play).
pub(crate) fn handle_rate(
    conn: &mut RaopConnection,
    request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    let url = request.url()?;
    let rate = parse_query_float(url, "value")?;
    tracing::debug!(rate, "HLS rate");
    if let Ok(mut state) = conn.hls_state.lock()
        && let Some(session) = state.session.as_mut()
    {
        session.set_rate(rate);
    }
    None
}

/// `POST /stop` — stop HLS playback.
pub(crate) fn handle_stop(
    conn: &mut RaopConnection,
    _request: &HttpRequest,
    _response: &mut HttpResponse,
) -> Option<Vec<u8>> {
    tracing::info!("HLS stop");
    if let Ok(mut state) = conn.hls_state.lock() {
        state.clear_session();
    }
    None
}

/// Parse `?key=value` from a URL query string.
fn parse_query_float(url: &str, key: &str) -> Option<f32> {
    let query = url.split('?').nth(1)?;
    for param in query.split('&') {
        let Some((param_key, val)) = param.split_once('=') else {
            continue;
        };
        if param_key == key {
            let parsed = val.parse::<f32>().ok()?;
            if parsed.is_finite() {
                return Some(parsed);
            }
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use crate::crypto::pairing::Pairing;
    use crate::crypto::rsa::RsaKey;
    use crate::proto::http::{HttpRequest, HttpResponse};
    use crate::raop::connection::RaopShared;
    use crate::raop::hls::{HlsHandler, HlsSession, HlsState};
    use crate::raop::{AudioFormat, AudioHandler, AudioSession, MemoryPairingStore};

    #[derive(Default)]
    struct NoopAudioHandler;

    impl AudioHandler for NoopAudioHandler {
        fn audio_init(&self, _format: AudioFormat) -> Box<dyn AudioSession> {
            unreachable!("audio path is not used in HLS handler tests")
        }
    }

    #[derive(Debug, Clone, PartialEq, Default)]
    struct PlaybackState {
        duration: f32,
        position: f32,
        rate: f32,
        ready: bool,
        stop_calls: usize,
    }

    struct MockHlsSession {
        state: Arc<Mutex<PlaybackState>>,
    }

    impl HlsSession for MockHlsSession {
        fn duration(&self) -> f32 {
            self.state.lock().expect("playback state mutex poisoned").duration
        }

        fn position(&self) -> f32 {
            self.state.lock().expect("playback state mutex poisoned").position
        }

        fn rate(&self) -> f32 {
            self.state.lock().expect("playback state mutex poisoned").rate
        }

        fn ready(&self) -> bool {
            self.state.lock().expect("playback state mutex poisoned").ready
        }

        fn seek(&mut self, position: f32) {
            self.state
                .lock()
                .expect("playback state mutex poisoned")
                .position = position;
        }

        fn set_rate(&mut self, rate: f32) {
            self.state
                .lock()
                .expect("playback state mutex poisoned")
                .rate = rate;
        }

        fn stop(&mut self) {
            let mut state = self.state.lock().expect("playback state mutex poisoned");
            state.stop_calls += 1;
        }
    }

    #[derive(Default)]
    struct MockHlsHandler {
        play_calls: Mutex<Vec<(String, f32)>>,
        created: AtomicUsize,
        initial_state: PlaybackState,
    }

    impl HlsHandler for MockHlsHandler {
        fn on_play(&self, url: &str, start_position: f32) -> Box<dyn HlsSession> {
            self.play_calls
                .lock()
                .expect("play calls mutex poisoned")
                .push((url.to_string(), start_position));
            self.created.fetch_add(1, Ordering::SeqCst);
            Box::new(MockHlsSession {
                state: Arc::new(Mutex::new(self.initial_state.clone())),
            })
        }
    }

    fn test_connection(hls_handler: Option<Arc<dyn HlsHandler>>) -> RaopConnection {
        let hwaddr = vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        let shared = Arc::new(RaopShared {
            rsakey: Arc::new(RsaKey::from_pem(include_str!("../../airport.key")).unwrap()),
            pairing: Arc::new(Pairing::generate().unwrap()),
            hwaddr,
            password: String::new(),
            #[cfg(feature = "pipewire-auth-setup-compat")]
            pipewire_auth_setup_compat: false,
            handler: Arc::new(NoopAudioHandler),
            #[cfg(feature = "ap2")]
            pairing_store: Arc::new(MemoryPairingStore::default()),
            #[cfg(feature = "ap2")]
            identity_seed: [1u8; 32],
            output_sample_rate: None,
            output_max_channels: None,
            #[cfg(feature = "ap2")]
            pin: None,
            #[cfg(feature = "video")]
            video_handler: None,
            #[cfg(feature = "video")]
            video_ekey: Arc::new(std::sync::RwLock::new(None)),
            #[cfg(feature = "video")]
            video_eiv: Arc::new(std::sync::RwLock::new(None)),
            #[cfg(feature = "ap2")]
            pairing_id: "pairing-id".into(),
            #[cfg(feature = "ap2")]
            device_id: "10:20:30:40:50:60".into(),
            #[cfg(feature = "ap2")]
            airplay_name: "test-airplay".into(),
            #[cfg(feature = "ap2")]
            active_audio: Mutex::new(None),
            #[cfg(feature = "hls")]
            hls_handler,
        });

        RaopConnection {
            raop_rtp: None,
            fairplay: crate::crypto::fairplay::FairPlay::new(),
            pairing: shared.pairing.create_session(),
            local_addr: vec![127, 0, 0, 1],
            remote_addr: vec![127, 0, 0, 1],
            remote_socket: "127.0.0.1:7000".parse().unwrap(),
            nonce: String::new(),
            shared,
            #[cfg(feature = "ap2")]
            srp_server: None,
            #[cfg(feature = "ap2")]
            pair_verify: None,
            #[cfg(feature = "ap2")]
            ap2_shared_secret: None,
            #[cfg(feature = "ap2")]
            pair_verify_secret: None,
            #[cfg(feature = "ap2")]
            is_ap2: true,
            #[cfg(feature = "ap2")]
            playout_cmd: None,
            #[cfg(feature = "ap2")]
            event_sender: None,
            #[cfg(feature = "video")]
            ekey: None,
            #[cfg(feature = "video")]
            eiv: None,
            #[cfg(feature = "hls")]
            hls_state: HlsState::new(),
        }
    }

    fn request_with_body(method: &str, url: &str, body: &[u8], extra_headers: &str) -> HttpRequest {
        let mut req = HttpRequest::new();
        let head = format!(
            "{method} {url} RTSP/1.0\r\nCSeq: 1\r\n{extra_headers}Content-Length: {}\r\n\r\n",
            body.len()
        );
        let mut raw = head.into_bytes();
        raw.extend_from_slice(body);
        req.add_data(&raw).unwrap();
        req
    }

    fn request_no_body(method: &str, url: &str) -> HttpRequest {
        let mut req = HttpRequest::new();
        let raw = format!("{method} {url} RTSP/1.0\r\nCSeq: 1\r\n\r\n");
        req.add_data(raw.as_bytes()).unwrap();
        req
    }

    #[test]
    fn parse_query_float_basic() {
        assert_eq!(
            parse_query_float("/scrub?position=12.5", "position"),
            Some(12.5)
        );
        assert_eq!(parse_query_float("/rate?value=1.0", "value"), Some(1.0));
        assert_eq!(parse_query_float("/rate?value=0.0", "value"), Some(0.0));
    }

    #[test]
    fn parse_query_float_missing() {
        assert_eq!(parse_query_float("/scrub", "position"), None);
        assert_eq!(parse_query_float("/scrub?other=1", "position"), None);
    }

    #[test]
    fn parse_query_float_multiple_params() {
        assert_eq!(
            parse_query_float("/x?a=1&position=2.75&b=2", "position"),
            Some(2.75)
        );
    }

    #[test]
    fn parse_query_float_invalid() {
        assert_eq!(parse_query_float("/scrub?position=abc", "position"), None);
        assert_eq!(parse_query_float("/scrub?position=", "position"), None);
    }

    #[test]
    fn parse_query_float_rejects_non_finite() {
        assert_eq!(parse_query_float("/rate?value=NaN", "value"), None);
        assert_eq!(parse_query_float("/rate?value=inf", "value"), None);
        assert_eq!(parse_query_float("/rate?value=-inf", "value"), None);
    }

    #[test]
    fn parse_query_float_requires_exact_key_match() {
        assert_eq!(
            parse_query_float("/scrub?positionMs=1.5&position=2.0", "position"),
            Some(2.0)
        );
    }

    #[test]
    fn server_info_returns_plist_and_content_type() {
        let mut conn = test_connection(None);
        let req = request_no_body("GET", "/server-info");
        let mut resp = HttpResponse::new("RTSP/1.0", 200, "OK");

        let body = handle_server_info(&mut conn, &req, &mut resp).expect("server-info body");
        let text = String::from_utf8(body).expect("plist must be utf8 xml");

        assert!(
            text.contains("<key>macAddress</key>") && text.contains("10:20:30:40:50:60"),
            "plist should include MAC address"
        );
        assert!(text.contains("<key>srcvers</key>"));
        let wire = String::from_utf8(resp.get_data().to_vec()).expect("response is ascii");
        assert!(wire.contains("Content-Type: text/x-apple-plist+xml"));
    }

    #[test]
    fn play_installs_session_and_tracks_session_id() {
        let handler = Arc::new(MockHlsHandler {
            initial_state: PlaybackState {
                duration: 100.0,
                position: 1.25,
                rate: 1.0,
                ready: true,
                stop_calls: 0,
            },
            ..Default::default()
        });
        let mut conn = test_connection(Some(handler.clone()));

        let mut dict = plist::Dictionary::new();
        dict.insert(
            "Content-Location".into(),
            plist::Value::String("https://example.com/live.m3u8".into()),
        );
        dict.insert("Start-Position".into(), plist::Value::Real(2.5));
        let mut body = Vec::new();
        plist::to_writer_xml(&mut body, &plist::Value::Dictionary(dict)).unwrap();

        let req = request_with_body(
            "POST",
            "/play",
            &body,
            "X-Apple-Session-ID: sess-42\r\n",
        );
        let mut resp = HttpResponse::new("RTSP/1.0", 200, "OK");

        assert!(handle_play(&mut conn, &req, &mut resp).is_none());

        let calls = handler.play_calls.lock().expect("play calls mutex poisoned");
        assert_eq!(calls.as_slice(), &[("https://example.com/live.m3u8".into(), 2.5)]);
        drop(calls);

        let state = conn.hls_state.lock().expect("hls state mutex poisoned");
        assert!(state.session.is_some());
        assert_eq!(state.session_id.as_deref(), Some("sess-42"));
    }

    #[test]
    fn playback_info_scrub_rate_and_stop_follow_session_state() {
        let mut conn = test_connection(None);
        let state = Arc::new(Mutex::new(PlaybackState {
            duration: 120.0,
            position: 10.0,
            rate: 1.0,
            ready: false,
            stop_calls: 0,
        }));
        {
            let mut hls = conn.hls_state.lock().expect("hls state mutex poisoned");
            hls.replace_session(
                Box::new(MockHlsSession {
                    state: Arc::clone(&state),
                }),
                Some("demo".into()),
            );
        }

        let mut info_resp = HttpResponse::new("RTSP/1.0", 200, "OK");
        let info_req = request_no_body("GET", "/playback-info");
        let info_body = handle_playback_info(&mut conn, &info_req, &mut info_resp)
            .expect("playback-info should return body");
        let plist: plist::Value = plist::from_bytes(&info_body).expect("valid plist xml");
        let dict = plist.as_dictionary().expect("plist dictionary");

        assert_eq!(dict.get("duration").and_then(|v| v.as_real()), Some(120.0));
        assert_eq!(dict.get("position").and_then(|v| v.as_real()), Some(10.0));
        assert_eq!(dict.get("rate").and_then(|v| v.as_real()), Some(1.0));
        assert_eq!(
            dict.get("readyToPlay")
                .and_then(|v| v.as_signed_integer()),
            Some(0)
        );

        let scrub_req = request_no_body("POST", "/scrub?position=33.5");
        let mut scrub_resp = HttpResponse::new("RTSP/1.0", 200, "OK");
        assert!(handle_scrub(&mut conn, &scrub_req, &mut scrub_resp).is_none());

        let rate_req = request_no_body("POST", "/rate?value=0.0");
        let mut rate_resp = HttpResponse::new("RTSP/1.0", 200, "OK");
        assert!(handle_rate(&mut conn, &rate_req, &mut rate_resp).is_none());

        {
            let current = state.lock().expect("playback state mutex poisoned");
            assert_eq!(current.position, 33.5);
            assert_eq!(current.rate, 0.0);
            assert_eq!(current.stop_calls, 0);
        }

        let stop_req = request_no_body("POST", "/stop");
        let mut stop_resp = HttpResponse::new("RTSP/1.0", 200, "OK");
        assert!(handle_stop(&mut conn, &stop_req, &mut stop_resp).is_none());

        {
            let current = state.lock().expect("playback state mutex poisoned");
            assert_eq!(current.stop_calls, 1);
        }
        let hls = conn.hls_state.lock().expect("hls state mutex poisoned");
        assert!(hls.session.is_none());
        assert!(hls.session_id.is_none());
    }
}
