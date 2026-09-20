//! HLS (HTTP Live Streaming) handler traits and playback state.
//!
//! The iPhone sends an m3u8 URL via `/play`. The application is responsible
//! for fetching and playing the stream. The library relays playback state
//! (position, duration, rate) back to the iPhone via `/playback-info`.

use std::sync::{Arc, Mutex};

/// Factory for HLS playback sessions.
pub trait HlsHandler: Send + Sync {
    /// Called when the iPhone sends a `/play` request with an HLS URL.
    /// The application should start playing the stream and return a session
    /// handle for state queries.
    fn on_play(&self, url: &str, start_position: f32) -> Box<dyn HlsSession>;
}

/// A live HLS playback session. The library polls this to respond to
/// `/playback-info` requests from the iPhone.
pub trait HlsSession: Send {
    /// Total duration in seconds (0.0 if unknown/live).
    fn duration(&self) -> f32;
    /// Current playback position in seconds.
    fn position(&self) -> f32;
    /// Playback rate: 0.0 = paused, 1.0 = normal.
    fn rate(&self) -> f32;
    /// Whether the player is ready to play.
    fn ready(&self) -> bool {
        true
    }
    /// Seek to a position in seconds.
    fn seek(&mut self, position: f32);
    /// Set playback rate (0.0 = pause, 1.0 = play).
    fn set_rate(&mut self, rate: f32);
    /// Stop playback.
    fn stop(&mut self);
}

/// Shared HLS state accessible from RTSP handlers.
pub(crate) struct HlsState {
    pub(crate) session: Option<Box<dyn HlsSession>>,
    pub(crate) session_id: Option<String>,
}

impl HlsState {
    pub(crate) fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            session: None,
            session_id: None,
        }))
    }

    /// Install a new playback session, stopping any existing one first.
    pub(crate) fn replace_session(
        &mut self,
        session: Box<dyn HlsSession>,
        session_id: Option<String>,
    ) {
        if let Some(mut current) = self.session.take() {
            current.stop();
        }
        self.session = Some(session);
        self.session_id = session_id;
    }

    /// Stop and remove the active playback session, if any.
    pub(crate) fn clear_session(&mut self) {
        if let Some(mut current) = self.session.take() {
            current.stop();
        }
        self.session_id = None;
    }
}

impl Drop for HlsState {
    fn drop(&mut self) {
        self.clear_session();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockSession {
        pos: f32,
        rate: f32,
        stopped: bool,
        stop_count: Arc<AtomicUsize>,
    }

    impl HlsSession for MockSession {
        fn duration(&self) -> f32 {
            120.0
        }
        fn position(&self) -> f32 {
            self.pos
        }
        fn rate(&self) -> f32 {
            self.rate
        }
        fn seek(&mut self, position: f32) {
            self.pos = position;
        }
        fn set_rate(&mut self, rate: f32) {
            self.rate = rate;
        }
        fn stop(&mut self) {
            self.stopped = true;
            self.rate = 0.0;
            self.stop_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn mock_session(stop_count: Arc<AtomicUsize>) -> Box<dyn HlsSession> {
        Box::new(MockSession {
            pos: 0.0,
            rate: 1.0,
            stopped: false,
            stop_count,
        })
    }

    #[test]
    fn hls_state_lifecycle() {
        let state = HlsState::new();
        let stop_count = Arc::new(AtomicUsize::new(0));
        {
            let s = state.lock().unwrap();
            assert!(s.session.is_none());
        }

        // Simulate /play
        {
            let mut s = state.lock().unwrap();
            s.replace_session(mock_session(stop_count.clone()), Some("test-123".into()));
        }

        // Simulate /playback-info poll
        {
            let s = state.lock().unwrap();
            let session = s.session.as_ref().unwrap();
            assert_eq!(session.duration(), 120.0);
            assert_eq!(session.rate(), 1.0);
        }

        // Simulate /scrub
        {
            let mut s = state.lock().unwrap();
            s.session.as_mut().unwrap().seek(60.0);
            assert_eq!(s.session.as_ref().unwrap().position(), 60.0);
        }

        // Simulate /rate?value=0 (pause)
        {
            let mut s = state.lock().unwrap();
            s.session.as_mut().unwrap().set_rate(0.0);
            assert_eq!(s.session.as_ref().unwrap().rate(), 0.0);
        }

        // Simulate /stop
        {
            let mut s = state.lock().unwrap();
            s.clear_session();
        }

        let s = state.lock().unwrap();
        assert!(s.session.is_none());
        assert_eq!(s.session_id, None);
        assert_eq!(stop_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn replace_session_stops_previous() {
        let state = HlsState::new();
        let stop_count = Arc::new(AtomicUsize::new(0));

        {
            let mut s = state.lock().unwrap();
            s.replace_session(mock_session(stop_count.clone()), Some("first".into()));
            s.replace_session(mock_session(stop_count.clone()), Some("second".into()));
            assert_eq!(s.session_id.as_deref(), Some("second"));
        }

        assert_eq!(stop_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dropping_state_stops_active_session() {
        let stop_count = Arc::new(AtomicUsize::new(0));
        let mut state = HlsState {
            session: Some(mock_session(stop_count.clone())),
            session_id: Some("drop-test".into()),
        };

        state.replace_session(mock_session(stop_count.clone()), Some("updated".into()));
        assert_eq!(stop_count.load(Ordering::Relaxed), 1);

        drop(state);
        assert_eq!(stop_count.load(Ordering::Relaxed), 2);
    }
}
