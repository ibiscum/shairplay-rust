//! NTP timing responder for AirPlay legacy connections.
//!
//! Sends timing requests to the iPhone and responds to incoming
//! timing requests. Required for legacy (non-PTP) AirPlay connections.

/// Seconds between the NTP epoch (1900-01-01) and the UNIX epoch (1970-01-01).
const NTP_UNIX_EPOCH_OFFSET_SECS: u64 = 0x83AA_7E80; // 2_208_988_800

fn put_ntp(buf: &mut [u8], off: usize, secs: u32, frac: u32) {
    buf[off..off + 4].copy_from_slice(&secs.to_be_bytes());
    buf[off + 4..off + 8].copy_from_slice(&frac.to_be_bytes());
}

fn is_timing_request(buf: &[u8]) -> bool {
    buf.len() >= 32 && (buf[1] & 0x7f) == 0x52
}

fn build_timing_request(secs: u32, frac: u32) -> [u8; 32] {
    let mut req = [0u8; 32];
    req[0] = 0x80;
    req[1] = 0xd2;
    req[2] = 0x00;
    req[3] = 0x07;
    put_ntp(&mut req, 24, secs, frac);
    req
}

fn build_timing_response(request: &[u8], secs: u32, frac: u32) -> Option<[u8; 32]> {
    if !is_timing_request(request) {
        return None;
    }
    let mut resp = [0u8; 32];
    resp.copy_from_slice(&request[..32]);
    resp[1] = 0xd3;
    // Echo client's transmit timestamp as originate timestamp.
    resp[8..16].copy_from_slice(&request[24..32]);
    put_ntp(&mut resp, 16, secs, frac);
    put_ntp(&mut resp, 24, secs, frac);
    Some(resp)
}

fn sender_allowed(remote_timing: std::net::SocketAddr, sender: std::net::SocketAddr) -> bool {
    remote_timing.port() == 0 || sender.ip() == remote_timing.ip()
}

/// timing requests and sends periodic keepalives. Required for legacy AirPlay
/// connections where the iPhone expects NTP sync before streaming audio.
pub(crate) fn spawn_ntp_responder(
    tsock: tokio::net::UdpSocket,
    remote_timing: std::net::SocketAddr,
) {
    tokio::spawn(async move {
        let mut buf = [0u8; 128];

        let ntp_now = || {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let secs = (now.as_secs() + NTP_UNIX_EPOCH_OFFSET_SECS) as u32;
            let frac = ((now.subsec_nanos() as u64) << 32) / 1_000_000_000;
            (secs, frac as u32)
        };

        // Send initial timing requests to iPhone
        if remote_timing.port() > 0 {
            tracing::debug!(%remote_timing, "NTP: sending initial timing requests");
            for _ in 0..3 {
                let (s, f) = ntp_now();
                let req = build_timing_request(s, f);
                let _ = tsock.send_to(&req, remote_timing).await;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }

        loop {
            let timeout = tokio::time::sleep(std::time::Duration::from_secs(3));
            tokio::select! {
                result = tsock.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) if is_timing_request(&buf[..len]) => {
                            if !sender_allowed(remote_timing, addr) {
                                tracing::debug!(%addr, expected = %remote_timing, "NTP: ignoring timing request from unexpected peer");
                                continue;
                            }
                            let (s, f) = ntp_now();
                            if let Some(resp) = build_timing_response(&buf[..len], s, f) {
                                let _ = tsock.send_to(&resp, addr).await;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                _ = timeout => {
                    if remote_timing.port() > 0 {
                        let (s, f) = ntp_now();
                        let req = build_timing_request(s, f);
                        let _ = tsock.send_to(&req, remote_timing).await;
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_request_signature_requires_len_and_type() {
        let mut req = [0u8; 32];
        req[1] = 0x52;
        assert!(is_timing_request(&req));
        assert!(!is_timing_request(&req[..31]));
        req[1] = 0x51;
        assert!(!is_timing_request(&req));
    }

    #[test]
    fn build_timing_request_sets_header_and_transmit_timestamp() {
        let req = build_timing_request(0x1122_3344, 0x5566_7788);
        assert_eq!(req[0], 0x80);
        assert_eq!(req[1], 0xd2);
        assert_eq!(&req[24..28], &0x1122_3344u32.to_be_bytes());
        assert_eq!(&req[28..32], &0x5566_7788u32.to_be_bytes());
    }

    #[test]
    fn build_timing_response_echoes_and_stamps_fields() {
        let mut req = [0u8; 32];
        req[1] = 0x52;
        req[24..28].copy_from_slice(&0xAABB_CCDDu32.to_be_bytes());
        req[28..32].copy_from_slice(&0xEEFF_0011u32.to_be_bytes());

        let resp = build_timing_response(&req, 0x0102_0304, 0x0506_0708).unwrap();
        assert_eq!(resp[1], 0xd3);
        assert_eq!(&resp[8..12], &0xAABB_CCDDu32.to_be_bytes());
        assert_eq!(&resp[12..16], &0xEEFF_0011u32.to_be_bytes());
        assert_eq!(&resp[16..20], &0x0102_0304u32.to_be_bytes());
        assert_eq!(&resp[20..24], &0x0506_0708u32.to_be_bytes());
        assert_eq!(&resp[24..28], &0x0102_0304u32.to_be_bytes());
        assert_eq!(&resp[28..32], &0x0506_0708u32.to_be_bytes());
    }

    #[test]
    fn sender_allowed_requires_matching_ip_when_remote_known() {
        let remote: std::net::SocketAddr = "192.168.1.10:7010".parse().unwrap();
        let ok_same_ip: std::net::SocketAddr = "192.168.1.10:9000".parse().unwrap();
        let bad_other_ip: std::net::SocketAddr = "192.168.1.11:7010".parse().unwrap();
        assert!(sender_allowed(remote, ok_same_ip));
        assert!(!sender_allowed(remote, bad_other_ip));
    }

    #[test]
    fn sender_allowed_accepts_any_when_remote_port_unknown() {
        let remote: std::net::SocketAddr = "192.168.1.10:0".parse().unwrap();
        let sender: std::net::SocketAddr = "10.0.0.7:9000".parse().unwrap();
        assert!(sender_allowed(remote, sender));
    }
}
