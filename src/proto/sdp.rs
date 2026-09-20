//! RAOP-specific SDP parser. Extracts fields needed for AirPlay audio streaming.
//! Equivalent to sdp.c.
/// Parsed SDP session description with fields needed for AirPlay audio setup.
pub struct Sdp {
    version: Option<String>,
    connection: Option<String>,
    rtpmap: Option<String>,
    fmtp: Option<String>,
    rsaaeskey: Option<String>,
    fpaeskey: Option<String>,
    aesiv: Option<String>,
    min_latency: Option<String>,
}

impl Sdp {
    /// Parse SDP data. Equivalent to sdp_init + parse_sdp_data.
    pub fn parse(data: &str) -> Self {
        let mut sdp = Self {
            version: None,
            connection: None,
            rtpmap: None,
            fmtp: None,
            rsaaeskey: None,
            fpaeskey: None,
            aesiv: None,
            min_latency: None,
        };

        for line in data.lines() {
            let line = line.trim_end_matches('\r').trim();
            if line.len() < 2 || line.as_bytes()[1] != b'=' {
                continue;
            }
            let value = line[2..].trim();
            match line.as_bytes()[0] {
                b'v' if sdp.version.is_none() && !value.is_empty() => {
                    sdp.version = Some(value.to_string());
                }
                b'c' if sdp.connection.is_none() && !value.is_empty() => {
                    sdp.connection = Some(value.to_string());
                }
                b'a' => {
                    if let Some((key, val)) = value.split_once(':') {
                        let key = key.trim();
                        let val = val.trim();
                        if val.is_empty() {
                            continue;
                        }
                        match key {
                            "rtpmap" if sdp.rtpmap.is_none() => {
                                sdp.rtpmap = Some(val.to_string());
                            }
                            "fmtp" if sdp.fmtp.is_none() => {
                                sdp.fmtp = Some(val.to_string());
                            }
                            "rsaaeskey" if sdp.rsaaeskey.is_none() => {
                                sdp.rsaaeskey = Some(val.to_string());
                            }
                            "fpaeskey" if sdp.fpaeskey.is_none() => {
                                sdp.fpaeskey = Some(val.to_string());
                            }
                            "aesiv" if sdp.aesiv.is_none() => {
                                sdp.aesiv = Some(val.to_string());
                            }
                            "min-latency" if sdp.min_latency.is_none() => {
                                sdp.min_latency = Some(val.to_string());
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        sdp
    }

    /// SDP version (v=).
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
    /// Connection address (c=). Used to determine IPv4/IPv6.
    pub fn connection(&self) -> Option<&str> {
        self.connection.as_deref()
    }
    /// RTP map (a=rtpmap).
    pub fn rtpmap(&self) -> Option<&str> {
        self.rtpmap.as_deref()
    }
    /// Format parameters (a=fmtp). Contains ALAC config.
    pub fn fmtp(&self) -> Option<&str> {
        self.fmtp.as_deref()
    }
    /// RSA-encrypted AES key (a=rsaaeskey).
    pub fn rsaaeskey(&self) -> Option<&str> {
        self.rsaaeskey.as_deref()
    }
    /// FairPlay-encrypted AES key (a=fpaeskey).
    pub fn fpaeskey(&self) -> Option<&str> {
        self.fpaeskey.as_deref()
    }
    /// AES initialization vector (a=aesiv).
    pub fn aesiv(&self) -> Option<&str> {
        self.aesiv.as_deref()
    }
    /// Minimum latency (a=min-latency).
    pub fn min_latency(&self) -> Option<&str> {
        self.min_latency.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::Sdp;

    #[test]
    fn parses_core_fields_with_whitespace_and_crlf() {
        let sdp = Sdp::parse(
            "\r\n  v=0\r\n  c=IN IP4 192.168.1.2\r\n  a=rtpmap: 96 AppleLossless \r\n  a=fmtp: 96 4096 0 16 40 10 14 2 255 0 0 44100\r\n",
        );
        assert_eq!(sdp.version(), Some("0"));
        assert_eq!(sdp.connection(), Some("IN IP4 192.168.1.2"));
        assert_eq!(sdp.rtpmap(), Some("96 AppleLossless"));
        assert_eq!(sdp.fmtp(), Some("96 4096 0 16 40 10 14 2 255 0 0 44100"));
    }

    #[test]
    fn duplicate_sensitive_fields_use_first_value() {
        let sdp = Sdp::parse(
            "a=rsaaeskey:first\n\
             a=rsaaeskey:second\n\
             a=fpaeskey:fp-first\n\
             a=fpaeskey:fp-second\n\
             a=aesiv:iv-first\n\
             a=aesiv:iv-second\n\
             a=min-latency:11025\n\
             a=min-latency:22050\n",
        );
        assert_eq!(sdp.rsaaeskey(), Some("first"));
        assert_eq!(sdp.fpaeskey(), Some("fp-first"));
        assert_eq!(sdp.aesiv(), Some("iv-first"));
        assert_eq!(sdp.min_latency(), Some("11025"));
    }

    #[test]
    fn empty_attribute_values_are_ignored() {
        let sdp = Sdp::parse("a=rsaaeskey:\na=fpaeskey:   \na=aesiv:\na=min-latency:\n");
        assert_eq!(sdp.rsaaeskey(), None);
        assert_eq!(sdp.fpaeskey(), None);
        assert_eq!(sdp.aesiv(), None);
        assert_eq!(sdp.min_latency(), None);
    }
}
