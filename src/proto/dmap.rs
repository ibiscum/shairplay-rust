//! DMAP (Digital Media Access Protocol) parser.
//!
//! Parses the binary TLV format used by AirPlay for track metadata.
//! Format: 4-byte ASCII tag + 4-byte BE length + data.

/// Parsed track metadata from DMAP.
#[derive(Debug, Clone, Default)]
pub struct TrackMetadata {
    /// Track title (`minm`).
    pub title: Option<String>,
    /// Artist name (`asar`).
    pub artist: Option<String>,
    /// Album name (`asal`).
    pub album: Option<String>,
    /// Genre (`asgn`).
    pub genre: Option<String>,
    /// Duration in milliseconds (`astm`).
    pub duration_ms: Option<u32>,
    /// Track number (`astn`).
    pub track_number: Option<u16>,
    /// Disc number (`asdk`).
    pub disc_number: Option<u16>,
}

impl TrackMetadata {
    /// Parse DMAP binary data into structured metadata.
    pub(crate) fn from_dmap(data: &[u8]) -> Self {
        let mut meta = Self::default();
        if data.len() < 8 || &data[..4] != b"mlit" {
            return meta;
        }

        let declared_len = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
        let Some(declared_end) = 8usize.checked_add(declared_len) else {
            return meta;
        };
        // Parse only the declared mlit payload, but tolerate truncated frames.
        let end = declared_end.min(data.len());

        let mut pos: usize = 8;
        while let Some(header_end) = pos.checked_add(8) {
            if header_end > end {
                break;
            }
            let tag = &data[pos..pos + 4];
            let len = u32::from_be_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
            pos += 8;
            let Some(value_end) = pos.checked_add(len) else {
                break;
            };
            if value_end > end {
                break;
            }
            let chunk = &data[pos..value_end];
            let as_str = || std::str::from_utf8(chunk).ok().map(String::from);
            let as_u32 = || chunk.try_into().ok().map(u32::from_be_bytes);
            let as_u16 = || chunk.try_into().ok().map(u16::from_be_bytes);
            match tag {
                b"minm" => {
                    if let Some(v) = as_str() {
                        meta.title = Some(v);
                    }
                }
                b"asar" => {
                    if let Some(v) = as_str() {
                        meta.artist = Some(v);
                    }
                }
                b"asal" => {
                    if let Some(v) = as_str() {
                        meta.album = Some(v);
                    }
                }
                b"asgn" => {
                    if let Some(v) = as_str() {
                        meta.genre = Some(v);
                    }
                }
                b"astm" => {
                    if let Some(v) = as_u32() {
                        meta.duration_ms = Some(v);
                    }
                }
                b"astn" => {
                    if let Some(v) = as_u16() {
                        meta.track_number = Some(v);
                    }
                }
                b"asdk" => {
                    if let Some(v) = as_u16() {
                        meta.disc_number = Some(v);
                    }
                }
                _ => {
                    tracing::trace!(tag = %String::from_utf8_lossy(tag), len, "DMAP: unknown tag");
                }
            }
            pos = value_end;
        }
        tracing::debug!(?meta, "Track metadata parsed");
        meta
    }
}

#[cfg(test)]
mod tests {
    use super::TrackMetadata;

    const DMAP_FULL: &[u8] = &[
        0x6d, 0x6c, 0x69, 0x74, 0x00, 0x00, 0x00, 0x57, 0x6d, 0x69, 0x6b, 0x64, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x6d, 0x69, 0x6e, 0x6d, 0x00, 0x00, 0x00, 0x11, 0x42, 0x6f, 0x68, 0x65, 0x6d,
        0x69, 0x61, 0x6e, 0x20, 0x52, 0x68, 0x61, 0x70, 0x73, 0x6f, 0x64, 0x79, 0x61, 0x73, 0x61,
        0x72, 0x00, 0x00, 0x00, 0x05, 0x51, 0x75, 0x65, 0x65, 0x6e, 0x61, 0x73, 0x61, 0x6c, 0x00,
        0x00, 0x00, 0x14, 0x41, 0x20, 0x4e, 0x69, 0x67, 0x68, 0x74, 0x20, 0x61, 0x74, 0x20, 0x74,
        0x68, 0x65, 0x20, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x61, 0x73, 0x67, 0x6e, 0x00, 0x00, 0x00,
        0x04, 0x52, 0x6f, 0x63, 0x6b,
    ];

    #[test]
    fn dmap_parse_full() {
        let meta = TrackMetadata::from_dmap(DMAP_FULL);
        assert_eq!(meta.title.as_deref(), Some("Bohemian Rhapsody"));
        assert_eq!(meta.artist.as_deref(), Some("Queen"));
        assert_eq!(meta.album.as_deref(), Some("A Night at the Opera"));
        assert_eq!(meta.genre.as_deref(), Some("Rock"));
    }

    #[test]
    fn dmap_parse_title_only() {
        let data: &[u8] = &[
            0x6d, 0x6c, 0x69, 0x74, 0x00, 0x00, 0x00, 0x0d, 0x6d, 0x69, 0x6e, 0x6d, 0x00, 0x00,
            0x00, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
        ];
        let meta = TrackMetadata::from_dmap(data);
        assert_eq!(meta.title.as_deref(), Some("Hello"));
        assert_eq!(meta.artist, None);
    }

    #[test]
    fn dmap_parse_empty() {
        let meta = TrackMetadata::from_dmap(&[]);
        assert_eq!(meta.title, None);
    }

    #[test]
    fn dmap_parse_truncated() {
        let meta = TrackMetadata::from_dmap(&DMAP_FULL[..8]);
        assert_eq!(meta.title, None);
    }

    #[test]
    fn dmap_parse_corrupt_length() {
        let data: &[u8] = &[
            0x6d, 0x6c, 0x69, 0x74, 0x00, 0x00, 0x00, 0x0d, 0x6d, 0x69, 0x6e, 0x6d, 0x00, 0x00,
            0xff, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
        ];
        let meta = TrackMetadata::from_dmap(data);
        assert_eq!(meta.title, None);
    }

    #[test]
    fn dmap_rejects_non_mlit_root() {
        let data: &[u8] = &[
            0x6e, 0x6f, 0x70, 0x65, 0x00, 0x00, 0x00, 0x0d, 0x6d, 0x69, 0x6e, 0x6d, 0x00, 0x00,
            0x00, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
        ];
        let meta = TrackMetadata::from_dmap(data);
        assert_eq!(meta.title, None);
    }

    #[test]
    fn dmap_respects_declared_outer_length() {
        let data: &[u8] = &[
            // mlit length = 13 bytes (one minm chunk)
            0x6d, 0x6c, 0x69, 0x74, 0x00, 0x00, 0x00, 0x0d,
            // minm = "Hello"
            0x6d, 0x69, 0x6e, 0x6d, 0x00, 0x00, 0x00, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
            // Extra bytes beyond declared mlit payload must be ignored.
            0x6d, 0x69, 0x6e, 0x6d, 0x00, 0x00, 0x00, 0x05, 0x57, 0x6f, 0x72, 0x6c, 0x64,
        ];
        let meta = TrackMetadata::from_dmap(data);
        assert_eq!(meta.title.as_deref(), Some("Hello"));
    }

    #[test]
    fn dmap_malformed_duplicate_does_not_clear_prior_value() {
        let data: &[u8] = &[
            // mlit length = 23 bytes
            0x6d, 0x6c, 0x69, 0x74, 0x00, 0x00, 0x00, 0x17,
            // astm (u32) = 1000
            0x61, 0x73, 0x74, 0x6d, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x03, 0xE8,
            // malformed astm length (3 bytes)
            0x61, 0x73, 0x74, 0x6d, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03,
        ];
        let meta = TrackMetadata::from_dmap(data);
        assert_eq!(meta.duration_ms, Some(1000));
    }
}
