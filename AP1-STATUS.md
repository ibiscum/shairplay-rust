# AirPlay 1 (Classic RAOP) — Implementation Status & Parity

## Complete

| Feature | Status | Details |
|---------|--------|---------|
| mDNS discovery | ✅ Implemented | `_raop._tcp` plus `_airplay._tcp` advertisement for classic mode. |
| AP1 capability advertisement (`cn`, `et`) | ✅ Implemented | Default `cn=0,1` (PCM + ALAC), `et=0` (unencrypted), configurable via builder APIs. |
| RTSP control flow | ✅ Implemented | `OPTIONS`, `ANNOUNCE`, `SETUP`, `RECORD`, `SET_PARAMETER`, `GET_PARAMETER`, `FLUSH`, `TEARDOWN`. |
| Audio codecs | ✅ Implemented | ALAC (`AppleLossless`) and PCM (`L16`) decode to f32 interleaved output. |
| AP1 transport modes | ✅ Implemented | UDP (data/control/timing sockets) and TCP interleaved RTP. |
| AP1 encryption modes | ✅ Implemented | Plain RTP (`et=0`), RSA key exchange (`et=1`), FairPlay (`et=3` + `fp-setup`). |
| RTP retransmit handling | ✅ Implemented | Handles control-channel retransmit packets (PT `0x56`) in UDP mode. |
| Classic timing | ✅ Implemented | Per-session NTP responder is spawned for AP1 timing sync. |
| Metadata and artwork | ✅ Implemented | DMAP metadata, cover art, volume, and progress are forwarded through handler callbacks. |
| DACP remote control | ✅ Implemented | Discover `_dacp._tcp` and issue play/pause/next/prev/stop/volume/shuffle/repeat commands. |
| Digest authentication | ✅ Implemented | Password-protected RTSP Digest flow via builder `.password()`. |

## Parity Comparison vs `mikebrady/shairport-sync` (AP1-relevant scope)

Reference compared: `https://github.com/mikebrady/shairport-sync`

Scope note: this table compares classic AirPlay receiver behavior relevant to
this library's domain (protocol, decode, timing, metadata, control). System
service packaging and audio-daemon-specific integrations are listed separately.

| Capability Area | `shairplay-rust` AP1 | Parity vs shairport-sync |
|---|---|---|
| Classic RAOP receiver (audio-only AP1) | ✅ | ✅ Parity for core receiver role |
| ALAC decode path | ✅ | ✅ |
| PCM (`L16`) decode path | ✅ | ✅ |
| RTP over UDP | ✅ | ✅ |
| RTP over TCP interleaved | ✅ | ✅ |
| RTP retransmit handling (UDP control channel) | ✅ | ✅ |
| Classic NTP-style timing participation | ✅ | ✅ |
| Metadata forwarding (track/progress/artwork) | ✅ | ✅ |
| DACP remote-control callbacks | ✅ | ✅ |
| Digest password authentication | ✅ | ✅ |
| AP1 encryption negotiation (`et=0/1/3`) | ✅ | ✅ |
| MFi-SAP `/auth-setup` (`et=4`) | ⚠️ Partial/compat-only | ❌ Not parity (no conformant MFi implementation) |
| Built-in audio backends (ALSA/PipeWire/Pulse/etc.) | ❌ (library callback model) | ❌ Different architecture |
| MQTT / D-Bus / MPRIS service interfaces | ❌ | ❌ |
| Built-in DSP/loudness toolchain | ❌ | ❌ |
| Video/photos receiver support in AP1 context | ❌ (AP1 scope here is audio) | ✅ Intentional match for shairport-sync audio focus |

Legend: ✅ implemented, ⚠️ partial or compatibility-only, ❌ missing.

## `/auth-setup` in AP1 Context

Conformant MFi-SAP (`et=4`) is not implemented. AP1 intentionally advertises
`et` values from `0`, `1`, and `3` only. An optional compatibility mode exists
for one bounded PipeWire probe, but it is not receiver authentication and does
not provide MFi security properties.

See the dedicated protocol evidence and constraints in
`docs/protocol/auth-setup.md`.

## Open / Non-Goals vs shairport-sync

- System-daemon integrations (MQTT, D-Bus, MPRIS) are not built into this
  crate; applications can layer their own control plane around `AudioHandler`.
- Audio backend matrix (ALSA/PipeWire/PulseAudio/sndio/libao/stdout) is not a
  crate concern; this project provides decoded f32 PCM via callbacks.
- Conformant MFi-SAP (`et=4`) remains open work; compatibility probing does not
  count as protocol parity.

## Verification Anchors

- AP1 capability advertisement and defaults: `src/raop/config.rs`,
  `src/net/mdns.rs`, `src/raop/server.rs`
- AP1 RTSP handlers and encryption negotiation: `src/raop/handlers_ap1.rs`
- AP1 RTP transport, retransmit, and timing responder: `src/raop/rtp.rs`
- DACP implementation: `src/dacp/mod.rs`
- API and status claims: `README.md`
