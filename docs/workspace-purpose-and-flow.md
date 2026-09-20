# Workspace Purpose and Flow

This workspace contains the shairplay-rust codebase: a pure Rust AirPlay receiver library that supports classic AirPlay (AP1) and AirPlay 2 (AP2), including audio and optional video/HLS feature paths.

## Purpose

Primary goals of this repository:

- Provide a clean-room AirPlay receiver implementation in safe Rust.
- Expose a library-first API so applications can embed AirPlay receive capabilities.
- Support AP1 and AP2 protocol paths with shared output as f32 interleaved PCM.
- Keep protocol, crypto, codec, transport, and app-facing APIs modular and testable.

## Workspace Layout

Top-level areas and why they exist:

- src/: Core library code.
- docs/: Protocol notes, release process, and implementation status references.
- tests/: Integration and unit coverage for end-to-end protocol behavior and core primitives.
- examples/: Runnable sample applications (for example, local audio output player).
- fuzz/: Fuzz targets for parser and transport robustness.
- scripts/: Release verification and repo guardrail scripts.

Key source modules under src/:

- lib.rs: Public API exports and crate-level docs.
- raop/: AirPlay server lifecycle, RTSP handlers, RTP stream handling, AP1/AP2 connection logic.
- net/: TCP/HTTP server plumbing, mDNS registration, and protocol diagnostics.
- proto/: HTTP/RTSP parsing, SDP, Digest auth, and protocol data formats.
- crypto/: RSA, pairing, FairPlay-related cryptography, transport ciphers, and TLV utilities.
- codec/: ALAC/AAC decode and optional resample support.
- error.rs: Error types mapped across protocol and server layers.

## Runtime Flow (High-Level)

Typical startup and stream lifecycle:

1. Application builds a RaopServer through RaopServer::builder() and provides an AudioHandler.
2. Server starts listeners and publishes discovery records (AirPlay/RAOP mDNS).
3. Sender discovers receiver and opens RTSP control connection.
4. Handlers negotiate authentication and session setup (AP1/AP2-specific path).
5. Stream transport starts:
	- AP1: classic RTP (ALAC/L16, optional encryption).
	- AP2: buffered/realtime channels with AP2 crypto and timing behavior.
6. Audio is decoded and converted to library output format (f32 interleaved PCM).
7. AudioHandler::audio_init creates a session; AudioSession::audio_process receives sample frames.
8. Teardown/flush/metadata/control events flow through the same RAOP connection state.

## AP1 and AP2 Path Split

- AP1 mode focuses on classic RAOP negotiation and transport formats.
- AP2 mode adds pairing, encrypted RTSP transport, buffered audio behavior, and AP2 state.
- Both paths converge to the same application-facing audio callback model.

## Developer Workflow

Expected day-to-day flow in this workspace:

1. Implement or modify code in src/.
2. Add or update tests in tests/ (and module tests where appropriate).
3. Run cargo test to validate behavior.
4. Run targeted example(s) when changing integration behavior (for example examples/player).
5. Update docs/ and status notes when protocol behavior or feature support changes.

## Testing and Quality Structure

Quality is enforced through multiple layers:

- Unit tests for low-level protocol, crypto, and codec behavior.
- Integration tests for server/session and protocol interaction behavior.
- Fuzz targets for parser and transport hardening.
- CI/release scripts and policy configuration for dependency and release checks.

## How to Read the Codebase Quickly

Suggested entry sequence for new contributors:

1. Read src/lib.rs for exported API surface.
2. Read src/raop/server.rs and src/raop/connection.rs for lifecycle and session control.
3. Read src/raop/handlers_ap1.rs and src/raop/handlers_ap2.rs for protocol branching.
4. Read src/net/server.rs and src/proto/http.rs for request parsing and dispatch details.
5. Read tests/integration.rs to see validated real-world interaction patterns.

## Scope Boundaries

- This repository is a receiver library, not a standalone product UI.
- Consumer applications are responsible for final audio/video rendering, UX, and persistent app state.
- AP2/video behavior evolves behind feature flags; status details are tracked in AP2-STATUS.md and docs/protocol/.
