# ADR 0004 — LiveKit as SFU, media handled in the Rust core

- Status: accepted
- Date: 2026-11-13

## Context

Tavern needs voice, webcam and 1080p60 screen sharing for calls of up to a few dozen people, end-to-end encrypted, on a self-hosted instance. The client runs in system webviews, and WebKitGTK on Linux has no reliable WebRTC. The RAM budget for a client sharing its screen is 300 MB.

Verified on 2026-11-13 against the sources of `livekit/rust-sdks`:

- `livekit` 0.10.1, `libwebrtc` 0.4.0, `webrtc-sys` 0.3.53, Apache-2.0; LiveKit server v1.13.11.
- E2EE is available in the Rust SDK: `E2eeOptions`, a `KeyProvider` with per-participant keys (`set_key(identity, key_index, key)`), a ring of 16 key indices, and a choice of internal key derivation (PBKDF2 by default, or HKDF). Data channel packets are encrypted with AES-GCM from the same key provider.
- `libwebrtc` exposes a `DesktopCapturer` for screens and windows (ScreenCaptureKit picker on macOS).
- Hardware encoders wired into the encoder factory: VideoToolbox (macOS), NVENC and VAAPI (Linux), Jetson. On Windows only NVENC was found; there is no QuickSync or AMF path. Pre-encoded frames can be published through `NativeVideoSource::new_encoded`.
- `webrtc-sys` downloads a prebuilt libwebrtc at build time.

## Decision

- **LiveKit server**, self-hosted in the reference Docker Compose, is the SFU and the TURN server. No transcoding.
- **The LiveKit Rust SDK runs inside `client-core`.** The webview's WebRTC stack is never used.
- **E2EE keys come from MLS.** For each participant and each MLS epoch of the group bound to the call:
  `key = MLS-Exporter(label = "tavern media v1", context = participant identity, length = 32)`.
  The key is pushed with `KeyProvider::set_key(identity, key_index = epoch mod 16, key)` on every epoch change. The LiveKit participant identity is the device id.
- **LiveKit's internal derivation is set to HKDF.** LiveKit derives the frame encryption key from the provided key material and the ratchet salt; automatic ratcheting inside LiveKit is not relied upon, since rotation is driven by MLS epochs. The exact derivation parameters and frame format are to be documented from `frame_cryptor` at M6.
- **A voice channel has its own MLS group** whose members are the devices currently connected to it, so every arrival and departure creates an epoch and a new media key. A DM or group call reuses the conversation's group.
- **Screen and window capture use `libwebrtc::desktop_capturer` first.** The `scap` crate is dropped (last push August 2025, self-described as unsuitable for production). OS-specific capture (`windows-capture`, `screencapturekit`, `ashpd` + PipeWire) is added only if M7 measurements require it.
- **Hardware encoding in v1 is whatever the SDK provides**: VideoToolbox on macOS, NVENC and VAAPI on Linux, NVENC on Windows, OpenH264 software fallback elsewhere. A Media Foundation encoder for QuickSync and AMF, fed through `NativeVideoSource::new_encoded`, is deferred to M7 and decided after measurement. The M7 criterion is "1080p60 with hardware encoding when it is available".
- **System and application audio during screen sharing** is implemented per OS in the `media` crate at M7.
- **The prebuilt libwebrtc is accepted.** The `livekit`, `libwebrtc` and `webrtc-sys` versions are pinned exactly, `deny.toml` restricts sources, and the risk is listed in the threat model.
- **Default network layout**: LiveKit signalling behind Caddy on 443, one multiplexed UDP port for media, 7881/TCP as ICE fallback, TURN/TLS on 5349. `network_mode: host` with a UDP port range is documented as an advanced option for Linux.
- The server issues LiveKit access tokens (short lived, one room, identity fixed to the device id) only after checking permissions.

## Alternatives considered

- **WebRTC in the webview**: least code, but unreliable on WebKitGTK, no control over encoders or capture, and insertable-stream E2EE support varies per webview.
- **mediasoup, Janus, Pion-based custom SFU**: more integration work, no maintained Rust client with E2EE.
- **Peer-to-peer mesh**: no SFU to host, but upload cost grows with the number of viewers; unusable for a 1080p60 stream watched by ten people.
- **A shared media key for the room**: simpler, but per-sender keys keep nonce spaces separate and bind frames to a sender.
- **Writing capture by hand per OS from the start**: more control, three implementations to maintain before knowing whether they are needed.

## Consequences

- LiveKit signalling is protected by TLS only. The SFU and the instance admin see who is in which room, IP addresses, track kinds, bitrates and timing. Media content is not visible to them.
- Codec headers needed by the SFU for routing remain unencrypted, as in every SFU-compatible frame encryption scheme.
- In a DM or group call, conversation members who are not in the call hold the group's exporter secret and could decrypt the media if they obtained the packets. They are members of that conversation anyway.
- Windows machines without an NVIDIA GPU encode in software in v1; 1080p60 may not hold on weak CPUs. Measured at M7.
- The client binary embeds libwebrtc. Its size and memory use are measured at M6 against the 200 MB call budget.
- TURN/TLS on 5349 needs a certificate for the TURN host name. How Caddy-managed certificates reach LiveKit is settled in M0.
- Video rendering (webview or native through wgpu) is decided at M7 after measurement.
