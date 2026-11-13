# ADR 0001 — Rust everywhere, Tauri 2 for the desktop client

- Status: accepted
- Date: 2026-11-13

## Context

Tavern is a self-hosted messaging application for small groups (about 40 users per instance). Two of its three pillars constrain the language and client framework:

- a light client (under 150 MB of RAM idle, under 2 s cold start) on Windows, macOS and Linux;
- end-to-end encryption everywhere, which puts a lot of security-critical parsing, cryptography and networking code on the client.

The server must also fit, together with PostgreSQL and LiveKit, on a 4 vCPU / 8 GB machine.

## Decision

- **Rust** (edition 2024, stable toolchain) for the server and for all client logic. Client and server share the `protocol` and `crypto` crates.
- **Tauri 2** (2.12 at the time of writing) as the desktop shell. Tauri 3 is in alpha and is not considered until it is stable.
- **Svelte 5 + TypeScript + Vite** for the UI, built with `pnpm`.
- The webview is a rendering surface only. Keys, ciphertext, networking and media live in Rust (`client-core`); the UI receives already-decrypted view models through Tauri commands and events.

## Alternatives considered

- **Electron**: mature and uniform (one Chromium everywhere, working WebRTC), but ships a full browser per app. The idle RAM budget is not reachable.
- **Native toolkits per OS** (SwiftUI, WinUI, GTK): best footprint, three UIs to maintain. Not realistic for a small project.
- **Rust-native GUI** (egui, iced, Slint, Dioxus native): attractive footprint, but rich text, accessibility, IME and animated media support are weaker than a webview, and a chat UI leans on all of them.
- **Go or TypeScript on the server**: workable at this scale, but would split the protocol and crypto code across two languages.

## Consequences

- One language for protocol, crypto, server and client core; memory safety for the code that parses untrusted input.
- The system webview differs per OS (WebView2, WKWebView, WebKitGTK). UI code must be tested on all three, and nothing critical may depend on a webview-specific API. In particular WebKitGTK has no reliable WebRTC, which is one reason media is handled in Rust (see [ADR 0004](0004-livekit-sfu-native-media.md)).
- Tauri 2 supports iOS and Android, which keeps mobile clients possible after v1.
- Contributors need a Rust toolchain and Node/pnpm. sqlx 0.9 requires Rust 1.94 or newer, which sets the workspace MSRV floor.
