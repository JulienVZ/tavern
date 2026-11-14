# Tavern

**A self-hosted, end-to-end encrypted chat for groups of friends.** Text, voice, video and screen sharing, on a server you run yourself.

> **Work in progress.** Accounts work: invitations, registration, sign-in from several devices, two-factor authentication, account recovery. Messaging and calls do not exist yet. Nothing has been audited. Do not use it for real conversations. "Tavern" is a provisional name.

## Why

Group chat applications are convenient, but the company running them can read everything, and the best features sit behind a subscription. Tavern takes the other route:

- **End-to-end encrypted everywhere.** Direct messages, groups, server channels, files, voice, video and screen sharing. The server relays ciphertext and never sees content.
- **Yours to host.** One `docker compose up -d` and one `.env` file, on a VPS or a machine at home, for about 40 people.
- **Light.** A native desktop client built on the system webview, not a bundled browser.
- **Nothing held back.** High-quality audio, 1080p60 screen sharing, large uploads, animated avatars and custom emojis are just features, limited only by what the instance admin configures.
- **No telemetry.** No analytics, no third-party service, no external fonts.

## Planned features

| Area | Features |
|---|---|
| Social | Accounts by invitation, profiles, friends, blocking, presence, typing indicators |
| Messaging | 1:1 and group direct messages, servers with text channels, categories, roles and permissions; edits, replies, reactions, mentions, Markdown, custom emojis, client-side link previews, local search |
| Files | Encrypted attachments with a configurable size limit (500 MB by default) |
| Voice and video | 1:1 and group calls, persistent voice channels, Opus audio, noise suppression, push-to-talk, webcam |
| Screen sharing | 1080p at 60 fps by default, with application or system audio where the OS allows |
| Administration | Closed registration with invitation codes, admin panel, storage quotas, quality limits |
| Platforms | Windows, macOS, Linux |

Not planned for the first version: federation between instances, mobile apps, bots and public API, a browser client.

Screenshots will be added when there is something to show.

## Status

| Milestone | Content | State |
|---|---|---|
| M0 | Project scaffolding, deployment, CI | done |
| M1 | Accounts: OPAQUE login, devices, invitations, TOTP, recovery | done |
| M2 | Friends and encrypted direct messages | next |
| M3 | Private groups | planned |
| M4 | Servers, channels, roles, moderation | planned |
| M5 | Attachments, avatars, custom emojis, reactions, local search | planned |
| M5b | Message history on a new device | planned |
| M6 | Voice | planned |
| M7 | Webcam and screen sharing | planned |
| M8 | Notifications, settings, updater, packaging | planned |
| M9 | Hardening and audit preparation | planned |

## How it works

```
Desktop client (Tauri 2)                     Your instance (Docker Compose)
┌──────────────────────────────┐            ┌───────────────────────────────┐
│ UI: Svelte 5 + TypeScript    │            │ Caddy: TLS, reverse proxy     │
│ Core (Rust): MLS, storage,   │◄── TLS ───►│ Server (Rust, axum)           │
│ networking, media            │            │ PostgreSQL                    │
│ Local store: SQLCipher       │◄─ media ──►│ LiveKit: media relay (SFU)    │
└──────────────────────────────┘            └───────────────────────────────┘
```

- Messages are encrypted with **MLS** (RFC 9420, through OpenMLS). Every device is a member of each conversation's group; removing someone rotates the keys.
- Call media is encrypted with keys derived from the same MLS groups, so the media relay only forwards frames it cannot read.
- Passwords never reach the server: login uses **OPAQUE**. A recovery key, shown once at registration, lets you set a new password without losing your identity.
- Files are encrypted on the device before upload.

What the server can still see is metadata: who talks to whom and when, the names of servers and channels, and profiles. This is spelled out in the [threat model](docs/threat-model.md).

More: [architecture](docs/architecture.md), [protocol](docs/protocol.md), [database schema](docs/database-schema.md), [decision records](docs/adr/).

## Host your own instance

You need a Linux machine with Docker, two DNS names pointing to it, and ports 80/TCP, 443/TCP+UDP, 7881/TCP and 7882/UDP reachable from the internet.

```bash
git clone https://github.com/JulienVZ/tavern.git
cd tavern/deploy

./scripts/init.sh          # creates .env, generates the secrets, asks for the host names
nano .env                  # set LIVEKIT_NODE_IP
docker compose up -d
./scripts/create-admin.sh  # prints the invitation code of the first administrator
```

Minimal configuration in `deploy/.env`:

```ini
TAVERN_DOMAIN=chat.example.org        # what users type in the client
LIVEKIT_DOMAIN=livekit.example.org    # voice and video signalling
LIVEKIT_NODE_IP=203.0.113.10          # public IPv4 address of the machine
```

Check it:

```bash
curl https://chat.example.org/health
# {"status":"ok","database":"ok"}
```

Then open the client, enter your instance address, and create your account with the invitation code. As administrator you create the invitations for everyone else.

TLS certificates are obtained automatically. For hardware sizing (about 40 users: 4 vCPU, 8 GB RAM, 500 Mb/s upload), home routers, updates and backups, read the [self-hosting guide](docs/self-hosting.md). Every setting is listed in the [configuration reference](docs/configuration.md).

## Build the desktop client

Prerequisites: [Rust](https://rustup.rs), Node.js 22.12+ or 24+, [pnpm](https://pnpm.io), and the [Tauri system dependencies](https://tauri.app/start/prerequisites/) for your OS.

```bash
cd apps/desktop
pnpm install
pnpm tauri dev      # run in development
pnpm tauri build    # build an installer for your OS
```

Signed installers for Windows, macOS and Linux will be published with releases.

## Repository layout

| Path | Content |
|---|---|
| `crates/protocol` | Wire types shared by client and server |
| `crates/crypto` | MLS, OPAQUE, key management, file encryption |
| `crates/server` | Instance server |
| `crates/client-core` | Client logic without UI |
| `crates/media` | Capture and encoding |
| `crates/e2e-tests` | End-to-end tests: the real client against the real server |
| `apps/desktop` | Tauri shell and Svelte UI |
| `deploy` | Docker Compose stack and scripts |
| `docs` | Architecture, threat model, protocol, guides, decision records |

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first, in particular the rules that keep content away from the server. Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md). Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licence

[GNU Affero General Public License v3.0 or later](LICENSE). If you run a modified Tavern server for other people, you must offer them your modified source code.
