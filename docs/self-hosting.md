# Self-hosting guide

This guide takes you from an empty machine to a running Tavern instance for a group of friends.

> **Status: work in progress.** The server handles accounts: invitations, registration, login, devices and two-factor authentication. Messaging and calls arrive with the next milestones. Installing today is useful to prepare your machine and network, not to chat yet.

## 1. What you need

### Hardware, for about 40 users

| Resource | Recommended |
|---|---|
| CPU | 4 vCPU |
| RAM | 8 GB |
| Disk | 100 GB SSD, plus space for uploaded files |
| Upload bandwidth | at least 500 Mb/s, ideally 1 Gb/s symmetric |
| Network | a public IPv4 address |

**Bandwidth is the limiting factor**, not CPU. The media server forwards streams without re-encoding them: one 1080p60 screen share watched by ten people uses about 80 Mb/s of upload. A smaller group, or lower stream quality, needs proportionally less.

Both `amd64` and `arm64` machines are supported.

### Software

- Linux with Docker Engine and the Compose plugin (v2).
- `git`, and `openssl` (optional; used to generate secrets when available).

### Names

Two DNS names pointing to your machine's public IPv4 address, for example:

| Name | Purpose |
|---|---|
| `chat.example.org` | The instance: what users type in the client |
| `livekit.example.org` | Voice and video signalling |

Create an `A` record for each. Add `AAAA` records only if the machine is reachable over IPv6 on the same ports.

## 2. Ports

| Port | Protocol | Service | Purpose |
|---|---|---|---|
| 80 | TCP | Caddy | Certificate issuance and redirect to HTTPS |
| 443 | TCP and UDP | Caddy | API, real-time gateway, LiveKit signalling (HTTP/2 and HTTP/3) |
| 7881 | TCP | LiveKit | Media when UDP is blocked |
| 7882 | UDP | LiveKit | Media (all streams multiplexed on this single port) |

All four must be reachable from the internet. Nothing else is exposed: PostgreSQL and the Tavern server are only reachable inside the Docker network.

TURN is disabled by default; see [section 8](#8-optional-turn-over-tls) if some of your users are on networks that block everything except HTTPS.

## 3. VPS or home server

### On a VPS

1. Open the ports above in the provider's firewall and in the host firewall (`ufw`, `firewalld`, `nftables`).
2. Use the VPS public IP address for the DNS records and for `LIVEKIT_NODE_IP`.

Check the provider's traffic allowance: video uses a lot of bandwidth.

### At home, behind a router

1. Give the server a fixed address on your local network (DHCP reservation).
2. In the router, forward TCP 80, TCP 443, UDP 443, TCP 7881 and UDP 7882 to that address.
3. Find your public IPv4 address (shown in the router's status page) and use it for the DNS records and `LIVEKIT_NODE_IP`.
4. If your public address changes over time, use a dynamic DNS service and update `LIVEKIT_NODE_IP` when it changes.

Things that prevent hosting at home:

- **CGNAT**: if the router's WAN address is in `100.64.0.0/10` or differs from the address seen from the internet, incoming connections cannot reach you. Ask your provider for a public IPv4 address, or use a VPS.
- **Blocked ports**: some providers block incoming 80 and 443.
- **Upload speed**: check it against the table in section 1.

Friends on the same local network as the server need the router to support NAT loopback (hairpinning), or a local DNS entry pointing the two names to the server's local address.

## 4. First installation

```bash
git clone https://github.com/JulienVZ/tavern.git
cd tavern/deploy

# Creates .env, Caddyfile and livekit.yaml, asks for the two host names and
# generates the secrets. The first run builds the server image (a few minutes).
./scripts/init.sh

# Set LIVEKIT_NODE_IP to the public IPv4 address of the machine.
nano .env

docker compose up -d
```

The first start builds the server image, which takes a few minutes. Caddy then obtains TLS certificates automatically; this needs ports 80 and 443 to be reachable and the DNS records to be in place.

Check that everything runs:

```bash
docker compose ps
curl https://chat.example.org/health
# {"status":"ok","database":"ok"}
```

`init.sh` never overwrites an existing value. Without a terminal (in a provisioning script, for example) it cannot ask for the host names: it lists what is still empty and exits with an error, and you set `TAVERN_DOMAIN` and `LIVEKIT_DOMAIN` in `deploy/.env` yourself.

`deploy/.env` contains the instance secrets. Keep it private (`init.sh` sets its permissions to `600`).

> **`.env` and the database belong together.** PostgreSQL stores its password inside its data volume when the volume is first created, and never reads `POSTGRES_PASSWORD` again. If `.env` is deleted or regenerated while the volume is kept, the new password does not match: PostgreSQL still reports "healthy", and the Tavern server stops with *"PostgreSQL rejected the credentials"*. Always back up and restore `.env` together with the database; `backup.sh` puts both in the same archive.

Every variable is described in [configuration.md](configuration.md).

### Creating the first administrator

Registration is closed by default: accounts are created with invitation codes issued by an administrator.

```bash
./scripts/create-admin.sh
```

This prints a single-use invitation code, valid 24 hours and shown only once. Register with it in the Tavern client: that account becomes an administrator and can then create invitations for everyone else. The server never creates an account with a password itself, so that it never sees one.

Run the script again if you need another administrator, or if the code expired before you used it.

### Trying it on your own computer

For a local test without a domain:

```bash
./scripts/init.sh --dev    # sets localhost and livekit.localhost
docker compose up -d
curl --insecure https://localhost/health
```

Caddy uses its own local certificate authority for `localhost`, hence `--insecure`. The desktop client refuses such a certificate; to connect a locally built client, use the development override described in [CONTRIBUTING.md](../CONTRIBUTING.md).

## 5. Updating

```bash
cd tavern
./deploy/scripts/backup.sh
git pull
cd deploy
docker compose up -d --build
```

Database migrations are applied automatically when the server starts. Read the release notes before updating: they list any change to `.env.example`, `Caddyfile.example` or `livekit.yaml.example` that you need to carry over to your own files. Running `./scripts/init.sh` again is safe: it never overwrites existing files or secrets.

## 6. Backup and restore

```bash
cd deploy
./scripts/backup.sh                # writes backups/tavern-<timestamp>.tar.gz
./scripts/restore.sh backups/tavern-<timestamp>.tar.gz
```

A backup contains the PostgreSQL dump, `.env` (configuration **and secrets**), `Caddyfile` and `livekit.yaml`. Encrypt it and copy it off the machine. The dump alone is not enough: without the matching `.env` the restored instance cannot be used.

What the secrets protect, and why they must be backed up together with the database:

- `.env` holds the **OPAQUE server setup**. Without it no user can log in again with their password.
- It also holds the dedicated **MLS external sender key**. If it is lost or replaced, the server can no longer remove kicked members from existing encrypted groups by itself until a member's client repairs each group. See [ADR 0002](adr/0002-mls-via-openmls.md#external-sender-key-lifecycle) for the consequences and the rotation procedure.
- It holds the **TOTP encryption key** and the **handle privacy key** as well. The table in [configuration.md](configuration.md#secrets) says what happens when each one is lost.

What a backup does **not** contain: readable messages. The server only stores ciphertext waiting for delivery; message history lives on your users' devices.

`restore.sh --db-only` restores the database and keeps the current configuration files. Uploaded files (attachments) will be added to both scripts when they exist (milestone M5).

## 7. Stopping and removing

```bash
docker compose down       # stop, keep data
docker compose down -v    # stop and DELETE the database and certificates
```

## 8. Optional: TURN over TLS

By default clients send media over UDP 7882, or TCP 7881 when UDP is blocked. Some corporate or school networks allow nothing but TLS on well-known ports; users there cannot join calls. TURN over TLS on port 5349 helps in that case.

This option is not part of the default deployment. Outline:

1. Add a DNS name for TURN (for example `turn.example.org`) and add it as a site in `Caddyfile` so that Caddy obtains a certificate for it.
2. Mount Caddy's certificate volume (`caddy-data`) read-only into the `livekit` service.
3. In `livekit.yaml`, set `turn.enabled: true`, `turn.domain`, `turn.tls_port: 5349` and the paths of the certificate and key inside the mounted volume.
4. Publish `5349/tcp` on the `livekit` service and open it in your firewall or router.
5. Restart LiveKit after each certificate renewal (about every 60 days), since it reads the certificate at start-up.

Detailed, tested instructions will be added when voice lands (milestone M6). Check the [LiveKit self-hosting documentation](https://docs.livekit.io/transport/self-hosting/) for the current option names.

## 9. Advanced: host networking on Linux

Instead of a single multiplexed UDP port, LiveKit can use a range of UDP ports (50000–60000), which performs better with many simultaneous participants. Docker's port publishing is slow for large ranges, so this requires `network_mode: host` for the `livekit` service, a `port_range_start`/`port_range_end` in `livekit.yaml` instead of `udp_port`, pointing Caddy at the host instead of the `livekit` container, and opening the whole range in the firewall. For 40 users the default single port is enough.

## 10. Privacy notes for administrators

- The server stores no message content, only ciphertext and the metadata listed in the [threat model](threat-model.md). As the administrator you can see who talks to whom and when, the names of servers and channels, and user profiles.
- No telemetry is sent anywhere, and the software contacts no third party. Caddy contacts Let's Encrypt to obtain certificates.
- The default configuration writes no access log, so client IP addresses are not recorded.
- If you run a modified version for other people, the AGPL requires you to offer them the modified source: set `TAVERN_SOURCE_URL`.

## 11. Troubleshooting

| Symptom | Check |
|---|---|
| `docker compose up` says a variable is not set | Run `./scripts/init.sh` (or `./scripts/init.sh --dev` for a local test). |
| The server restarts in a loop with "PostgreSQL rejected the credentials" | `.env` does not match the database volume. Restore the `.env` from your backup. On an instance with nothing to keep: `docker compose down -v`, then start again. |
| Caddy cannot obtain a certificate | DNS records point to this machine; ports 80 and 443 reachable from outside; `docker compose logs caddy`. |
| The server stops with "the instance secret ... is not set" | Run `./scripts/init.sh`, or restore the `.env` that belongs to this database. |
| Everyone gets "too many requests" at once | The server is behind a proxy that does not append the client address, so all clients share one rate-limit bucket. See `TAVERN_TRUST_FORWARDED_FOR` in [configuration.md](configuration.md). |
| `/health` answers 503 | `docker compose logs server postgres`. The database is unreachable. |
| The server restarts in a loop | `docker compose logs server`: an invalid variable is named in the error. |
| Calls connect but there is no audio or video | `LIVEKIT_NODE_IP` is the public address; UDP 7882 and TCP 7881 are forwarded. |
