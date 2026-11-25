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

The code is created by the server that is already running (`docker compose exec`): start the stack with `docker compose up -d` first. The script never builds, pulls or starts anything, so it works offline and never replaces the image you are running.

Run the script again if you need another administrator, or if the code expired before you used it.

### Trying it on your own computer

For a test on your own computer, without a domain:

```bash
./scripts/init.sh --dev    # localhost names, and the development override
docker compose up -d
./scripts/create-admin.sh
curl --insecure https://localhost/health
```

To run the server from your checkout instead of a published image, build it with `./scripts/build.sh` before `docker compose up -d`: the script records the commit, and `curl http://localhost:8080/version` then shows it as `commit` (with a `-dirty` suffix if the checkout had uncommitted changes). This is how to make sure a running server matches the code you are looking at.

Caddy uses its own local certificate authority for `localhost`, hence `--insecure`. The desktop client refuses such a certificate. `--dev` therefore also enables `docker-compose.dev.yml` (through `COMPOSE_FILE` in `.env`), which publishes the server on `http://localhost:8080`, on the loopback interface only: enter that address in the client. Never use `--dev` on a real instance.

## 5. Updating

```bash
cd tavern
./deploy/scripts/backup.sh
git pull
cd deploy
docker compose up -d --build
```

Then run `./scripts/init.sh` again: a new version may need secrets that your `.env` does not have yet, and the script adds only what is missing. The server refuses to start, with a message naming the variable, when one is absent.

Database migrations are applied automatically when the server starts. Read the release notes before updating: they list any change to `.env.example`, `Caddyfile.example` or `livekit.yaml.example` that you need to carry over to your own files. Running `./scripts/init.sh` again is safe: it never overwrites existing files or secrets.

## 6. Backup and restore

```bash
cd deploy
./scripts/backup.sh                # writes backups/tavern-<timestamp>.tar.gz
./scripts/restore.sh backups/tavern-<timestamp>.tar.gz
```

A backup contains the PostgreSQL dump, the date it was taken, `.env` (configuration **and secrets**), `Caddyfile` and `livekit.yaml`. Encrypt it and copy it off the machine. The dump alone is not enough: without the matching `.env` the restored instance cannot be used.

What the secrets protect, and why they must be backed up together with the database:

- `.env` holds the **OPAQUE server setup**. Without it no user can log in again with their password.
- It also holds the dedicated **MLS external sender key**. If it is lost or replaced, the server can no longer remove kicked members from existing encrypted groups by itself until a member's client repairs each group. See [ADR 0002](adr/0002-mls-via-openmls.md#external-sender-key-lifecycle) for the consequences and the rotation procedure.
- It holds the **TOTP encryption key** and the **handle privacy key** as well. The table in [configuration.md](configuration.md#secrets) says what happens when each one is lost.

What a backup does **not** contain: readable messages. The server only stores ciphertext waiting for delivery; message history lives on your users' devices.

The database does hold, for each device, the server's part of the key of that device's local history ([ADR 0017](adr/0017-device-identity-and-sign-out.md)). It is useless on its own, but a device cannot open its local history without it. **Back up often:** after restoring a backup, devices enrolled since that backup are unknown to the instance. Their users must sign in again, and those devices start over as new devices, without their local history. Devices that existed at the time of the backup keep everything.

**Back up often**, at least daily, and keep the backups off the machine: a restore undoes everything done on the instance since the backup, and the more recent the backup, the less there is for your users to do again.

What restoring does to users, once milestone M2 is complete (until then, restore only test instances; the clients recreate conversations from M2's tasks 10 and 11; see [ADR 0019](adr/0019-mls-direct-messages.md), section 15):

- **Everyone signs in again.** The server revokes every session the first time it starts on the restored database, before it serves anything. Each device must sign in again with the password, and the TOTP code if it is enabled, before it can do anything. This matters because the backup lists as active the devices that were revoked after it, a stolen one included: without the password, such a device can do nothing.
- **What users changed after the backup is undone**: a password changed since (the old one works again), a recovery key replaced since (the old one works again), revoked devices, blocks, unfriendings, and TOTP enabled or disabled since. The server cannot redo it: the restored database knows nothing of it.
- **Everyone is told.** After signing in, each user sees a notice with the date of the backup. It says what the restore undid and asks them to do it again: first change their password and create a new recovery key if they had changed them, then check their devices (and **revoke again** those they had revoked), the people they block or unfriended, and their two-factor authentication. Tell your users too, by another channel.
- **Conversations are recreated** with the same members. Encrypted messages sent after the backup and not yet delivered are lost; history already on the devices is kept.
- **One-time KeyPackages are deleted**: those handed out after the backup would otherwise be handed out a second time. Devices upload new ones when they reconnect.
- **What administrators did after the backup is undone too**: accounts disabled since (a banned member) are active again, roles and TOTP disabled by an administrator are as they were, and invitations revoked or used since would be valid again. The server revokes every invitation still valid, and each administrator sees a notice asking them to do their actions again. The audit log is restored with the database: it does not list what was done after the backup, so keep your own notes of bans.

### How the server knows it was restored

Two independent ways, so that a restore is handled even when `restore.sh` was not used:

- `restore.sh` raises the **instance generation** in the database and records the date of the backup.
- The server keeps a **marker** in its data directory (`TAVERN_DATA_DIR`, the `server-data` volume, outside the PostgreSQL volume): the instance generation and a counter that every write to the database advances. It writes it at start-up, every 10 seconds when something changed, and when it stops, and never backwards. If, at start-up, the database is behind the marker (a lower generation, or a lower counter at the same generation), the server treats it as restored and raises the generation itself; the date of the backup is then the server's last record of a change before it: a few seconds before the backup on an instance in use, but possibly days before on an instance nobody used (the notice then gives an older date than the backup's, which errs on the safe side).

**Always stop the server before restoring.** `restore.sh` does it, and refuses to go on if the server still runs. A database restored under a running server is served as it is for up to 10 seconds: devices revoked after the backup can act again, KeyPackages can be handed out a second time. The server then notices that the database went back, refuses to write its marker backwards, logs an error and stops; Docker starts it again, and the start-up handles the restore.

`restore.sh` also refuses a backup made by another version of Tavern (another database schema): restored over a newer schema, the database would not let the server start. Restore it with the version it was made with, then update.

Rules that keep this working:

- **Never back up or restore the `server-data` volume** with the database (`backup.sh` leaves it out). If it is restored together with an older database, the marker is old too, and the restore goes unnoticed unless `restore.sh` recorded it. A VM or disk snapshot of the whole machine restores both: after restoring one, run `restore.sh` on a backup instead, or tell the server by hand (`UPDATE instance_state SET generation = generation + 1;` before it starts).
- Losing the volume disables the check until the next start, which writes a new marker. `docker compose down -v` deletes it with the database: restoring a dump by hand afterwards goes unnoticed. Use `restore.sh`, which records the restore. A marker of another database (a new instance on the same volume) is replaced.
- A false detection is possible, rarely: after a power cut of the machine, PostgreSQL may come back with the counter slightly below the value the marker had written (an advance by a transaction that was rolled back is not always on disk). The server then handles a restore that did not happen, with all its effects: everyone signs in again and sees the notice, every conversation's group is recreated (messages not yet delivered are lost, history on the devices is kept), and invitations must be created again. Nothing the users changed is undone.
- The server refuses to start if it cannot write the marker, or if the file is not a marker. Delete it only if you know the database was not restored.
- What it cannot see: after a crash, which leaves no update at shutdown, a database restored from a backup taken in the last 10 seconds before the crash. What changed in those seconds is undone without the notice. Use `restore.sh`, which records the restore whatever the marker says.

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
- Caddy writes no access log in the default configuration, and the server's own request log holds the method, the route template, the status and the duration only: client IP addresses, handles and identifiers are not recorded ([details](configuration.md#request-log)).
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
