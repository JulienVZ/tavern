# Security policy

Tavern is an end-to-end encrypted messaging application. Security reports are welcome and treated as a priority.

## Project status

Tavern is in early development and **has not been audited**. Do not rely on it yet to protect sensitive communications.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a security problem.**

Report it privately with GitHub's private vulnerability reporting:

1. Open <https://github.com/JulienVZ/tavern/security/advisories/new> (repository → *Security* → *Report a vulnerability*).
2. Describe the problem, the affected component and version or commit, and how to reproduce it. A proof of concept helps.
3. Do not include real user data, real secrets or content from an instance you do not own.

What to expect:

- an acknowledgement within 7 days;
- an assessment and a plan within 30 days;
- a fix, an advisory and credit to you (unless you prefer to stay anonymous) once a patched version is available.

Please give us reasonable time to release a fix before publishing details.

## Scope

In scope:

- anything that lets the server, a network attacker or a non-member read message content, attachments, reactions, custom emojis or call media;
- authentication and session flaws (OPAQUE, device enrolment, session tokens, TOTP);
- MLS integration flaws (group membership, removal, external sender handling, key derivation for media);
- memory safety, injection or denial-of-service bugs in the server or the client;
- flaws in the reference deployment (`deploy/`) that expose secrets or data.

Out of scope, because they are documented limits (see [docs/threat-model.md](docs/threat-model.md)):

- metadata visible to the instance: who talks to whom and when, server and channel names, profiles;
- what a compromised device can read;
- a malicious instance administrator denying service to their own users.

Testing must only target instances you own or are explicitly allowed to test.

## Supported versions

Until the first stable release, only the latest commit on `main` and the latest tagged version receive fixes.
