# ADR 0015 — Argon2id working memory in a dedicated mapping

- Status: accepted
- Date: 2026-11-15

## Context

The client runs Argon2id with 128 MiB at every registration, login, password change and recovery (ADR 0003). The client's idle memory budget is 150 MB; exceeding it for the fraction of a second the computation lasts is an accepted exception, provided the memory goes back to the system afterwards.

With the working memory taken from the general-purpose allocator (`Argon2::hash_password_into`), that depends on the platform. Measured with `cargo run --release -p tavern-crypto --example argon2_memory`: three registrations in a row, then idle. The figure is the one each system charges to the process: physical footprint on macOS (`vmmap --summary`), resident set size on Linux, private bytes on Windows.

| Platform | Before | Right after | 2 s later | 10 s later | 30 s later |
|---|---|---|---|---|---|
| Linux, GitHub runner (ubuntu-24.04, glibc) | 2 MiB | 2 MiB | 2 MiB | 2 MiB | — |
| macOS 27, development machine (Apple M4) | 1.2 MiB | 129.3 MiB | 129.4 MiB | 1.4 MiB | 1.4 MiB |
| macOS 26.7, GitHub runner (`macos-latest`, arm64) | 1.0 MiB | 129.0 MiB | 129.1 MiB | 129.1 MiB | **129.1 MiB** |
| Windows, GitHub runner (`windows-latest`) | pending | | | | |

Linux returns the block at once. macOS 27 returns it within ten seconds. macOS 26 still holds it after thirty: a client sits about 128 MiB above its idle footprint after a login, for an unknown time. Three runs in a row never used more than one block, so this is the allocator's cache of large blocks, not a leak.

An experiment outside the project's crates, on the macOS 26.7.2 runner, compared two ways of giving the memory back:

| Step | Physical footprint |
|---|---|
| Start | 0.9 MiB |
| After hashing with the ordinary heap allocation | 129.0 MiB |
| After `malloc_zone_pressure_relief(NULL, 0)` (reported 0 bytes released) | 129.1 MiB |
| After a second hash in a dedicated anonymous mapping (`mmap`) | 257.2 MiB |
| After `munmap` of that mapping | 129.1 MiB |

Asking the allocator to drop its caches does nothing. A mapping that is unmapped after the computation returns its 128 MiB at once (the 129 MiB left in the last line are the cached block of the first step).

Viewing mapped bytes as Argon2 blocks requires `unsafe` code, which `tavern-crypto`, where the key stretching lives, forbids.

## Decision

A separate crate, **`tavern-argon2-memory`** (`crates/argon2-memory`), provides `WorkingMemory`: a zero-filled run of `argon2::Block`, erased and released when dropped. `tavern-crypto` uses it through `Argon2::hash_password_into_with_memory` and keeps `#![forbid(unsafe_code)]`, as do `protocol` and `server`.

- **Scope.** The crate contains the mapping and nothing else: no cryptography, no parameters, no policy. It depends on `argon2` only for the `Block` type, so that the conversion from mapped bytes to blocks happens inside it; on `zeroize`; and on `libc` (Unix).
- **Unix (Linux, macOS).** `mmap` of a private anonymous region, `munmap` at drop. The `unsafe` code is three calls (`mmap`, the view of the region as a slice of blocks, `munmap`) plus one `munmap` on a path that cannot be reached in practice (a mapping that would not be aligned for a block). Each carries a `// SAFETY:` comment; the layout assumptions (a block is 1024 bytes without padding, aligned to at most a page) are compile-time assertions.
- **Other systems (Windows).** The blocks come from the global allocator, with no `unsafe` code, and are erased before being freed. Whether Windows needs a native mapping too is decided by the measurement above.
- **Erasure.** The blocks are erased with `zeroize` (through `argon2`'s `zeroize` feature) before the memory is released, in the destructor: on normal return, on early return after an error and when a panic unwinds. Release builds of the client use `panic = "abort"`: a panic there ends the process without running destructors, and the system reclaims the pages, which it never hands to another process uncleared. Before this change the working memory was freed without being erased.
- **Not locked.** The memory is not `mlock`ed: like the rest of the process it can be written to swap during the computation. Locking 128 MiB commonly exceeds `RLIMIT_MEMLOCK`, and the password and derived keys live in ordinary memory anyway.
- **Allocation failure** is an error of the OPAQUE operation, not an abort.

Verification:

- unit tests in the crate: zero-filled on hand-out, erased before release on the three paths (normal, error, panic), refused sizes, and Argon2id giving the same output in this memory as in its own;
- the crate's tests under **Miri** in CI, for the Linux and macOS targets;
- `crates/crypto/tests/argon2_memory_release.rs`: after each of three registrations, with no delay, the memory charged to the process must not have grown by more than 32 MiB. It runs in CI on Linux, macOS (the affected runner) and Windows.

Result with the dedicated mapping, same measurement as above:

| Platform | Before | Right after each run |
|---|---|---|
| macOS 27, development machine (Apple M4) | 1.2 MiB | 1.3 – 1.4 MiB |
| Linux, macOS 26.7 and Windows runners | pending | |

## Alternatives considered

- **Accept the retention on macOS 26 and earlier**, documented. Rejected: 128 MiB held for an unknown time nearly doubles the idle budget on a system version that will remain common for years, and the fix is small.
- **`malloc_zone_pressure_relief`** after the computation. Measured: releases nothing.
- **A short-lived helper process** for the key stretching. Returns the memory on every system without `unsafe`, but adds process spawning, a channel carrying the OPRF output and the derived key between processes, and packaging of a second executable. Kept as a last resort only.
- **A lower memory parameter** (64 MiB). Halves the retained amount without removing it, and weakens the protection of every account's identity key against offline guessing (ADR 0003).
- **`unsafe` directly in `tavern-crypto`**. Rejected: the crate-wide `forbid` is worth more than one fewer crate.
- **A generic mapping crate from crates.io** (`memmap2`, `region`). They hand out bytes; turning bytes into `argon2::Block` still needs `unsafe` at the call site, in `tavern-crypto`. They would add a dependency without removing the code that needs review.
- **A custom global allocator.** Changes the behaviour of every allocation in the client to fix one.

## Consequences

- The project now contains `unsafe` code of its own, confined to one crate of about forty lines of implementation. Any change to that crate needs explicit review and must keep the Miri job green.
- `tavern-crypto` depends on `tavern-protocol` and `tavern-argon2-memory`.
- The working memory is erased after use, which it was not before. The cost is one pass over 128 MiB per login (a few milliseconds).
- Each login maps and unmaps 128 MiB; the kernel zero-fills the pages on first touch, as it did for the heap allocation.
- If a future system retains memory under the allocator fallback, the same crate is where a native mapping for it goes.
