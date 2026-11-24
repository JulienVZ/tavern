# syntax=docker/dockerfile:1
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Tavern server image. Build from the repository root:
#
#   docker build -f deploy/Dockerfile -t tavern-server:local .
#
# Multi-arch (amd64 + arm64) images are produced by CI with buildx.

ARG RUST_VERSION=1.100

FROM rust:${RUST_VERSION}-slim-trixie AS build
WORKDIR /src
COPY . .
# Shown by GET /version, to tell which commit a running server was built
# from. scripts/build.sh and the CI set it; the repository itself is not in
# the build context.
ARG TAVERN_BUILD_COMMIT=
# The `server` profile is the release profile with panic = "unwind": a panic
# caused by a request fails that request, never the server (ADR 0019,
# section 18).
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --profile server --locked --package tavern-server \
    && cp target/server/tavern-server /tavern-server
# The server's data directory (TAVERN_DATA_DIR), owned by the runtime user:
# a named volume mounted on it starts with this owner.
RUN mkdir -p /data/tavern

# Distroless: no shell, no package manager, runs as an unprivileged user.
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /tavern-server /usr/local/bin/tavern-server
COPY --from=build --chown=65532:65532 /data/tavern /var/lib/tavern
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/tavern-server"]
