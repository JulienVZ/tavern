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
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked --package tavern-server \
    && cp target/release/tavern-server /tavern-server

# Distroless: no shell, no package manager, runs as an unprivileged user.
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /tavern-server /usr/local/bin/tavern-server
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/tavern-server"]
