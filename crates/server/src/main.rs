// SPDX-License-Identifier: AGPL-3.0-or-later

//! `tavern-server` binary.
//!
//! Usage:
//!
//! - `tavern-server`: run the server.
//! - `tavern-server healthcheck`: query the local `/health` endpoint and exit
//!   with status 0 when it answers 200. Used by the container health check,
//!   since the runtime image has no shell or HTTP client.

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use tavern_server::config::Config;
use tavern_server::{AppState, app, db, telemetry};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let result = match (args.next().as_deref(), args.next()) {
        (None, _) => run().await,
        (Some("healthcheck"), None) => healthcheck().await,
        _ => Err(anyhow::anyhow!("usage: tavern-server [healthcheck]")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // The subscriber may not be installed yet, so write to stderr directly.
            #[expect(clippy::print_stderr, reason = "last-resort error report before exit")]
            {
                eprintln!("error: {error:#}");
            }
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let config = Config::from_env().context("invalid configuration")?;
    telemetry::init(&config.log_level, config.log_format).context("invalid log level")?;
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        ?config,
        "starting tavern-server"
    );

    let pool = db::connect(&config.database_url, config.db_max_connections)
        .await
        .context("cannot connect to PostgreSQL")?;

    if config.run_migrations {
        db::migrate(&pool)
            .await
            .context("cannot apply database migrations")?;
        tracing::info!("database migrations applied");
    } else {
        tracing::warn!("database migrations are disabled");
    }

    let state = AppState {
        db: pool.clone(),
        source_url: config.source_url.clone(),
    };
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("cannot listen on {}", config.listen_addr))?;
    tracing::info!(addr = %config.listen_addr, "listening");

    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server failed")?;

    pool.close().await;
    tracing::info!("shut down cleanly");
    Ok(())
}

/// Resolves when the process is asked to stop (Ctrl-C, or SIGTERM on Unix).
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "cannot listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutdown signal received");
}

/// Sends `GET /health` to the local server over plain TCP.
async fn healthcheck() -> anyhow::Result<()> {
    const TIMEOUT: Duration = Duration::from_secs(3);

    let port = match std::env::var(tavern_server::config::vars::LISTEN_ADDR) {
        Ok(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse::<SocketAddr>()
            .context("invalid listen address")?
            .port(),
        _ => 8080,
    };
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

    let exchange = async {
        let mut stream = TcpStream::connect(addr).await?;
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut head = [0u8; 12];
        stream.read_exact(&mut head).await?;
        Ok::<_, std::io::Error>(head)
    };

    let head = tokio::time::timeout(TIMEOUT, exchange)
        .await
        .context("health check timed out")?
        .context("health check request failed")?;

    if &head == b"HTTP/1.1 200" {
        Ok(())
    } else {
        bail!("server is unhealthy")
    }
}
