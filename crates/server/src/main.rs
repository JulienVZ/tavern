// SPDX-License-Identifier: AGPL-3.0-or-later

//! `tavern-server` binary.
//!
//! Usage:
//!
//! - `tavern-server`: run the server.
//! - `tavern-server gen-secrets`: print a fresh set of instance secrets.
//! - `tavern-server create-admin-invite`: print the code of a single-use
//!   invitation that makes its account an administrator.
//! - `tavern-server healthcheck`: query the local `/health` endpoint and exit
//!   with status 0 when it answers 200. Used by the container health check,
//!   since the runtime image has no shell or HTTP client.

#![forbid(unsafe_code)]

// A panic caused by a request must fail that request, never stop the server
// (ADR 0019, section 18): the release build comes from the `server` profile.
#[cfg(not(panic = "unwind"))]
compile_error!(
    "tavern-server must be built with panic = \"unwind\": \
     use `cargo build --profile server`, not `--release`"
);

use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use tavern_server::config::Config;
use tavern_server::secrets::InstanceSecrets;
use tavern_server::{AppState, Settings, app, db, panics, purge, routes, telemetry};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let result = match (args.next().as_deref(), args.next()) {
        (None, _) => run().await,
        (Some("healthcheck"), None) => healthcheck().await,
        (Some("gen-secrets"), None) => {
            gen_secrets();
            Ok(())
        }
        (Some("create-admin-invite"), None) => create_admin_invite().await,
        _ => Err(anyhow::anyhow!(
            "usage: tavern-server [healthcheck | gen-secrets | create-admin-invite]"
        )),
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
    panics::install_hook();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        ?config,
        "starting tavern-server"
    );

    // Checked before touching the database: a missing secret is a set-up
    // mistake that the administrator must see first.
    let secrets = InstanceSecrets::from_env()?;

    // The error text explains the cause and the fix; `main` prints it to
    // stderr, which is what `docker compose logs` shows.
    let pool = db::connect(&config.database_url, config.db_max_connections).await?;

    if config.run_migrations {
        db::migrate(&pool)
            .await
            .context("cannot apply database migrations")?;
        tracing::info!("database migrations applied");
    } else {
        tracing::warn!("database migrations are disabled");
    }

    let state = AppState::new(
        pool.clone(),
        secrets,
        Settings {
            message_retention_days: config.message_retention_days,
            device_inactive_days: config.device_inactive_days,
            claim_limits: config.claim_limits,
            friend_requests_per_hour: config.friend_requests_per_hour,
            ..Settings::new(
                config.source_url.clone(),
                config.trust_forwarded_for,
                config.session_ttl,
            )
        },
    );
    // At start-up, then every hour (ADR 0019, sections 12 and 15).
    let purge = purge::spawn(state.clone());
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("cannot listen on {}", config.listen_addr))?;
    tracing::info!(addr = %config.listen_addr, "listening");

    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("HTTP server failed")?;

    purge.abort();
    pool.close().await;
    tracing::info!("shut down cleanly");
    Ok(())
}

/// Prints a fresh set of instance secrets as `NAME=value` lines.
///
/// `deploy/scripts/init.sh` copies into `.env` the ones that are still empty.
/// Nothing is written anywhere else, and nothing is logged.
fn gen_secrets() {
    for (name, value) in InstanceSecrets::generate() {
        #[expect(
            clippy::print_stdout,
            reason = "the output of this command is its purpose"
        )]
        {
            println!("{name}={value}");
        }
    }
}

/// Creates a single-use invitation whose account becomes an administrator,
/// and prints its code once.
async fn create_admin_invite() -> anyhow::Result<()> {
    const VALID_HOURS: u32 = 24;

    let config = Config::from_env().context("invalid configuration")?;
    let pool = db::connect(&config.database_url, 1).await?;
    if config.run_migrations {
        db::migrate(&pool)
            .await
            .context("cannot apply database migrations")?;
    }
    let created = routes::admin::insert_invite(&pool, None, 1, VALID_HOURS, true)
        .await
        .map_err(|error| anyhow::anyhow!("cannot create the invitation: {}", error.message))?;
    pool.close().await;

    #[expect(
        clippy::print_stdout,
        reason = "the output of this command is its purpose"
    )]
    {
        println!("Administrator invitation code (single use, valid {VALID_HOURS} hours):");
        println!();
        println!("    {}", created.code);
        println!();
        println!("Register with it in the Tavern client. It is not shown again.");
    }
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
