// SPDX-License-Identifier: AGPL-3.0-or-later

//! Harness for the end-to-end tests: starts the real server in-process on an
//! ephemeral port, against a real PostgreSQL database, and hands out real
//! clients (`tavern-client-core`) with in-memory secret stores.
//!
//! Nothing here is used in production. The tests need PostgreSQL:
//!
//! ```sh
//! TAVERN_TEST_DATABASE_URL=postgres://... cargo test -p tavern-e2e-tests -- --ignored
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "a test harness panics on set-up failure"
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tavern_client_core::local::ProfileLock;
use tavern_client_core::{GatewayEvent, InstanceClient, InstanceUrl, MemoryStore};
use tavern_server::secrets::InstanceSecrets;
use tavern_server::{AppState, Settings, app, db, routes};
use tokio::net::TcpListener;
use tokio::sync::mpsc::Receiver;

/// Environment variable holding the test database URL.
pub const DATABASE_URL_VAR: &str = "TAVERN_TEST_DATABASE_URL";

/// How long a request of a test server waits for a database connection.
/// The tests share one PostgreSQL, which at times is slow to open their
/// connections (right after a build, under load): five seconds, the
/// server's own limit, made registrations fail for that reason alone.
pub const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(60);
/// The URL of the test database, from `TAVERN_TEST_DATABASE_URL`.
///
/// Tests create accounts by the hundred and rewrite rows at will, so they
/// refuse any database whose name does not end in `_test`: the database of a
/// development stack, with the accounts used for manual testing, is never
/// touched. `deploy/scripts/test-db.sh` creates one and prints its URL.
pub fn database_url() -> String {
    let url = std::env::var(DATABASE_URL_VAR)
        .unwrap_or_else(|_| panic!("{DATABASE_URL_VAR} must be set to run this test"));
    let name = url
        .rsplit('/')
        .next()
        .and_then(|rest| rest.split('?').next())
        .unwrap_or_default();
    assert!(
        name.ends_with("_test"),
        "{DATABASE_URL_VAR} names the database \"{name}\": tests only run on a database \
         whose name ends in _test (see deploy/scripts/test-db.sh)"
    );
    url
}

/// A password that meets the strength requirement.
pub const PASSWORD: &str = "tournesol-vexant-42-brume";

/// A computer's local data directory and a profile.
type ProfileKey = (PathBuf, Option<String>);

/// A running server.
pub struct Server {
    /// Where it listens.
    pub addr: SocketAddr,
    /// Its state, for assertions on the database.
    pub state: AppState,
    /// The local data directories of the simulated computers, deleted with
    /// the server.
    data: tempfile::TempDir,
    /// The hold of each profile of each computer: one per window of the
    /// application, shared here by the clients of one computer and profile.
    locks: std::sync::Mutex<HashMap<ProfileKey, Arc<ProfileLock>>>,
}

impl Server {
    /// Starts a server with fresh instance secrets.
    pub async fn spawn() -> Self {
        let database_url = database_url();
        let pool = db::connect_with_acquire_timeout(&database_url, 5, ACQUIRE_TIMEOUT)
            .await
            .expect("database must be reachable");
        db::migrate(&pool).await.expect("migrations must apply");

        let generated: HashMap<String, String> = InstanceSecrets::generate()
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        let secrets = InstanceSecrets::from_lookup(|name| generated.get(name).cloned()).unwrap();
        let state = AppState::new(
            pool,
            secrets,
            Settings {
                // Scenarios sign in many times with one account. Rate limiting
                // itself is covered by the server's own tests.
                auth_per_ip_per_minute: 10_000,
                auth_per_handle_per_minute: 10_000,
                ..Settings::new(None, false, Duration::from_secs(3600))
            },
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = app(state.clone());
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let data = tempfile::tempdir().expect("a temporary directory");
        Self {
            addr,
            state,
            data,
            locks: std::sync::Mutex::default(),
        }
    }

    /// A client on a computer that has never been used: empty secret store.
    pub fn new_computer(&self) -> InstanceClient {
        self.new_computer_with_store().0
    }

    /// Same, with access to the computer's secret store, to check what it
    /// keeps.
    pub fn new_computer_with_store(&self) -> (InstanceClient, Arc<MemoryStore>) {
        let store = Arc::new(MemoryStore::default());
        (self.computer(&store, None), store)
    }

    /// Another client on a computer whose secret store is `store`, under
    /// `profile`. A computer is its secret store: the same store always comes
    /// with the same local data directory.
    pub fn computer(&self, store: &Arc<MemoryStore>, profile: Option<&str>) -> InstanceClient {
        let url = InstanceUrl::parse(&format!("http://{}", self.addr)).unwrap();
        let local_data = self.local_data(store);
        let lock = Arc::clone(
            self.locks
                .lock()
                .unwrap()
                .entry((local_data.clone(), profile.map(str::to_owned)))
                .or_insert_with(|| Arc::new(ProfileLock::acquire(&local_data, profile).unwrap())),
        );
        InstanceClient::new(url, store.clone(), lock).unwrap()
    }

    /// The local data directory of the computer whose secret store is `store`.
    pub fn local_data(&self, store: &Arc<MemoryStore>) -> PathBuf {
        self.data
            .path()
            .join(format!("computer-{:p}", Arc::as_ptr(store)))
    }

    /// Creates an invitation on the host, as `create-admin.sh` does.
    pub async fn host_invite(&self, grants_admin: bool) -> String {
        routes::admin::insert_invite(&self.state.db, None, 1, 24, grants_admin)
            .await
            .unwrap()
            .code
    }
}

/// A handle that no other test uses.
pub fn random_handle(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    format!(
        "{prefix}_{}_{nanos:x}",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Waits for the next gateway event, failing the test after five seconds.
pub async fn next_event(events: &mut Receiver<GatewayEvent>) -> GatewayEvent {
    tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("no gateway event arrived in time")
        .expect("the gateway stopped")
}
