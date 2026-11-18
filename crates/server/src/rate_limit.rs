// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rate limiting.
//!
//! The authentication routes are limited per client address and per handle;
//! KeyPackage claims per requesting user and per (requester, target) pair
//! (ADR 0019, section 3). Counters live in memory only, and start from zero
//! when the server restarts. Client addresses are never logged or stored.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;
use governor::clock::{Clock, DefaultClock};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use tavern_protocol::handle::Handle;
use uuid::Uuid;

use crate::AppState;
use crate::config::ClaimLimits;
use crate::error::{ApiError, ApiResult};

/// Requests per minute and per address on `/v1/auth/*`.
pub const AUTH_PER_IP_PER_MINUTE: u32 = 30;
/// Attempts per minute and per handle (login, recovery, registration).
pub const AUTH_PER_HANDLE_PER_MINUTE: u32 = 5;
/// Above this many tracked keys, idle ones are dropped.
const PRUNE_THRESHOLD: usize = 10_000;

/// The limiters of an instance.
pub struct RateLimits {
    per_ip: DefaultKeyedRateLimiter<IpAddr>,
    per_handle: DefaultKeyedRateLimiter<String>,
    clock: DefaultClock,
    /// KeyPackage claims.
    pub claims: ClaimLimiter,
}

impl std::fmt::Debug for RateLimits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RateLimits")
    }
}

fn per_minute(count: u32) -> Quota {
    Quota::per_minute(NonZeroU32::new(count).unwrap_or(NonZeroU32::MIN))
}

impl Default for RateLimits {
    fn default() -> Self {
        Self::new(
            AUTH_PER_IP_PER_MINUTE,
            AUTH_PER_HANDLE_PER_MINUTE,
            ClaimLimits::default(),
        )
    }
}

impl RateLimits {
    /// Creates limiters with the given authentication quotas per minute,
    /// and the given claim limits.
    pub fn new(per_ip: u32, per_handle: u32, claims: ClaimLimits) -> Self {
        Self {
            per_ip: RateLimiter::keyed(per_minute(per_ip)),
            per_handle: RateLimiter::keyed(per_minute(per_handle)),
            clock: DefaultClock::default(),
            claims: ClaimLimiter::new(claims),
        }
    }

    /// Counts one request from `ip`.
    pub fn check_ip(&self, ip: IpAddr) -> ApiResult<()> {
        if self.per_ip.len() > PRUNE_THRESHOLD {
            self.per_ip.retain_recent();
        }
        self.per_ip
            .check_key(&ip)
            .map_err(|not_until| self.rejection(&not_until))
    }

    /// Counts one attempt against `handle`, whether or not the account exists.
    pub fn check_handle(&self, handle: &Handle) -> ApiResult<()> {
        if self.per_handle.len() > PRUNE_THRESHOLD {
            self.per_handle.retain_recent();
        }
        self.per_handle
            .check_key(&handle.as_str().to_owned())
            .map_err(|not_until| self.rejection(&not_until))
    }

    fn rejection(
        &self,
        not_until: &governor::NotUntil<<DefaultClock as Clock>::Instant>,
    ) -> ApiError {
        let wait = not_until.wait_time_from(self.clock.now());
        ApiError::rate_limited(u64::try_from(wait.as_millis()).unwrap_or(u64::MAX).max(1))
    }
}

const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(24 * 3600);

/// Recent events per key, oldest first, none older than a day.
struct Recent<K>(Mutex<HashMap<K, VecDeque<Instant>>>);

impl<K: Eq + Hash + Clone> Recent<K> {
    fn new() -> Self {
        Self(Mutex::new(HashMap::new()))
    }

    /// Runs `decide` on the recent events of `key` at `now`, and records one
    /// more event if it allows it.
    fn admit(
        &self,
        key: &K,
        now: Instant,
        decide: impl FnOnce(&VecDeque<Instant>) -> Result<(), Duration>,
    ) -> Result<(), Duration> {
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if map.len() > PRUNE_THRESHOLD {
            map.retain(|_, events| {
                forget_before(events, now);
                !events.is_empty()
            });
        }
        let events = map.entry(key.clone()).or_default();
        forget_before(events, now);
        decide(events)?;
        events.push_back(now);
        Ok(())
    }
}

fn forget_before(events: &mut VecDeque<Instant>, now: Instant) {
    while events
        .front()
        .is_some_and(|&at| now.saturating_duration_since(at) >= DAY)
    {
        events.pop_front();
    }
}

/// Whether `events` (oldest first) leave room for one more within `window`:
/// at most `limit` in any such window. Otherwise, how long until there is.
fn room(
    events: &VecDeque<Instant>,
    now: Instant,
    window: Duration,
    limit: u32,
) -> Result<(), Duration> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let inside = events
        .iter()
        .rev()
        .take_while(|&&at| now.saturating_duration_since(at) < window)
        .count();
    if inside < limit {
        return Ok(());
    }
    // The room comes back when the oldest of the last `limit` leaves.
    let oldest = events
        .len()
        .checked_sub(limit)
        .and_then(|index| events.get(index))
        .copied()
        .unwrap_or(now);
    Err((oldest + window).saturating_duration_since(now))
}

/// The KeyPackage claim limits (ADR 0019, section 3), counted exactly over
/// sliding windows: "3 an hour" means at most 3 in any hour, which a token
/// bucket would not guarantee. Counters live in memory, and start from zero
/// when the server restarts.
pub struct ClaimLimiter {
    limits: ClaimLimits,
    by_requester: Recent<Uuid>,
    by_pair: Recent<(Uuid, Uuid)>,
}

impl ClaimLimiter {
    fn new(limits: ClaimLimits) -> Self {
        Self {
            limits,
            by_requester: Recent::new(),
            by_pair: Recent::new(),
        }
    }

    /// Counts one claim by `requester`, whoever the target.
    pub fn check_requester(&self, requester: Uuid) -> ApiResult<()> {
        self.check_requester_at(requester, Instant::now())
    }

    /// Counts one claim by `requester` of another user's KeyPackages. A
    /// claim refused by either limit counts against neither.
    pub fn check_pair(&self, requester: Uuid, target: Uuid) -> ApiResult<()> {
        self.check_pair_at(requester, target, Instant::now())
    }

    fn check_requester_at(&self, requester: Uuid, now: Instant) -> ApiResult<()> {
        let limit = self.limits.per_requester_per_hour;
        self.by_requester
            .admit(&requester, now, |events| room(events, now, HOUR, limit))
            .map_err(refused_for)
    }

    fn check_pair_at(&self, requester: Uuid, target: Uuid, now: Instant) -> ApiResult<()> {
        let ClaimLimits {
            per_pair_per_hour,
            per_pair_per_day,
            ..
        } = self.limits;
        self.by_pair
            .admit(&(requester, target), now, |events| {
                let hour = room(events, now, HOUR, per_pair_per_hour);
                let day = room(events, now, DAY, per_pair_per_day);
                match (hour, day) {
                    (Ok(()), Ok(())) => Ok(()),
                    (Err(wait), Ok(())) | (Ok(()), Err(wait)) => Err(wait),
                    (Err(a), Err(b)) => Err(a.max(b)),
                }
            })
            .map_err(refused_for)
    }
}

fn refused_for(wait: Duration) -> ApiError {
    ApiError::rate_limited(u64::try_from(wait.as_millis()).unwrap_or(u64::MAX).max(1))
}

/// The address a request is attributed to for rate limiting.
///
/// Behind the reference deployment's Caddy, the TCP peer is always Caddy. When
/// `TAVERN_TRUST_FORWARDED_FOR` is set, the address is therefore the **last**
/// entry of `X-Forwarded-For`: the one appended by the proxy itself. Earlier
/// entries are whatever the client sent and are never trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

/// Picks the address appended by the nearest proxy.
pub fn last_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get_all("x-forwarded-for")
        .iter()
        .next_back()?
        .to_str()
        .ok()?
        .rsplit(',')
        .next()?
        .trim()
        .parse()
        .ok()
}

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
            .ok_or_else(|| ApiError::internal("client address", &"missing connect info"))?;

        if state.settings.trust_forwarded_for
            && let Some(forwarded) = last_forwarded_for(&parts.headers)
        {
            return Ok(Self(forwarded));
        }
        Ok(Self(peer))
    }
}

/// Middleware: applies the per-address limit.
pub async fn limit_by_ip(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    state.rate_limits.check_ip(ip)?;
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use tavern_protocol::rest::ErrorCode;

    use super::*;

    fn headers(values: &[&'static str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for value in values {
            map.append("x-forwarded-for", HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn the_last_forwarded_address_is_used() {
        let expected: IpAddr = "203.0.113.7".parse().unwrap();

        assert_eq!(
            last_forwarded_for(&headers(&["203.0.113.7"])),
            Some(expected)
        );
        // A client-supplied value comes first; the proxy appends the real one.
        assert_eq!(
            last_forwarded_for(&headers(&["10.0.0.1, 203.0.113.7"])),
            Some(expected)
        );
        assert_eq!(
            last_forwarded_for(&headers(&["1.1.1.1, 2.2.2.2", "10.0.0.1 , 203.0.113.7 "])),
            Some(expected)
        );
        assert_eq!(
            last_forwarded_for(&headers(&["203.0.113.7, 2001:db8::1"])),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn a_spoofed_first_entry_never_wins() {
        let spoofed: IpAddr = "127.0.0.1".parse().unwrap();

        assert_ne!(
            last_forwarded_for(&headers(&["127.0.0.1, 203.0.113.7"])),
            Some(spoofed)
        );
    }

    #[test]
    fn missing_or_malformed_headers_yield_nothing() {
        assert_eq!(last_forwarded_for(&HeaderMap::new()), None);
        assert_eq!(last_forwarded_for(&headers(&["not an address"])), None);
        assert_eq!(
            last_forwarded_for(&headers(&["203.0.113.7, garbage"])),
            None
        );
        assert_eq!(last_forwarded_for(&headers(&[""])), None);
    }

    fn minutes(start: Instant, minutes: u64) -> Instant {
        start + Duration::from_secs(minutes * 60)
    }

    #[test]
    fn claims_of_a_pair_are_counted_over_any_hour_and_any_day() {
        let limiter = ClaimLimiter::new(ClaimLimits {
            per_requester_per_hour: 60,
            per_pair_per_hour: 3,
            per_pair_per_day: 10,
        });
        let (alice, bob, carol) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let start = Instant::now();
        let at = |m| minutes(start, m);

        // Three in an hour, then nothing until the first is an hour old.
        for minute in [0, 1, 2] {
            assert!(limiter.check_pair_at(alice, bob, at(minute)).is_ok());
        }
        let refused = limiter.check_pair_at(alice, bob, at(30)).unwrap_err();
        assert_eq!(refused.code, ErrorCode::RateLimited);
        assert_eq!(refused.retry_after_ms, Some(30 * 60 * 1000));
        // Per target and per requester: other pairs are not affected.
        assert!(limiter.check_pair_at(alice, carol, at(30)).is_ok());
        assert!(limiter.check_pair_at(bob, alice, at(30)).is_ok());

        // Ten in any day. The refused attempt above counted for nothing:
        // seven more fit, one an hour.
        for hour in 1..=7 {
            assert!(
                limiter.check_pair_at(alice, bob, at(hour * 60 + 5)).is_ok(),
                "hour {hour}"
            );
        }
        let refused = limiter.check_pair_at(alice, bob, at(9 * 60)).unwrap_err();
        assert_eq!(
            refused.retry_after_ms,
            Some((24 - 9) * 3600 * 1000),
            "until the first claim is a day old"
        );
        assert!(limiter.check_pair_at(alice, bob, at(24 * 60)).is_ok());
    }

    #[test]
    fn every_claim_counts_against_its_requester() {
        let limiter = ClaimLimiter::new(ClaimLimits {
            per_requester_per_hour: 2,
            per_pair_per_hour: 3,
            per_pair_per_day: 10,
        });
        let (alice, bob) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let start = Instant::now();

        assert!(limiter.check_requester_at(alice, start).is_ok());
        assert!(limiter.check_requester_at(alice, minutes(start, 1)).is_ok());
        assert!(
            limiter
                .check_requester_at(alice, minutes(start, 2))
                .is_err()
        );
        assert!(limiter.check_requester_at(bob, minutes(start, 2)).is_ok());
        assert!(
            limiter
                .check_requester_at(alice, minutes(start, 60))
                .is_ok()
        );
    }

    #[test]
    fn limits_are_per_key_and_report_a_delay() {
        let limits = RateLimits::new(2, 1, ClaimLimits::default());
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let b: IpAddr = "203.0.113.2".parse().unwrap();

        assert!(limits.check_ip(a).is_ok());
        assert!(limits.check_ip(a).is_ok());
        let error = limits.check_ip(a).unwrap_err();
        assert_eq!(error.code, ErrorCode::RateLimited);
        assert!(error.retry_after_ms.unwrap() > 0);
        assert!(limits.check_ip(b).is_ok());

        let alice = Handle::parse_canonical("alice").unwrap();
        let bob = Handle::parse_canonical("bob").unwrap();
        assert!(limits.check_handle(&alice).is_ok());
        assert!(limits.check_handle(&alice).is_err());
        assert!(limits.check_handle(&bob).is_ok());
    }
}
