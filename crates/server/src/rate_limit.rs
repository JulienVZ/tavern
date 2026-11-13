// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rate limiting of the authentication routes.
//!
//! Two limits apply: per client address and per handle. Counters live in
//! memory only. Client addresses are never logged or stored.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;

use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;
use governor::clock::{Clock, DefaultClock};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use tavern_protocol::handle::Handle;

use crate::AppState;
use crate::error::{ApiError, ApiResult};

/// Requests per minute and per address on `/v1/auth/*`.
const AUTH_PER_IP_PER_MINUTE: u32 = 30;
/// Attempts per minute and per handle (login, recovery, registration).
const AUTH_PER_HANDLE_PER_MINUTE: u32 = 5;
/// Above this many tracked keys, idle ones are dropped.
const PRUNE_THRESHOLD: usize = 10_000;

/// The limiters of an instance.
pub struct RateLimits {
    per_ip: DefaultKeyedRateLimiter<IpAddr>,
    per_handle: DefaultKeyedRateLimiter<String>,
    clock: DefaultClock,
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
        Self::new(AUTH_PER_IP_PER_MINUTE, AUTH_PER_HANDLE_PER_MINUTE)
    }
}

impl RateLimits {
    /// Creates limiters with the given quotas per minute.
    pub fn new(per_ip: u32, per_handle: u32) -> Self {
        Self {
            per_ip: RateLimiter::keyed(per_minute(per_ip)),
            per_handle: RateLimiter::keyed(per_minute(per_handle)),
            clock: DefaultClock::default(),
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

    #[test]
    fn limits_are_per_key_and_report_a_delay() {
        let limits = RateLimits::new(2, 1);
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
