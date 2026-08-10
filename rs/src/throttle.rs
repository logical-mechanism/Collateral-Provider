//! Per-IP rate limiting for the collateral endpoint.
//!
//! Port of DRF's `AnonRateThrottle`: a sliding-window log of request
//! timestamps per identity, allowing `num_requests` inside `period`.
//!
//! The Python service needed a *file-based* Django cache because gunicorn
//! runs several worker processes that must share the counter. The Rust
//! service is a single process, so the window lives in memory — same
//! semantics, no filesystem dependency, no cull-on-write cost.

use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Bound on distinct identities tracked at once. Beyond this the
/// oldest-touched identities are evicted.
///
/// Deliberately larger than the Python cache's `MAX_ENTRIES` of 2000
/// (`settings.py`): that value is a bound on a *file-based* cache, where each
/// entry is a file and culling costs a directory walk. An in-process map of
/// `(String, VecDeque<Instant>)` is cheap enough to hold an order of magnitude
/// more, and every evicted identity is one whose budget silently resets.
pub const DEFAULT_MAX_ENTRIES: usize = 20_000;

/// A `"<count>/<period>"` rate, where period is `sec`/`min`/`hour`/`day`
/// (DRF accepts any prefix of those words, e.g. `300/m`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThrottleRate {
    pub num_requests: u32,
    pub period: Duration,
}

impl FromStr for ThrottleRate {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let malformed = || {
            format!(
                "rate must be \"<count>/<period>\" with period one of sec/min/hour/day, got {value:?}"
            )
        };

        let (count, period) = value.trim().split_once('/').ok_or_else(malformed)?;
        // DRF unpacks `rate.split('/')` into exactly two names, so a third
        // segment is an error rather than an ignored suffix.
        if period.contains('/') {
            return Err(malformed());
        }

        let num_requests: u32 = count.trim().parse().map_err(|_| malformed())?;
        if num_requests == 0 {
            return Err(format!(
                "rate count must be greater than zero, got {value:?}"
            ));
        }

        // DRF indexes {'s','m','h','d'} by the period's FIRST character, so
        // "min", "m", and "minute" are the same rate. Keep that, including
        // its case sensitivity.
        let seconds = match period.trim().chars().next() {
            Some('s') => 1,
            Some('m') => 60,
            Some('h') => 3600,
            Some('d') => 86_400,
            _ => return Err(malformed()),
        };

        Ok(ThrottleRate {
            num_requests,
            period: Duration::from_secs(seconds),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleDecision {
    Allowed,
    /// Seconds until the caller may retry, rounded up as DRF does.
    Throttled {
        retry_after: u64,
    },
}

/// One identity's sliding window, oldest timestamp first.
struct Bucket {
    window: VecDeque<Instant>,
    /// Monotonic counter of the last time this identity was seen, used as the
    /// eviction key. Cheaper and more robust than storing another `Instant`.
    touched: u64,
}

struct Inner {
    buckets: HashMap<String, Bucket>,
    tick: u64,
}

pub struct Throttle {
    rate: ThrottleRate,
    max_entries: usize,
    inner: Mutex<Inner>,
}

impl Throttle {
    pub fn new(rate: ThrottleRate, max_entries: usize) -> Self {
        Throttle {
            rate,
            // A zero cap would evict every identity on sight and silently
            // disable the only abuse control this endpoint has.
            max_entries: max_entries.max(1),
            inner: Mutex::new(Inner {
                buckets: HashMap::new(),
                tick: 0,
            }),
        }
    }

    /// Record a request from `ident` and say whether it is allowed.
    pub fn allow(&self, ident: &str) -> ThrottleDecision {
        self.allow_at(ident, Instant::now())
    }

    /// Readiness probe. The Python service round-trips its throttle cache in
    /// `/healthz` because a collateral request cannot be served without it;
    /// the in-memory equivalent is checking the state is reachable (i.e. the
    /// lock is not poisoned).
    pub fn healthy(&self) -> bool {
        self.inner.lock().is_ok()
    }

    /// The decision logic, with the clock injected so tests can advance it.
    /// `Instant` only — a wall-clock jump backwards must not hand out a free
    /// window, and one forwards must not expire a live one.
    fn allow_at(&self, ident: &str, now: Instant) -> ThrottleDecision {
        let period = self.rate.period;
        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            // Nothing in this critical section can panic, but if it somehow
            // did, keep serving on the recovered state and let /healthz be
            // the thing that reports the process as unready.
            Err(poisoned) => poisoned.into_inner(),
        };
        let inner = &mut *guard;

        inner.tick += 1;
        let tick = inner.tick;

        if inner.buckets.len() >= self.max_entries && !inner.buckets.contains_key(ident) {
            evict(inner, self.max_entries, now, period);
        }

        let bucket = inner
            .buckets
            .entry(ident.to_owned())
            .or_insert_with(|| Bucket {
                window: VecDeque::new(),
                touched: tick,
            });
        bucket.touched = tick;

        // DRF pops while `history[-1] <= now - duration`, so an entry exactly
        // `period` old has already left the window.
        while let Some(oldest) = bucket.window.front() {
            if now.duration_since(*oldest) >= period {
                bucket.window.pop_front();
            } else {
                break;
            }
        }

        if bucket.window.len() >= self.rate.num_requests as usize {
            let remaining = bucket
                .window
                .front()
                .map(|oldest| period.saturating_sub(now.duration_since(*oldest)))
                .unwrap_or(period);
            return ThrottleDecision::Throttled {
                retry_after: ceil_secs(remaining),
            };
        }

        bucket.window.push_back(now);
        ThrottleDecision::Allowed
    }
}

/// `Throttled.__init__` does `math.ceil(wait)`, so a 0.2 s wait is advertised
/// as 1 s rather than 0 — never tell a client to retry immediately.
fn ceil_secs(duration: Duration) -> u64 {
    duration.as_secs() + u64::from(duration.subsec_nanos() > 0)
}

/// Make room for a new identity.
///
/// Two passes, cheapest first: identities whose window has fully aged out hold
/// no state worth keeping, and only if that is not enough do we drop the
/// least-recently-touched tenth. Trimming below the cap rather than to it
/// amortizes the O(n) sweep across many requests instead of paying it on each.
fn evict(inner: &mut Inner, max_entries: usize, now: Instant, period: Duration) {
    inner
        .buckets
        .retain(|_, bucket| match bucket.window.back() {
            Some(newest) => now.duration_since(*newest) < period,
            None => false,
        });
    if inner.buckets.len() < max_entries {
        return;
    }

    let target = (max_entries * 9 / 10).max(1);
    let excess = inner.buckets.len().saturating_sub(target).max(1);
    let mut ticks: Vec<u64> = inner
        .buckets
        .values()
        .map(|bucket| bucket.touched)
        .collect();
    let index = (excess - 1).min(ticks.len() - 1);
    ticks.select_nth_unstable(index);
    // Ticks are unique, so this drops exactly `index + 1` identities.
    let threshold = ticks[index];
    inner.buckets.retain(|_, bucket| bucket.touched > threshold);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate(text: &str) -> ThrottleRate {
        text.parse().expect("valid rate")
    }

    #[test]
    fn period_is_matched_by_its_first_character() {
        for text in ["300/s", "300/sec", "300/second"] {
            assert_eq!(rate(text).period, Duration::from_secs(1), "{text}");
        }
        for text in ["300/m", "300/min", "300/minute"] {
            assert_eq!(rate(text).period, Duration::from_secs(60), "{text}");
        }
        assert_eq!(rate("10/hour").period, Duration::from_secs(3600));
        assert_eq!(rate("10/day").period, Duration::from_secs(86_400));
        assert_eq!(rate("300/min").num_requests, 300);
    }

    #[test]
    fn malformed_rates_are_rejected() {
        for text in [
            "", "300", "/min", "300/", "300/x", "300/M", "abc/min", "300/m/x", "3.5/min", "-1/min",
        ] {
            assert!(text.parse::<ThrottleRate>().is_err(), "{text:?} parsed");
        }
    }

    #[test]
    fn zero_count_is_rejected() {
        // DRF would accept it and throttle everything; refusing at startup is
        // better than a service that answers 429 to every caller.
        assert!("0/min".parse::<ThrottleRate>().is_err());
    }

    #[test]
    fn allows_up_to_the_limit_then_throttles() {
        let throttle = Throttle::new(rate("3/min"), DEFAULT_MAX_ENTRIES);
        for _ in 0..3 {
            assert_eq!(throttle.allow("1.2.3.4"), ThrottleDecision::Allowed);
        }
        assert!(matches!(
            throttle.allow("1.2.3.4"),
            ThrottleDecision::Throttled { .. }
        ));
    }

    #[test]
    fn identities_are_independent() {
        let throttle = Throttle::new(rate("1/min"), DEFAULT_MAX_ENTRIES);
        assert_eq!(throttle.allow("1.2.3.4"), ThrottleDecision::Allowed);
        assert_eq!(throttle.allow("5.6.7.8"), ThrottleDecision::Allowed);
        assert!(matches!(
            throttle.allow("1.2.3.4"),
            ThrottleDecision::Throttled { .. }
        ));
    }

    #[test]
    fn retry_after_counts_down_to_the_oldest_entry_expiring() {
        let throttle = Throttle::new(rate("2/min"), DEFAULT_MAX_ENTRIES);
        let start = Instant::now();
        assert_eq!(throttle.allow_at("ip", start), ThrottleDecision::Allowed);
        assert_eq!(
            throttle.allow_at("ip", start + Duration::from_secs(10)),
            ThrottleDecision::Allowed
        );
        // Oldest entry is 20 s old, so 40 s remain on it.
        assert_eq!(
            throttle.allow_at("ip", start + Duration::from_secs(20)),
            ThrottleDecision::Throttled { retry_after: 40 }
        );
    }

    #[test]
    fn retry_after_rounds_up() {
        let throttle = Throttle::new(rate("1/min"), DEFAULT_MAX_ENTRIES);
        let start = Instant::now();
        throttle.allow_at("ip", start);
        assert_eq!(
            throttle.allow_at("ip", start + Duration::from_millis(59_500)),
            ThrottleDecision::Throttled { retry_after: 1 }
        );
    }

    #[test]
    fn the_window_slides() {
        let throttle = Throttle::new(rate("2/min"), DEFAULT_MAX_ENTRIES);
        let start = Instant::now();
        throttle.allow_at("ip", start);
        throttle.allow_at("ip", start + Duration::from_secs(1));
        assert!(matches!(
            throttle.allow_at("ip", start + Duration::from_secs(2)),
            ThrottleDecision::Throttled { .. }
        ));
        // An entry exactly `period` old is already gone, matching DRF's
        // `history[-1] <= now - duration`.
        assert_eq!(
            throttle.allow_at("ip", start + Duration::from_secs(60)),
            ThrottleDecision::Allowed
        );
    }

    #[test]
    fn an_active_identity_survives_churn_past_the_cap() {
        // The property the Python cache's MAX_ENTRIES override exists to
        // protect: a heavy hitter's counter must not be forgotten just
        // because many other IPs are also making requests. Total identities
        // here (25) exceed the cap (16), so eviction really runs.
        let throttle = Throttle::new(rate("3/min"), 16);
        let mut churn = 0;
        for _ in 0..3 {
            assert_eq!(throttle.allow("busy"), ThrottleDecision::Allowed);
            for _ in 0..8 {
                throttle.allow(&format!("churn-{churn}"));
                churn += 1;
            }
        }
        assert!(matches!(
            throttle.allow("busy"),
            ThrottleDecision::Throttled { .. }
        ));
    }

    #[test]
    fn tracked_identities_stay_bounded() {
        let max_entries = 32;
        let throttle = Throttle::new(rate("5/min"), max_entries);
        for index in 0..1000 {
            throttle.allow(&format!("ip-{index}"));
        }
        let tracked = throttle.inner.lock().expect("not poisoned").buckets.len();
        assert!(tracked <= max_entries, "tracked {tracked}");
    }

    #[test]
    fn fully_expired_identities_are_reclaimed_before_live_ones() {
        let max_entries = 8;
        let throttle = Throttle::new(rate("5/min"), max_entries);
        let start = Instant::now();
        for index in 0..max_entries {
            throttle.allow_at(&format!("old-{index}"), start);
        }
        // A minute later every stored window has aged out, so the newcomer
        // costs nothing but the sweep.
        let later = start + Duration::from_secs(61);
        assert_eq!(throttle.allow_at("fresh", later), ThrottleDecision::Allowed);
        let inner = throttle.inner.lock().expect("not poisoned");
        assert_eq!(inner.buckets.len(), 1);
        assert!(inner.buckets.contains_key("fresh"));
    }

    #[test]
    fn healthy_when_state_is_reachable() {
        let throttle = Throttle::new(rate("300/min"), DEFAULT_MAX_ENTRIES);
        assert!(throttle.healthy());
    }
}
