//! Reverse-DNS resolution (A4): a bounded async pool over the OS resolver, with
//! timeouts and a cache that remembers *absences* too — PTR records frequently
//! don't exist, and re-asking for one that doesn't is the expensive mistake
//! (PITFALLS A4).
//!
//! ## How it fits the capture loop
//!
//! [`lookup`](DnsResolver::lookup) is synchronous and cheap — it just reads the
//! cache, so the capture thread never blocks on the network. A cache miss is
//! handed to [`request`](DnsResolver::request), which spawns one bounded,
//! timed-out lookup on the Tokio runtime; when it lands in the cache, the next
//! poll's flow picks up the name and the diff emits it. Concurrency is capped by a
//! semaphore (the "pool"), and an in-flight set keeps repeated polls from spawning
//! duplicate lookups for the same address.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::sync::Semaphore;

/// Max concurrent reverse lookups in flight.
const MAX_CONCURRENT: usize = 8;
/// Per-lookup timeout — the OS resolver can hang on a dead DNS server.
const TIMEOUT: Duration = Duration::from_secs(2);
/// Cap the cache so a long session against many peers can't grow it without bound.
const MAX_CACHE: usize = 8192;

/// The blocking resolve step, injectable so tests don't touch the network.
type ResolveFn = Arc<dyn Fn(IpAddr) -> Option<String> + Send + Sync>;

pub struct DnsResolver {
    handle: Handle,
    sem: Arc<Semaphore>,
    /// `ip → Some(name)` resolved, or `ip → None` for a cached *absence*.
    cache: Arc<Mutex<HashMap<IpAddr, Option<String>>>>,
    /// Addresses with a lookup currently spawned — dedupes repeated requests.
    inflight: Arc<Mutex<HashSet<IpAddr>>>,
    resolve: ResolveFn,
}

impl DnsResolver {
    pub fn new(handle: Handle) -> Self {
        Self::with_resolver(handle, Arc::new(system_reverse_dns))
    }

    pub fn with_resolver(handle: Handle, resolve: ResolveFn) -> Self {
        Self {
            handle,
            sem: Arc::new(Semaphore::new(MAX_CONCURRENT)),
            cache: Arc::new(Mutex::new(HashMap::new())),
            inflight: Arc::new(Mutex::new(HashSet::new())),
            resolve,
        }
    }

    /// Read the cache. `Some(Some(name))` = resolved; `Some(None)` = known to have
    /// no PTR; `None` = not looked up yet.
    pub fn lookup(&self, ip: IpAddr) -> Option<Option<String>> {
        self.cache.lock().unwrap().get(&ip).cloned()
    }

    /// Spawn a bounded, timed-out reverse lookup if one isn't already cached or in
    /// flight. Returns immediately — the capture thread never waits.
    pub fn request(&self, ip: IpAddr) {
        // Already known, or already being resolved → nothing to do.
        if self.cache.lock().unwrap().contains_key(&ip) {
            return;
        }
        if !self.inflight.lock().unwrap().insert(ip) {
            return;
        }

        let sem = Arc::clone(&self.sem);
        let cache = Arc::clone(&self.cache);
        let inflight = Arc::clone(&self.inflight);
        let resolve = Arc::clone(&self.resolve);

        self.handle.spawn(async move {
            // Hold a permit for the duration of the (blocking) lookup.
            let _permit = sem.acquire().await;
            let res =
                tokio::time::timeout(TIMEOUT, tokio::task::spawn_blocking(move || resolve(ip)))
                    .await;
            // Timeout or a join error both cache as a (negative) absence — better
            // than re-hammering a hung resolver.
            let name = match res {
                Ok(Ok(name)) => name,
                _ => None,
            };
            {
                let mut c = cache.lock().unwrap();
                // Bound memory, but always cache the result. Refusing to insert
                // when full would leave this ip uncached, so every later poll would
                // re-spawn a lookup for it — a lookup storm. Evict an arbitrary
                // entry to make room instead.
                if c.len() >= MAX_CACHE {
                    if let Some(evict) = c.keys().next().copied() {
                        c.remove(&evict);
                    }
                }
                c.insert(ip, name);
            }
            inflight.lock().unwrap().remove(&ip);
        });
    }
}

/// The real reverse lookup via the OS resolver (`getnameinfo`). A result equal to
/// the IP string (no PTR), an empty string, or an error all mean "no name".
fn system_reverse_dns(ip: IpAddr) -> Option<String> {
    match dns_lookup::lookup_addr(&ip) {
        Ok(name) if !name.is_empty() && name != ip.to_string() => Some(name),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    /// Poll the cache until populated (or a deadline) without an async test harness.
    fn wait_cached(r: &DnsResolver, ip: IpAddr) -> Option<String> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(v) = r.lookup(ip) {
                return v;
            }
            if Instant::now() > deadline {
                panic!("lookup never cached");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn resolves_and_caches() {
        let rt = rt();
        let r = DnsResolver::with_resolver(
            rt.handle().clone(),
            Arc::new(|_| Some("host.example".into())),
        );
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        assert_eq!(r.lookup(ip), None); // not yet
        r.request(ip);
        assert_eq!(wait_cached(&r, ip).as_deref(), Some("host.example"));
    }

    #[test]
    fn caches_absence() {
        let rt = rt();
        let r = DnsResolver::with_resolver(rt.handle().clone(), Arc::new(|_| None));
        let ip: IpAddr = "203.0.113.11".parse().unwrap();
        r.request(ip);
        // Cached as a (None) absence — present in the cache, but no name.
        assert_eq!(wait_cached(&r, ip), None);
        assert_eq!(r.lookup(ip), Some(None));
    }

    #[test]
    fn dedupes_inflight_requests() {
        let rt = rt();
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let r = DnsResolver::with_resolver(
            rt.handle().clone(),
            Arc::new(move |_| {
                c.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(50));
                Some("once.example".into())
            }),
        );
        let ip: IpAddr = "203.0.113.12".parse().unwrap();
        // Many requests before the first resolves should spawn exactly one lookup.
        for _ in 0..20 {
            r.request(ip);
        }
        assert_eq!(wait_cached(&r, ip).as_deref(), Some("once.example"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
