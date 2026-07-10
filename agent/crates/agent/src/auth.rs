//! # C2 — pairing codes + bearer tokens for the remote path
//!
//! The agent's WebSocket on `127.0.0.1:8787` is reachable only over loopback and
//! is gated by the `Origin` check (`main.rs`). That is enough for the *local*
//! client, where the browser's same-origin honesty and the loopback bind are the
//! boundary. A **remote** client (the C3 tailnet path) has no such locality, so
//! it must present a credential. This module is that credential's lifecycle.
//!
//! The flow (documented adversarially in `docs/threat-model.md`):
//!
//! 1. the agent mints a short-lived **pairing code** — six digits, shown only on
//!    the agent host (printed on start; served to the trusted local UI);
//! 2. the remote device exchanges the code for a long-lived **token** over TLS
//!    (`POST /pair`). The code is **single-use** and expires in 60 s, and a code
//!    is burned after a handful of wrong guesses so the 10⁶ space can't be
//!    brute-forced online inside its window (PITFALLS C2);
//! 3. every remote WebSocket presents the token and is validated on the handshake.
//!
//! **Tokens are stored only as SHA-256 hashes.** A disclosure of the agent's auth
//! set therefore never yields a usable bearer credential; validation hashes the
//! presented token and looks the hash up. Revocation drops the hash — the next
//! handshake from that device fails.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use sha2::{Digest, Sha256};

/// Pairing-code lifetime. Short by design: a code is a low-entropy secret typed
/// across a possibly-hostile network, so its window is the dominant interception
/// surface. 60 s, single-use.
const PAIRING_TTL: Duration = Duration::from_secs(60);

/// Wrong guesses a single pairing code tolerates before it is burned. With a
/// 10⁶ code space and a 60 s TTL, an unbounded online guesser is the real risk;
/// capping attempts closes it without hurting a human who fat-fingers once.
const MAX_PAIRING_ATTEMPTS: u8 = 5;

/// A pairing code handed to the local UI for display.
pub struct PairingCode {
    pub code: String,
    pub expires_in_secs: u64,
}

/// The agent's auth state: the (at most one) live pairing code and the set of
/// issued token hashes. Behind a single `Mutex` — contention is nil (auth events
/// are human-paced), and one lock keeps the code/token invariants atomic.
pub struct AuthState {
    inner: Mutex<Inner>,
    ttl: Duration,
}

struct Inner {
    pairing: Option<Pairing>,
    token_hashes: HashSet<[u8; 32]>,
}

struct Pairing {
    code: String,
    expires: Instant,
    attempts_left: u8,
}

impl AuthState {
    pub fn new() -> Self {
        Self::with_ttl(PAIRING_TTL)
    }

    fn with_ttl(ttl: Duration) -> Self {
        AuthState {
            inner: Mutex::new(Inner {
                pairing: None,
                token_hashes: HashSet::new(),
            }),
            ttl,
        }
    }

    /// The current pairing code, minting a fresh one only if none is live.
    /// Idempotent within the TTL so the local UI can poll/redisplay it without
    /// invalidating a code the user is mid-way through typing elsewhere.
    pub fn current_code(&self) -> PairingCode {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        let live = matches!(&inner.pairing, Some(p) if p.expires > now);
        if !live {
            inner.pairing = Some(self.fresh_pairing(now));
        }
        let p = inner.pairing.as_ref().expect("just ensured live");
        PairingCode {
            code: p.code.clone(),
            expires_in_secs: p.expires.saturating_duration_since(now).as_secs(),
        }
    }

    /// Force a fresh code, invalidating any prior one (the "show a new code" control).
    pub fn rotate_code(&self) -> PairingCode {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        let p = self.fresh_pairing(now);
        let out = PairingCode {
            code: p.code.clone(),
            expires_in_secs: p.expires.saturating_duration_since(now).as_secs(),
        };
        inner.pairing = Some(p);
        out
    }

    /// Exchange a code for a token. Single-use: a successful redeem consumes the
    /// code. A wrong guess decrements the attempt budget and burns the code at
    /// zero. Returns `None` on any unknown/expired/exhausted code.
    pub fn redeem(&self, code: &str) -> Option<String> {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();

        // Take the pairing out; we put it back only if it survives this attempt.
        let mut pairing = inner.pairing.take()?;
        if pairing.expires <= now {
            return None; // expired — already removed
        }
        if constant_time_eq(pairing.code.as_bytes(), code.as_bytes()) {
            let token = mint_token();
            inner.token_hashes.insert(sha256(token.as_bytes()));
            return Some(token); // code consumed (not put back)
        }
        // Wrong guess: spend an attempt; keep the code only if budget remains.
        pairing.attempts_left = pairing.attempts_left.saturating_sub(1);
        if pairing.attempts_left > 0 {
            inner.pairing = Some(pairing);
        }
        None
    }

    /// True when `token` is a live issued token.
    pub fn validate(&self, token: &str) -> bool {
        let hash = sha256(token.as_bytes());
        self.inner.lock().unwrap().token_hashes.contains(&hash)
    }

    /// De-authorize every paired device. Returns how many tokens were dropped.
    pub fn revoke_all(&self) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let n = inner.token_hashes.len();
        inner.token_hashes.clear();
        n
    }

    fn fresh_pairing(&self, now: Instant) -> Pairing {
        Pairing {
            code: mint_code(),
            expires: now + self.ttl,
            attempts_left: MAX_PAIRING_ATTEMPTS,
        }
    }
}

impl Default for AuthState {
    fn default() -> Self {
        Self::new()
    }
}

/// A 256-bit token, base64url (no padding) — URL/header-safe and a valid
/// WebSocket subprotocol token, so it can ride the `Sec-WebSocket-Protocol`
/// header (the only header a browser can set on the WS handshake).
fn mint_token() -> String {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// A six-digit pairing code, drawn uniformly from `000000..=999999` by rejection
/// sampling (no modulo bias).
fn mint_code() -> String {
    loop {
        let mut b = [0u8; 4];
        fill_random(&mut b);
        let n = u32::from_le_bytes(b);
        // Largest multiple of 1_000_000 that fits in u32; reject above it.
        const LIMIT: u32 = (u32::MAX / 1_000_000) * 1_000_000;
        if n < LIMIT {
            return format!("{:06}", n % 1_000_000);
        }
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Fill `buf` from the OS CSPRNG. A failure here means the platform RNG is
/// unavailable — a non-recoverable security condition, so we refuse to run rather
/// than mint a guessable secret.
fn fill_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

/// Length-independent byte comparison. The pairing code is low-entropy and
/// already attempt-capped, but comparing it in constant time costs nothing and
/// keeps the same primitive available for any future secret compare.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_six_digits() {
        let c = AuthState::new().current_code();
        assert_eq!(c.code.len(), 6);
        assert!(c.code.chars().all(|ch| ch.is_ascii_digit()));
        assert!(c.expires_in_secs <= 60 && c.expires_in_secs > 0);
    }

    #[test]
    fn current_code_is_stable_within_ttl() {
        let auth = AuthState::new();
        assert_eq!(auth.current_code().code, auth.current_code().code);
    }

    #[test]
    fn rotate_changes_the_code_and_invalidates_the_old() {
        let auth = AuthState::new();
        let old = auth.current_code().code;
        let new = auth.rotate_code().code;
        // Astronomically unlikely to collide, but redeeming the old must fail.
        assert!(auth.redeem(&old).is_none());
        assert!(new != old || auth.redeem(&new).is_some());
    }

    #[test]
    fn redeem_is_single_use_and_yields_a_valid_token() {
        let auth = AuthState::new();
        let code = auth.current_code().code;
        let token = auth.redeem(&code).expect("valid code redeems");
        assert!(auth.validate(&token));
        // The code is burned; a second redeem of it fails.
        assert!(auth.redeem(&code).is_none());
    }

    #[test]
    fn wrong_code_never_validates_and_burns_after_max_attempts() {
        let auth = AuthState::new();
        let real = auth.current_code().code;
        let wrong = if real == "000000" { "111111" } else { "000000" };
        for _ in 0..super::MAX_PAIRING_ATTEMPTS {
            assert!(auth.redeem(wrong).is_none());
        }
        // Budget exhausted: even the correct code no longer redeems (burned).
        assert!(auth.redeem(&real).is_none());
    }

    #[test]
    fn unknown_token_does_not_validate() {
        let auth = AuthState::new();
        assert!(!auth.validate("not-a-real-token"));
    }

    #[test]
    fn revoke_all_deauthorizes_every_token() {
        let auth = AuthState::new();
        let t1 = auth.redeem(&auth.current_code().code).unwrap();
        let t2 = auth.redeem(&auth.rotate_code().code).unwrap();
        assert!(auth.validate(&t1) && auth.validate(&t2));
        assert_eq!(auth.revoke_all(), 2);
        assert!(!auth.validate(&t1) && !auth.validate(&t2));
    }

    #[test]
    fn expired_code_does_not_redeem() {
        let auth = AuthState::with_ttl(Duration::from_millis(10));
        let code = auth.current_code().code;
        std::thread::sleep(Duration::from_millis(25));
        assert!(auth.redeem(&code).is_none());
    }

    #[test]
    fn tokens_are_distinct() {
        let auth = AuthState::new();
        let t1 = auth.redeem(&auth.current_code().code).unwrap();
        let t2 = auth.redeem(&auth.rotate_code().code).unwrap();
        assert_ne!(t1, t2);
    }
}
