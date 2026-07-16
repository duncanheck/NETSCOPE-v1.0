# planning/WARDEN.md — Track E: The Warden

*Status: **E1 + E2 + E3 landed; E4 landed (Linux + Windows); E6 landed; E7 landed; E5 proposed.** Turning NETSCOPE from sight into action: block the
risky flows it already surfaces — trackers, plaintext exfil, and known-bad
endpoints — without spending a cent, without an inline packet engine, and without
quietly regressing the "runs unprivileged, no admin needed" property that makes the
observer safe to run. Written before any code, in the PITFALLS spirit.*

The thematic line continues: Agent watches, Organism renders, Bridge carries,
Narrator explains — **the Warden guards the gate.**

-----

## The design decision (use the OS, don't become one)

A blocker can be built many ways. Most of them are wrong for this project — they
cost money, blow the overhead budget, or reinvent a firewall. The logic:

| Approach | Free? | Efficient? | Verdict |
|---|---|---|---|
| **OS-native firewall set** — nftables (Linux), WFP (Windows), pf (macOS); the agent only edits *set membership* | ✅ built-in | ✅ kernel does the per-packet work; hash/interval sets are O(1) | **✅ primary preventive layer** |
| **Reactive socket teardown** — `SOCK_DESTROY` netlink (Linux, the `ss -K` mechanism), `SetTcpEntry` `DELETE_TCB` (Windows) | ✅ built-in | ✅ one syscall per kill | **✅ for immediate effect on live connections** |
| **DNS sinkhole** — answer flagged names with `0.0.0.0`/NXDOMAIN | ✅ | ✅-ish | 🟡 optional later — domain-based, CDN-friendly, but requires *being* the resolver |
| **Inline NFQUEUE / WinDivert packet engine** — userspace verdict per packet | ✅ | ❌ per-packet userspace cost; a kernel driver on Windows | **❌ kills the <1 %-CPU budget; the same reason Npcap was deferred** |
| **Cloud firewall / paid threat intel** | ❌ | n/a | **❌ violates "no money"** |

So the Warden's shape is fixed by the constraints:

1. **Lean on the kernel's own firewall.** The agent *generates and maintains a
   namespaced rule set*; the kernel enforces it. Per-packet work stays in-kernel at
   O(1); the agent only writes set membership, which is rare and cheap. This is the
   "firewall generator" the brief asks for, done natively.
2. **Reactive kill for immediacy.** A firewall set only catches the *next* packet to
   a blocked IP; an already-open TCP connection keeps flowing. One `SOCK_DESTROY` /
   `DELETE_TCB` per offending socket makes a block take effect *now* — free,
   built-in, no persistent state. NETSCOPE already knows the exact 5-tuple and PID,
   so this is cheap and precise.
3. **Free threat intelligence, downloaded not redistributed.** Reuse the GeoLite2
   pattern (A4): ship a license-aware *downloader*, not the data. Free feeds
   (abuse.ch, FireHOL, StevenBlack) turn "block what looks risky" into "block what's
   *known* bad."
4. **Privilege separation, opt-in.** Blocking needs `CAP_NET_ADMIN`/admin; watching
   doesn't. Keep the observer unprivileged; make enforcement a *separate, minimal,
   opt-in* privileged helper. The read-only product must still run with zero admin.
5. **Generate-and-preview before apply.** The eval (D3) is honest that the
   classifier has false positives (it flagged a legit BI tool). You never auto-block
   on a heuristic. Every block is previewed, reversible, and allowlist-gated.

**The non-negotiable invariant:** the Warden leans on the OS's firewall and the
OS's socket APIs. It never reimplements a packet filter, never sits inline, never
phones a paid service.

-----

## Roadmap (Track E — each milestone names its skill and its proof)

**E1. Policy engine + dry-run — the brain, zero privilege. ✅**
A pure, testable policy (`netscope-warden`) that turns the flow stream into block
*decisions*: rules `category` / `flag` / `org` / `cidr` (v4+v6), a hard **allowlist
that always wins**, and a hard **protected floor** (loopback, RFC1918, link-local,
CGNAT/tailnet, ULA — and an unparseable address fails *safe*) that no rule can
override, so a policy can never cut you off from your own network. `dry_run` answers
"what *would* be blocked, and why" with deduplicated firewall targets; nothing is
enforced. Wired to a loopback-only `POST /warden/preview` and a read-only **block
preview** panel in the HUD (tick risk classes → see what would be cut, with the
reason). 10 unit tests incl. the protected floor under a deny-everything policy,
allow-beats-deny precedence, CIDR matching, and policy JSON round-trip.
*Skill:* deny/allow precedence, policy-as-a-pure-function. *Artifact:* the preview
panel + the test suite (the same "never act without showing the work" ethos as D3).
*(Gateway/DNS auto-detection for the protected floor is deferred to E4, where the
runtime context exists.)*

**E2. Threat-intelligence feeds — finding the vulnerabilities. ✅**
Pulls free, redistributable blocklists with a license-aware downloader (A4 pattern):
`scripts/download-threatfeeds.{sh,ps1}` fetch **StevenBlack** unified hosts
(ads/trackers/malware, MIT), **abuse.ch** URLhaus hostfile + Feodo C2 IPs (CC0), and
**FireHOL** level-1 IP aggregates into `threatfeeds/` (overridable via
`NETSCOPE_THREAT_DIR`). The repo ships the *downloader, not the data* — nothing
bundled, nothing paid, feeds stay fresh. `netscope_warden::ThreatDb::load_dir` reads
whatever feed files are present at startup (dispatched by extension:
`.hosts`/`.domains`/`.ips`/`.netset`/`.txt`); a missing dir simply leaves the feature
off. Matching is cheap and in `ThreatDb`: a domain `HashSet` walked over the host's
suffixes (`a.b.evil.com → b.evil.com → evil.com`, O(labels)), an exact-IP `HashSet`,
and a small CIDR `Vec` (a longest-prefix trie is the noted scale path once feeds reach
millions of CIDRs). A new `Rule::Threat` deny variant feeds the E1 engine via
`evaluate_with`/`dry_run_with(policy, flows, Some(&db))`, surfacing the reason "threat
feed (host X)" / "threat feed (IP)". The agent exposes loopback-only `GET
/warden/threats` (loaded indicator count, feed filenames, and which current flows
match); the HUD's WardenPanel adds a **known-bad lists** toggle that auto-enables once
at least one feed is loaded and shows the indicator count.
*Skill:* feed ingestion, suffix-walk / CIDR membership, license-aware data handling.
*Artifact:* feed-matched flows surfaced in the HUD + a loopback status endpoint;
verified end-to-end against live flows.

**E3. The firewall generator — emit native rules (still zero privilege). ✅**
Renders the E1 policy's block targets into an OS-native ruleset the user reads and
applies by hand: a namespaced `inet netscope` `nft -f` file (Linux), a grouped
`netsh advfirewall` batch (Windows), a `netscope` pf anchor (macOS) — each
outbound-only, atomically re-appliable, and removable in one command. Generation is
structured and **injection-proof by construction**: only strings that *parse* as an
IPv4/IPv6 literal or CIDR reach the output (a hostname or shell metacharacter is
dropped), and the firewall tool's own parser is the second gate. Wired to a
loopback-only `POST /warden/generate { policy, backend }` and a HUD section
(backend dropdown → generated rules in a copyable block with apply/remove hints).
6 unit tests incl. the injection guard and netsh chunking; the nftables output was
checked with the real `nft -c -f` (valid syntax). *(iptables-legacy and WFP-direct
remain documented gaps; the three shipped backends cover the project's target OSes.)*
*Skill:* per-OS firewall semantics, idempotent/namespaced/injection-safe generation.
*Artifact:* the generated, diffable ruleset, validated by the firewall's own parser.

**E4. The enforcer — privilege-separated apply (the unglamorous, security-critical one). ✅ (Linux)**
A minimal privileged helper (`netscope-enforcer`) that does *only* "add/remove an
address in *its own* `inet netscope` set" on request from the unprivileged agent over
an **authenticated** Unix socket — the peer's real UID comes from `SO_PEERCRED` and is
checked against an allowlist (`is_authorized`), never "loopback == trusted". It ships
with a hardened **systemd unit** (`packaging/netscope-enforcer.service`): a dedicated
user with `AmbientCapabilities=CAP_NET_ADMIN` and everything else dropped — not root.
It owns one table (the same namespace E3 generates), **enforces the never-block floor
itself** via the warden's `is_protected_addr` (so loopback/LAN/tailnet can't be cut
even if the agent asks), caps the set size, and **audits every change**. The agent
side is opt-in: only with `NETSCOPE_ENFORCER_SOCKET` set does it reach for the helper
(`POST /warden/apply`, `GET /warden/blocked`, `POST /warden/unblock`, all loopback-
only); absent that, NETSCOPE stays generate-only (E3). The nft mechanism is isolated
behind an `Applier` trait (real / `nft -c` validate-only / in-memory mock), so the
auth, floor, and bookkeeping are unit-tested and the full agent→socket→apply→list path
is smoke-tested without privilege.
**The Windows follow-up landed too:** the same enforcer core behind a **named pipe**
(`\\.\pipe\netscope-enforcer`, `PIPE_REJECT_REMOTE_CLIENTS`, DACL-restricted), each
connection authenticated by the client process token's **user SID** (kernel-reported
via `GetNamedPipeClientProcessId` → token query — the `SO_PEERCRED` analog; SYSTEM
plus one configured desktop user allowed). It runs as a real Windows **service**
(`windows-service` crate; console mode for testing) and applies blocks as Windows
Firewall rules in its own namespaced **"NETSCOPE Warden" group** through the
NetSecurity cmdlets — full-set resync on change, `-WhatIf` as the unprivileged
dry-run, only parsed `IpAddr` values ever reaching the command line. Because Windows
Firewall rules persist across reboots, the service starts clean (removes stale group
rules) and **clears its rules on stop** — fail-open, no orphaned invisible blocks.
Audits to `%ProgramData%\netscope\enforcer.log`. Installed/removed by
`packaging/install-enforcer.ps1` / `uninstall-enforcer.ps1`; the agent auto-detects
the well-known pipe, so installing the service is the whole opt-in. The pipe server,
SID auth, SDDL, and the apply/list/clear path are unit-tested end-to-end over a real
named pipe.
*Skill:* privilege separation, least privilege, secure local IPC. *Artifact:* the
hardened unit + the [threat-model addendum](../docs/threat-model.md) — the enforcer is
a new attack surface, and a paired/stolen C2 token now also implies "could request
blocks," which is bounded (never-block floor, cap) and audited.

**E5. Immediate effect — reactive socket teardown.**
Kill the *already-open* offending connection so a block bites within one poll, not
on the next attempt: Linux `SOCK_DESTROY` over `inet_diag` netlink (the kernel
sends RST), Windows `SetTcpEntry` with `MIB_TCP_STATE_DELETE_TCB`. Only sockets
whose remote is already in the firewall set are killed, so a reconnect is refused by
the set — closing the kill→reconnect→kill loop. UDP can't be torn down; it relies on
the filter alone (documented honestly).
*Skill:* netlink / `iphlpapi` socket teardown, identity-checked kills.
*Artifact:* "a block takes effect inside one capture poll," demonstrated.

**E6. UX — block, preview, undo, audit (product-grade). ✅**
The HUD's block panel gains an **enforcement** section (wired to E4 via `POST
/warden/apply`, `GET /warden/blocked`, `POST /warden/unblock`): the rule toggles
("block trackers / plaintext / unattributable / known-bad") already drove the preview;
now **apply** them through the enforcer behind a **mandatory preview → confirm** step
(never one-click, never silent). It shows a persistent **"N blocks active"** count and
the live **blocked list** with one-click per-row unblock and **unblock all**, surfaces
the enforcer's never-block-floor **refusals** inline, and keeps a persistent
(localStorage) **audit log** of every block/unblock with timestamps. The selected-flow
inspector gets a per-endpoint **block / unblock this endpoint** toggle. When no enforcer
is configured the section says so and stays generate-only — enforcement is detected at
runtime (the agent answers `503`), so the UI degrades gracefully. State is shared
through a small `useWardenStore`, so the panel and the flow inspector stay in sync.
*(Auto-expiring temporary blocks remain a noted nice-to-have.)*
*Skill:* dangerous-action UX (preview → confirm → undo), runtime capability detection.
*Artifact:* the blocking panel + the per-flow action + the audit trail; transport
mapping unit-tested (incl. the not-configured path) and the apply/unblock/clear loop
smoke-tested end-to-end against the live enforcer.

**E7. Real-time verification — proving the firewall is actually enforcing. ✅**
Everything through E6 trusts the enforcer's own bookkeeping: `GET /warden/blocked`
answers from an **in-memory mirror** of what the enforcer believes it applied, not a
live read of the OS. That's a real gap for a security-facing status — Windows
Firewall rules can be edited or reset outside NETSCOPE, an `nft` resync can silently
fail, and the UI would keep showing "N blocks active" regardless. E7 closes it with a
new enforcer request, `Verify` (`netscope_enforcer::Applier::verify`), that re-reads
the *actual* structure — `nft -j list set inet netscope blocked{4,6}` on Linux,
`Get-NetFirewallRule -Group 'NETSCOPE Warden' | Get-NetFirewallAddressFilter` on
Windows — and compares it to the enforcer's expectation, returning `{live, expected,
in_sync}` over a new loopback-only `GET /warden/verify` (mirroring the
NotConfigured(503)/Failed(502) split `/warden/blocked` already has, so "never
installed" and "installed but not responding" stay distinguishable). The HUD polls
it every 8s and immediately after every apply/unblock (no waiting on the next tick
to confirm what the user just did), showing one plain-language line: verified (with
a live count and "checked Ns ago"), drift (live vs. expected disagree — an audited
event, not just a UI flag), unreachable, or not installed.

On top of that live proof, E7 also adds the **simple surface**: a **Warden Mode**
switch (applies the same default risky-traffic policy the rule checkboxes already
compute — trackers, plaintext, unattributable — behind one confirm step to turn on,
one click to unblock everything and turn off) and a **Threat Feed** switch (the same
`useThreats` toggle, promoted to the top). Both read the *same* policy state the
granular checkboxes drive, so the simple switches and the advanced panel (now under
a collapsible **advanced controls** `<details>`) never disagree — flipping "Warden
Mode" and opening "advanced" shows the identical blocked list and audit entry.
Neither switch ever re-applies on page load from its persisted (localStorage) state
— reflecting the last-seen position is fine, silently re-blocking on a refresh is
not.
*Skill:* live-vs-belief verification (the "trust but verify" gap in the E4 design),
opinionated-defaults-over-granular-controls UX. *Artifact:* `Applier::verify` unit
tests (in-sync + simulated external drift, via `MockApplier`) plus an end-to-end
smoke test against a **real** `netscope-enforcer` + `nft`: apply, verify (in sync),
hand-edit the live nftables set to simulate external tampering, verify again (drift
correctly detected and audited) — see the enforcer's own audit log line
`verify: DRIFT — live N expected M`. The Windows `Get-NetFirewallAddressFilter`
query path is `cargo check`/`clippy`-clean on the MSVC target (this project's usual
bar for Windows-only code written off a Linux dev box) but, like the rest of
`apply_windows.rs`, needs a real Windows run to confirm against actual Firewall
state.

**Suggested order (so risk lands last):** E1 → E3 → E2 give a complete, zero-
privilege, zero-risk "generate a firewall script and apply it yourself" — free and
efficient, exactly as asked. E4 → E5 → E6 add in-app apply, immediacy, and the UX,
each gated behind the opt-in privileged helper. E7 adds proof that E4's apply is
still true, plus a simpler front door onto the same policy.

-----

## Pitfalls (prefire, before any code)

**E1 (policy)**
- *Pitfall:* auto-blocking on a heuristic with known false positives (D3 flagged a
  legitimate BI tool as a tracker) — you cut the user's own service.
  *Prefire:* never auto-block; default-off; per-rule user confirmation; the
  allowlist *always* wins; `--dry-run` preview is mandatory before any apply.
- *Pitfall:* ambiguous rule precedence (does `block tracker` beat `allow org=X`?).
  *Prefire:* fixed, tested precedence — explicit allowlist > never-block list >
  deny rules > default-allow — and a per-decision "why" string.

**E2 (threat feeds)**
- *Pitfall:* feeds are millions of CIDRs; a naive `Vec<IpAddr>` scan or per-flow
  string match blows the <1 %-CPU/low-RSS budget.
  *Prefire:* a longest-prefix-match trie loaded once (O(log n) match), and push the
  list into the kernel `nft` *interval set* so the hot-path match is in-kernel and
  free; cap feed size; refresh on a timer with backoff, last-good on offline.
- *Pitfall:* a feed isn't redistributable, or goes stale and blocks a now-clean IP.
  *Prefire:* ship a downloader, not the data (license-checked, GeoLite2 pattern);
  record each feed's age; let the allowlist override; prefer recent, high-confidence
  entries.

**E3 (generator)**
- *Pitfall:* a generated rule locks the user out — blocking loopback, DNS, the
  default route, or the agent's own socket; or it clobbers the user's existing
  firewall.
  *Prefire:* generate into an *own, namespaced* table/anchor that never touches the
  user's rules; scope to *outbound to specific remote IPs* only; bake the
  never-block list into generation; make teardown a single `nft delete table` /
  remove-anchor; everything reversible.
- *Pitfall:* shell-string-building `nft`/`netsh` commands → injection from a
  hostname/org field.
  *Prefire:* structured generation to a file the firewall tool parses and validates;
  never interpolate untrusted text into a shell.
- *Pitfall:* one ruleset assumed to fit all OSes; IPv4-only rules leave an IPv6
  bypass.
  *Prefire:* generate per-OS, detect the backend (nftables vs iptables-legacy), and
  emit *both* address families (`inet` set covers v4+v6).

**E4 (enforcer)**
- *Pitfall:* a privileged daemon is a juicy target — a spoofed or compromised agent
  blocks arbitrary traffic (a DoS) or is tricked into removing protections.
  *Prefire:* least privilege (`CAP_NET_ADMIN` only, everything else dropped — never
  root); the enforcer owns *only* its own table and refuses everything else;
  peer-credential-authenticated IPC (not "loopback == trusted"); a hard never-block
  list the enforcer applies regardless of what the agent asks; rate-limit; full
  audit log.
- *Pitfall:* the new capability silently widens the C2 blast radius — a stolen C3
  pairing token could now request blocks.
  *Prefire:* remote clients can *view* the blocked list but *cannot* apply/remove
  blocks (apply is loopback-only and peer-cred-checked, like `/update/apply`);
  document the new boundary in the threat-model.

**E5 (socket kill)**
- *Pitfall:* killing the wrong socket (PID reuse, stale 5-tuple), or a
  kill→reconnect→kill loop burning CPU against an app that retries instantly.
  *Prefire:* verify `(pid, start_time)` identity before a kill (reuse the A2
  PID-reuse cache); only kill remotes already in the firewall set so the reconnect
  is refused (breaking the loop); rate-limit kills; never kill loopback/management.
- *Pitfall:* assuming UDP/QUIC can be torn down like TCP.
  *Prefire:* document that teardown is TCP-only; UDP relies on the filter set alone.

**E6 (UX)**
- *Pitfall:* a user blocks something critical (their VPN, corp proxy, update server)
  and loses connectivity with no obvious way back.
  *Prefire:* preview before apply; one-click undo + "unblock all"; a persistent,
  visible "N blocks active" badge; optional auto-expiring blocks; the allowlist
  front-and-centre; an audit trail. Never block silently.

**E7 (real-time verification + the simple switches)**
- *Pitfall:* a "verified" badge that's actually just re-displaying the enforcer's own
  in-memory belief is worse than no badge — it launders an unverified claim as proof.
  *Prefire:* `verify()` is a genuinely separate code path from `list()`/`blocked()` —
  it shells out to `nft -j list set` / `Get-NetFirewallAddressFilter` fresh every
  call, never reads the `blocked` `BTreeSet` the enforcer keeps in memory. Proven with
  a test that mutates the mock applier's set directly (simulating external drift the
  enforcer's own bookkeeping never sees) and checking `verify()` catches it.
- *Pitfall:* the simple switches become a second policy that quietly diverges from
  the advanced rule checkboxes, so "Warden Mode: on" stops meaning what the panel
  underneath shows.
  *Prefire:* no second policy — the switch applies exactly the `deny` the checkboxes
  already compute (reusing the E1 rule types, not a hardcoded parallel list), so the
  simple and advanced views are always describing the same blocked set.
- *Pitfall:* a persisted "Warden Mode: on" flag re-applying a block on every app
  launch, unprompted — the exact "never block silently" line this project holds.
  *Prefire:* the switch position is remembered (localStorage) for display only; only
  a live toggle event calls `apply`/`unblock`, never a mount effect.
- *Pitfall:* polling `/warden/verify` on a fixed timer only, so the status line lags
  up to a full interval behind an action the user *just took* — undermining the
  "real-time" claim exactly when it matters most.
  *Prefire:* re-verify immediately after every apply/unblock, in addition to the
  timer (caught live, against a real enforcer, in manual testing — the first cut of
  this only polled periodically and visibly lagged).

**Cross-cutting**
- *Pitfall:* enforcement regresses the "runs unprivileged, no admin" selling point.
  *Prefire:* the *observer* stays unprivileged forever; enforcement is a separately-
  installed, opt-in, privileged component. Users who only want to watch never grant
  a capability.
- *Pitfall:* scope creep into "a real firewall" — an inline engine, a rule language,
  a policy DSL.
  *Prefire:* position the Warden as "generate/apply native rules from what you see,"
  not "replace your firewall." Lean on the OS; the moment a design needs a userspace
  packet path, it's the wrong design.
- *Pitfall:* CDN / shared-IP collateral — blocking one IP cuts unrelated sites, and
  CDN IPs rotate, so an IP block ages out of usefulness.
  *Prefire:* warn when blocking a `cdn`-category IP; prefer domain/SNI-based blocking
  (the optional DNS-sinkhole path) for CDN-fronted trackers; treat IP blocks as
  best-effort, short-TTL, refreshed from the live classification.

-----

## Decisions I'd revisit

- **Generator-first vs daemon-first.** Shipping E1+E3 (generate a script you apply
  by hand) before the privileged enforcer is the cautious call — auditable, free,
  no new attack surface — at the cost of a manual step. If users clearly want
  one-click blocking, E4 moves up. Either way the privileged surface ships *after*
  the policy is proven.
- **IP blocking vs DNS sinkhole as the default.** IP-set blocking is simpler and
  needs no resolver change, but it's coarse against CDN-hosted trackers. If most
  real-world "vulnerabilities" turn out to be domain-fronted, the DNS-sinkhole path
  (optional in E2/E6) becomes the better primary, and IP blocking the backstop.
- **Whether to enforce at all.** The honest framing: NETSCOPE is a visualizer with a
  rigorous agent, not a security product. The Warden is valuable *because* it acts on
  data the user can already see and understand — but if it ever starts making
  silent, automatic, heuristic-driven blocking decisions, it has become the thing
  this whole project is careful not to be. Keep it user-driven, previewed, and
  reversible, or don't ship it.
