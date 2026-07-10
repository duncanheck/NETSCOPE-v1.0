# docs/threat-model.md — The remote path, adversarially

*Status: **C2 + C3 landed, plus product self-update.** Pairing + token auth,
Tailscale reachability, and the Windows self-updater all ship; the threat tables
below are real, not aspirational. The relay (C5) is still future and is modelled as
such. A2's local-socket threat (below) is kept — it's the foundation the token
layer builds on.*

## Landed in A2 — the local socket carries sensitive data

Until A2 the agent's WebSocket on `127.0.0.1:8787` emitted only heartbeats —
nothing worth stealing. A2 changed that: it now streams **real connection
metadata** — remote IPs, owning process names and executable paths, PIDs. That is
exactly the data a profiler of your machine would want, so the socket's exposure
now matters.

**Threat — cross-site WebSocket hijacking (CSWSH).** A localhost service is *not*
private to local native apps: browser JavaScript on **any website you visit** can
execute `new WebSocket("ws://127.0.0.1:8787")`. The WebSocket handshake is not
subject to the same-origin policy and triggers no CORS preflight, so absent a
check the agent would happily hand a hostile page a live feed of your network
activity, which its script could exfiltrate.

**Mitigation now (defense-in-depth).** The handshake validates the `Origin`
header (`check_origin` in `agent/src/main.rs`):

- A request with **no `Origin`** is allowed — native clients (the desktop shell, a
  CLI, tests) don't send one, and a native attacker already owns the machine, so
  this is not the boundary we're defending.
- A request **with** an `Origin` (i.e. a browser) is allowed only if its host is
  loopback (`localhost` / `127.0.0.1` / `::1`, any scheme or port) — the legitimate
  local frontend — and refused with `403` otherwise. Browsers always send `Origin`,
  so the remote-page vector is closed.

The handshake is also bounded by a 5 s timeout so a peer that connects but never
upgrades can't pin a session task open (a slowloris on the accept).

**Residual risk (the boundary C2 draws).** The Origin check is not
authentication: it trusts the browser to report `Origin` honestly (browsers do; a
*native* client can forge or omit it). So the Origin check defends the *browser*
vector on the *local* machine — nothing more. C2 does **not** try to authenticate
loopback peers: a process that can open a loopback socket already runs on the
machine and could read the same data from `/proc` directly, so a token there would
be security theatre. The boundary C2 actually defends is **locality** — the moment
the feed leaves the host (the C3 tailnet path), a credential is required.

-----

# Landed in C2 — pairing + token auth (the remote path)

C3 will make the agent reachable from another device. Before that the feed must
stop being "anyone who can reach the port." C2 is the credential that gates it.

## The model

- **Trust boundary = locality.** A **loopback** peer connects with no token (the
  A2 boundary, unchanged — local native already owns the machine). A **non-loopback**
  peer must present a valid token. The agent decides which by the peer
  `SocketAddr` (`ws_handler`, `peer.ip().is_loopback()`), not by anything the
  client asserts.
- **Pairing code → token.** The agent mints a six-digit **pairing code**, shown
  only on the agent host (printed on start; served to the trusted local UI at
  `GET /pair/code`, loopback-only). A remote device exchanges it for a long-lived
  **token** at `POST /pair`. The token rides every WS handshake as the
  `Sec-WebSocket-Protocol: auth.<token>` value.
- **Control plane vs. data plane.** Pairing is plain HTTP (`/pair`, `/pair/code`,
  `/auth/revoke`) and deliberately *outside* the versioned wire protocol, which
  stays a pure data plane. Auth is a connection-establishment concern, not a
  message type — keeping it out of the protocol means the protocol's
  forward-compat rules never have to reason about credentials.

## Token storage (PITFALLS C2)

- **Agent side:** tokens are held **only as SHA-256 hashes** (`AuthState.token_hashes`).
  A memory disclosure of the auth set yields hashes, not usable bearer tokens;
  validation hashes the presented token and looks the hash up.
- **Client side:** the token lives **in memory only** — never `localStorage`,
  never `sessionStorage`, never a query string (which would land in server/proxy
  logs). The threat the token defends against is a hostile script reading the
  network feed; a token that same script could read back from storage would
  defeat the point, so this web client **re-pairs each session**. The desktop
  build's path to persistence is the **OS keychain via Tauri** (out of scope for
  the web client).

## Pairing-code interception (PITFALLS C2)

The code is a low-entropy secret (10⁶ space) typed across a possibly-hostile
network, so it gets three compounding limits:

- **TLS-only in deployment.** The exchange rides the C3 tunnel's TLS; the code is
  never sent in clear over the network.
- **Short-lived & single-use.** 60 s TTL; a successful redeem consumes it.
- **Attempt-capped.** A code is burned after 5 wrong guesses (`MAX_PAIRING_ATTEMPTS`),
  closing online brute-force of the 10⁶ space inside the 60 s window. Without this
  cap a fast guesser has a non-trivial success chance per window; with it, the
  expected number of codes an attacker can test before lockout is ≤ 5.

*Residual risk, honestly:* an attacker who can read the code in transit *and* beats
the legitimate device to `POST /pair` within 60 s pairs successfully (the code is
single-use, so the legitimate device's later attempt then fails — a visible
symptom, not a silent compromise). TLS closes the read; the single-use property
turns a race into a detectable failure. This is the residual the short window is
chosen to minimise.

## What each party sees

| Party | Sees | Does **not** see |
|---|---|---|
| **Agent** (your machine) | everything — it *is* the source | — |
| **Tailscale / tailnet (C3)** | that an encrypted WireGuard flow exists between your devices; endpoint IPs | the feed contents (WireGuard-encrypted end to end) |
| **Public relay (C5, future)** | connection metadata *iff* a room forwards plaintext | nothing if the relay only brokers E2E-encrypted frames — the design constraint C5 inherits from this table |

## What a stolen token grants — and doesn't

A stolen token is a **read** credential for the live connection feed and snapshot:
remote IPs, owning process names/paths, PIDs, geo/ASN enrichment. It is **not**:

- **Code execution or host control** — the agent exposes no command surface; the
  WS feed is one-directional (agent → client) and the control plane only mints/
  revokes credentials.
- **Persistent** past revocation — see below.
- **Self-escalating** — a token cannot mint another token or a pairing code; only
  a loopback (on-host) caller can (`/pair/code`, `/auth/revoke` are loopback-only).

The blast radius is therefore "an eavesdropper learns what your machine talks to,
until you revoke." Sensitive, but bounded and recoverable.

## Revocation

`POST /auth/revoke` (loopback-only) drops **every** issued token hash
(`AuthState.revoke_all`); previously-paired devices fail their next handshake and
must re-pair. It's deliberately all-or-nothing in v1 — per-token revocation needs
token identity/labels, which arrive with a real device list (a later milestone).
Rotating the pairing code (`POST /pair/code`) does **not** revoke existing tokens;
it only invalidates an unredeemed code.

## Threat table (C2)

| Threat | Vector | Mitigation | Residual |
|---|---|---|---|
| Unauthenticated remote read | open port on the tailnet | token required for any non-loopback peer; validated on handshake | none beyond a valid stolen token |
| Pairing-code brute force | guessing the 6-digit code | 60 s TTL, single-use, 5-attempt burn | ≤5 guesses/window |
| Pairing-code interception | reading the code in transit | TLS via the C3 tunnel; single-use makes a win detectable | attacker on-path who also wins the redeem race |
| Token theft from storage | XSS / disk read of a persisted token | token in memory only, never persisted (web); keychain on desktop | a script with live in-page access for the session |
| Token theft from agent memory | reading the agent's auth set | tokens stored as SHA-256 hashes | none — hashes aren't usable credentials |
| Token replay after compromise | reusing a leaked token | `revoke_all` drops all tokens | window between leak and revocation |
| Credential self-escalation | a token minting more access | mint/revoke endpoints are loopback-only | none |

-----

# Landed in C3 — reachability (Tailscale), and what it does to the model

C3 makes the agent reachable from another device without writing any relay or
exposing a public port. It rides [Tailscale](https://tailscale.com); the
interesting part for this document is what each reachability path does to the
trust model above.

## The mixed-content decision (PITFALLS C3)

A browser page loaded over HTTPS may not open a plain `ws://` socket — so a phone
on `https://…` could never reach a `ws://<tailnet-ip>` agent. We resolve it the
way C1 anticipated: **the agent serves its own UI**, so the page and the feed
share an origin and the wall never appears. This forced one code change — the
A2 `Origin` check allowed *loopback only*, which would reject the legitimate
served page whose origin is the tailnet address. It is now **loopback or
same-origin** (`origin_allowed`): the page the agent served is allowed, a hostile
third-party page is still refused, and the CSWSH boundary A2 drew is unchanged.

## Two paths, two trust boundaries

| Path | How the agent sees the peer | Auth boundary | Notes |
|---|---|---|---|
| **Direct bind** (`NETSCOPE_BIND=<tailnet-ip>:8787`) | the real remote tailnet IP — **non-loopback** | the **C2 token** (enforced on every remote handshake) | bind is opt-in and logged loudly; the warning insists the interface be private (a tailnet IP), never public |
| **`tailscale serve`** (HTTPS proxy → loopback agent) | **loopback** (tailscaled terminates and proxies locally) | **tailnet membership** — only your authenticated devices can reach the serve endpoint; Tailscale's ACLs are the gate | the agent can't see the real peer here, so the C2 token does *not* apply; this is honest, not a gap — the boundary simply moves to Tailscale's identity layer |

The direct-bind path keeps the C2 token as the control. The serve path delegates
to Tailscale's WireGuard identity (every tailnet device is authenticated and
ACL-scoped); the feed is WireGuard-encrypted end to end, and the relay/DERP
servers only ever see ciphertext (the "Tailscale / tailnet" row of the C2 table).
Choosing serve means trusting your tailnet ACLs; choosing direct-bind means
trusting the C2 token. Both are stated so the operator picks knowingly.

## Residual risk (C3)

- **Binding too wide.** `NETSCOPE_BIND=0.0.0.0:8787` listens on *every* interface,
  not just the tailnet one. On a host with a public NIC that exposes the port to
  the internet (still token-gated, but now internet-reachable). The startup
  warning calls this out; the documented form binds the specific tailnet IP.
- **Public exposure is explicitly out of scope.** C5 (a public relay) is the
  milestone that takes untrusted-network exposure seriously; until then the agent
  is private-network-only by construction.

-----

# Self-update — downloading and running a new binary, adversarially

The Windows product self-updates (so you don't re-download the exe by hand). That
means the agent will, on your say-so, fetch a binary off the internet and replace
itself with it — exactly the kind of capability that deserves a threat model.

## The model

On launch — and then on a slow background poll (every few hours) — a *stamped* build
(CI sets a monotonic build id) fetches a manifest (`latest.json`) from a **fixed**
GitHub release URL over HTTPS. If the manifest's build id is higher than the running
one, the HUD surfaces it. The updater panel also exposes `POST /update/check`
(loopback-only) so the user can re-check on demand and *see* the result. Nothing is
downloaded or run until **you click** (notify-then-apply). On click,
`POST /update/apply` downloads the exe, checks its SHA-256 against the manifest,
and only then swaps the binary in place; you restart to run it.

## Controls, and what each defends

| Control | Defends against |
|---|---|
| **HTTPS + fixed repo URL** | a network attacker serving a fake manifest/exe (transport authenticity; the URL isn't attacker-influenced) |
| **SHA-256 check** before swap | a corrupted or truncated download being run; a mismatch aborts and the binary is untouched |
| **Notify-then-apply** (no silent updates) | a surprise binary swap; the user is always in the loop |
| **`/update/apply` and `/update/check` are loopback-only** | a **remote paired device** (C3) triggering a download or a binary swap onto your host — pairing grants a *read* of the feed, never code execution |
| **Dev builds (id 0) + `NETSCOPE_NO_UPDATE`** | unexpected network calls / updates in development or locked-down deployments |

## Residual risk (honestly)

This is **integrity + locality, not authenticity of the artifact itself.** The
SHA-256 lives in the manifest, served over the same HTTPS channel as the exe — so
the check defends against corruption and a CDN hiccup, *not* against an attacker
who has compromised the GitHub repo/release (they could publish a malicious exe
and a matching hash). The real trust root is **GitHub + the maintainer's account**;
a compromise there is game over, as it is for any auto-updater without independent
**code signing**. Code signing (an Authenticode cert, or a signed manifest verified
against a pinned public key) is the documented next step if this graduates from a
portfolio build to something people depend on. Until then the honest statement is:
*you are trusting this repository's release pipeline exactly as much as you trust
the exe you downloaded from it by hand.*

-----

# The Warden enforcer (E4) — the one privileged component

Everything else in NETSCOPE is unprivileged: it *reads* connection state and, for
the Warden, *generates* firewall rules you apply by hand (E1–E3). E4 adds the single
elevated piece — `netscope-enforcer`, a helper that can actually edit the firewall —
so it gets its own model.

## What it is

A small daemon that does **only** "add/remove an address in *its own* firewall
namespace" — the `inet netscope` nftables set on Linux, the `NETSCOPE Warden`
Windows Firewall rule group on Windows. The unprivileged agent connects over a
local IPC channel and asks; the helper re-validates everything.

**Linux:** it listens on a Unix socket and runs from a hardened systemd unit as a
**dedicated service user with only `CAP_NET_ADMIN`** (not root), with
`NoNewPrivileges`, a read-only system view, a seccomp `@system-service` filter, and
address families restricted to `AF_UNIX`/`AF_NETLINK`. The agent only talks to it
when `NETSCOPE_ENFORCER_SOCKET` is set; otherwise NETSCOPE is generate-only,
exactly as before.

**Windows:** it listens on a named pipe (`\\.\pipe\netscope-enforcer`,
`PIPE_REJECT_REMOTE_CLIENTS` so the network path is closed outright, plus a DACL
that only lets SYSTEM/Administrators/the configured user connect) and runs as a
Windows service installed by `packaging/install-enforcer.ps1`. Each connection is
authenticated by the **user SID of the client's process token**, read from the
kernel (`GetNamedPipeClientProcessId` → token query) — the `SO_PEERCRED` analog;
SYSTEM and exactly one configured desktop user are allowed. It runs as LocalSystem
(Windows Firewall editing has no capability-granular equivalent of
`CAP_NET_ADMIN`; the narrow request vocabulary and the floor are what bound it).
Because Windows Firewall rules **persist across reboots**, the service starts by
removing stale rules in its group and **clears its rules on stop** — fail-open by
design, so a stopped or crashed service can never leave orphaned, invisible
blocks. Auditing goes to `%ProgramData%\netscope\enforcer.log`. The opt-in is
installing the service: the agent probes the well-known pipe and stays
generate-only when it's absent.

## New attack surface, and what bounds it

The enforcer can drop your traffic, and a paired/stolen **C2 token** that can reach
the agent now also implies "could ask the agent to request blocks." That is bounded,
in the enforcer itself (not just the agent), so a wrong or hostile caller still can't
do much harm:

| Control | Defends against |
|---|---|
| **Kernel-reported peer auth** — `SO_PEERCRED` UID on Linux, process-token SID on Windows (allowlisted user, or root/SYSTEM) — not "loopback == trusted" | any other local user, or a sandboxed process, driving the firewall; the peer's identity comes from the kernel and can't be forged |
| **The never-block floor is enforced *here*** (`is_protected_addr`: loopback / RFC1918 / link-local / CGNAT-tailnet / ULA) | the agent — buggy or compromised — being used to cut you off your own machine, LAN, or tailnet; the helper drops those addresses regardless of what's asked |
| **Owns one table only** (`inet netscope`), refuses everything else | the privileged helper being turned into a general firewall-editing oracle |
| **Set-size cap + every change audited** (to the journal) | unbounded growth, and silent changes — every add/remove/clear is logged |
| **Least privilege** (`CAP_NET_ADMIN` only, sandboxed unit) | a compromise of the helper escalating beyond editing nftables |
| **Opt-in** (`NETSCOPE_ENFORCER_SOCKET` unset ⇒ no enforcement) | enforcement existing at all on hosts that didn't ask for it |

## Residual risk (honestly)

The agent and enforcer run as the same human's session in the common single-user
case, so the peer-UID check is a *defense-in-depth* boundary (process integrity, not
a different principal) rather than a hard privilege wall — its real value is refusing
*other* users/sandboxes and making the never-block floor independent of the agent.
The floor is an allowlist of address *scopes*, not destinations: the enforcer can
still block a public IP the agent shouldn't have targeted (mitigated by the agent's
own dry-run/preview and the audit log + one-click unblock). And like the firewall
generator, this is **IP/CIDR enforcement** — it can't follow a domain across rotating
CDN IPs; the documented DNS-layer path (E6/optional) is the answer there. On
Windows the helper runs as LocalSystem rather than a capability-trimmed user (no
such granularity exists for firewall editing), so its narrow request vocabulary —
add/remove/list/clear in one group, floor enforced service-side — carries more of
the weight there; the same-user defense-in-depth caveat above applies equally to
the SID check.

## Data at rest — the opt-in flow history (G4.1)

Everything above assumes the baseline: the live world exists **in memory only**,
nothing the agent captures touches disk, and a restart forgets everything. That
ephemerality is a security property — a machine seized or malware-scraped after
the fact holds no connection history — and it stays the default.

`NETSCOPE_HISTORY_DIR` opts out of it, deliberately and visibly. When set, the
agent appends flow *lifecycle* events (an `open` line with the full enriched
metadata per new connection, a `close` line per ended one; never per-delta
activity churn) as JSONL, rotated at 10 MB with one predecessor file kept.

What that changes:

| Property | Without history (default) | With `NETSCOPE_HISTORY_DIR` |
|---|---|---|
| Connection metadata at rest | none | remote endpoints, process names/pids, org/geo, flags — the profile of the machine's activity over time |
| Who can read it | n/a | anyone with filesystem access to the chosen directory — NETSCOPE does not encrypt it; choose the directory (and its permissions) accordingly |
| Retention | n/a | bounded by rotation (~20 MB), but *not* time-bounded; delete the files to forget |
| Blast radius of a later compromise | the live view while running | plus the recorded history window |

The export buttons in the HUD (CSV/JSON of the current view) are client-side and
write only where the *user* chooses via the browser's download flow — the agent
itself still writes nothing unless history is opted into.

## Packet capture — the opt-in pcap/Npcap path (G5)

The baseline capture reads connection *tables* — no special privilege beyond
what any process can see of its own host. Enabling packet capture
(`--features pcap` + `NETSCOPE_PCAP=1`) changes the privilege story and is
therefore double-opt-in:

| Property | Polling (default) | With packet capture |
|---|---|---|
| Privilege required | none beyond normal user (own-process visibility) | root / `CAP_NET_RAW` (Linux), the Npcap driver (Windows) — the agent becomes a raw-socket holder |
| What the process holds | table rows (5-tuple, pid) | + link/IP/L4 **headers** of live traffic, aggregated |
| Payload exposure | none | none, structurally: snaplen 96 caps the kernel copy at headers; the parser reads nothing past the TCP/UDP port words; only per-conversation packet/byte counters cross the capture thread boundary, drained ~4×/s and never stored |
| Failure posture | n/a | any open/permission failure degrades to polling with a visible "unavailable" status — never a crash, never a silent success claim |

The residual honesty: a compromised agent process *with capture privilege* is a
worse compromise than one without — it could re-open the device with a larger
snaplen. That is inherent to holding the privilege at all and is why the
default remains no-capture; the mitigation is the same as the enforcer's
(privilege is opt-in, visible in the System panel, and revocable by unsetting
one variable).
