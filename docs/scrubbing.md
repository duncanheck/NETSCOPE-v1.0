# docs/scrubbing.md — The scrubbing pipeline (D1)

*Status: **landed (D1).** This is the privacy contract for the AI layer (Track D).
It is a pure, testable function in the `netscope-narrator` crate
(`scrub_session`), enforced by tests so it can't silently regress.*

## The rule

NETSCOPE's narrator asks an LLM to *explain* your traffic, which means a
description of it leaves your machine. **Nothing in Track D may call an API on
anything but the output of `scrub_session`.** The scrubber is the single boundary
between captured data and the network, deliberately one small pure function so the
policy is reviewable in one place.

## What leaves the machine vs. what never does

The redaction keeps the **destination** (what you're talking to — the explainable
surface) and drops everything that identifies **you or your network**.

| Field | Sent? | Why |
|---|---|---|
| connection `id` (5-tuple) | **dropped** | embeds your local IP + port |
| local IP / port | **dropped** | your machine + NAT layout |
| raw remote IP | **dropped** | the org + hostname + coarse geo identify the destination without the literal address |
| LAN hostname (local flows) | **dropped** | names your local devices |
| process `path` | **dropped** | embeds your home directory / username |
| process `pid` | **dropped** | not needed to explain anything |
| process **name** | kept | e.g. `firefox` — not a local-network identifier |
| public hostname (remote) | kept | the destination you chose to reach |
| org + ASN (remote) | kept | who owns the destination |
| country + city (remote) | kept | where the *server* is (coarse), not where you are |
| port / protocol / encrypted | kept | the shape of the conversation |
| category + security flags | kept | the security read the explanation is about |

Each flow becomes a stable **handle** (`flow-1`, `flow-2`, …) so the model can
reason about and reference flows without ever seeing a 5-tuple.

## Local vs. remote — fail-safe classification

A flow is treated as **local** (and reduced to `scope: "local"` with no host, org,
or geo) if *either* the A4 enrichment category says `local` *or* its address
classifies as local — defense in depth. The classifier (`classify_ip`) marks as
local:

- IPv4 loopback, RFC1918 private, link-local (`169.254/16`), unspecified/broadcast,
  and **CGNAT `100.64.0.0/10`** (which is also the Tailscale tailnet range);
- IPv6 loopback (`::1`), unspecified (`::`), link-local (`fe80::/10`), ULA
  (`fc00::/7`);
- **anything it can't parse fails safe to local** — an address we don't understand
  is never emitted.

## Residual risk (honestly)

- **Public hostnames and orgs are sent by design.** Visiting an unusual host means
  that host's name is in the prompt; that's the destination, which is the thing
  being explained. If you don't want a given session described, don't run the
  narrator on it (it is opt-in, per D2).
- **Coarse geo of the destination is sent.** It locates the *server*, not you, but
  it is still information about where your traffic goes.
- **The trust boundary is the API provider.** Scrubbing removes *your* identifiers;
  it does not make the destination list secret from the model. That trade — a
  redacted destination description in exchange for an explanation — is the whole
  point, stated so you can decline it.

## Used by D2 (the explain providers)

The structured-explain feature (D2) runs **only** on `scrub_session` output,
whichever provider the user picks:

- **Built-in** rules summary and **local Llama (Ollama)** keep everything on the
  machine — the scrubbed JSON never touches the network.
- **Claude** (Anthropic API) sends the scrubbed JSON off-machine. The provider menu
  labels this explicitly (`⚠ sends a scrubbed summary off-machine`) so the choice is
  informed. The `POST /narrator/explain` endpoint is loopback-only — a remote paired
  device can't trigger an off-machine send.

Scrubbing removes *your* identifiers before any of this; it does not make the
destination list secret from whichever model runs. Choosing built-in or Ollama keeps
even that local.

## Enforced by tests

`cargo test -p netscope-narrator` proves the contract: a session built from a flow
full of sensitive data (local IP, local port, LAN hostname, process path, username,
pid, 5-tuple id) serializes to JSON that contains **none** of them, while still
carrying the destination host, org, geo, and process name; plus the IP classifier
covers every local range and the fail-safe.
