# NETSCOPE — GROWTH.md

*From portfolio showcase to a tool anybody can run for security. Four phases, each
shippable on its own, ordered by user-visible value per unit of new risk.*

## The thesis

The core loop works: capture → enrich → visualize is landed and tested
([`ROADMAP.md`](ROADMAP.md) tracks A–E). What it doesn't yet do is *tell a
non-technical person whether they should care*. The scene is descriptive — it shows
that connections exist and what category each one is — but there is no synthesized
judgment, no trend, and every value-add capability (geo, threat feeds, blocking, AI
explain) requires terminal literacy to enable. Growth means closing the gap between
"beautiful and correct" and "meaningful and effortless," then adding depth for the
technical audience on top.

## Progress

`✅ landed · 🟡 partial · ⬜ planned`

| Phase | Milestones |
|---|---|
| **G1 — Meaning** | G1.1 ✅ G1.2 ✅ G1.3 ✅ G1.4 ✅ G1.5 ✅ |
| **G2 — Donations** | G2.1 ✅ G2.2 ✅ |
| **G3 — Zero-knowledge onboarding** | G3.1 ✅ G3.2 ✅ G3.3 ✅ |
| **G4 — Pro telemetry layer** | G4.1 ✅ G4.2 ✅ G4.3 ✅ |
| **G5 — Packet capture** | G5.1 ✅ G5.2 ✅ G5.3 ✅ |

---

## Phase G1 — Meaning (the visual upgrade)

**Goal:** the scene communicates *risk*, not just presence. A viewer who knows
nothing about networking should be able to glance at NETSCOPE and answer "am I
okay right now?"

**G1.1. Shared palette module. ✅** The five-color category map is currently
declared independently in at least five files (`Legend.tsx`, `Hud.tsx`,
`HoverTooltip.tsx`, `OrganismNodes.tsx`, `TendrilField.tsx`). Extract one shared
module (`frontend/src/scene/palette.ts`) before extending the encoding — severity
colors land on top of it.

**G1.2. Exposure score. ✅** A composite 0–100 score computed client-side from
signals already on the wire: tracker count, plaintext count, threat-feed matches,
unresolved-org ratio — weighted, normalized against total flows, and mapped to a
plain-language grade (e.g. *Protected / Fair / Exposed*). Replaces the raw-count
`ExposureSummary` chips as the HUD's headline while keeping the chips as the
drill-down. Pure function, unit-tested, documented weights — the eval-culture rule
applies: the score's formula is published, not vibes.

**G1.3. Severity visual channel. ✅** A per-node *severity* signal distinct from
category: flagged nodes (tracker ∧ plaintext, threat-feed match) get a visual
treatment that reads as "bad" at a glance — warm rim-light/pulse driven by a new
shader attribute, not a category recolor. Category answers *what is this*;
severity answers *should I worry*.

**G1.4. Exposure trend. ✅** A lightweight rolling window (last ~30 min) of the
exposure score, persisted to `localStorage` following the Warden audit-log pattern
— no server-side history, no change to the agent's ephemeral data model. Rendered
as a sparkline next to the score.

**G1.5. Meaning-first copy. ✅** `Legend` and `HelpOverlay` updated to explain the
score and severity channel in consumer language; the "what am I looking at" story
leads with *risk*, then category.

*Scope guard:* G1 is frontend-only. No agent, protocol, or persistence changes.

## Phase G2 — Donations

**G2.1. `FUNDING.yml`. ✅** GitHub-native Sponsor button (Buy Me a Coffee);
zero code.
**G2.2. In-app support link. ✅** A small, dismissible "Support NETSCOPE" link at
the bottom of the HUD — link-out only, no in-app payment processing, no new
compliance surface; dismissal persists via localStorage.

## Phase G3 — Zero-knowledge onboarding

**Goal:** every value-add feature enableable from inside the app — no terminal, no
env vars, no restart.

**G3.1. On-disk config. ✅** `config.rs`: JSON in the platform config dir
(`NETSCOPE_CONFIG_DIR` override), written by the UI's setup flow, env vars always
win. Today it stores the MaxMind key so a geoip refresh never asks twice.
**G3.2. In-app enablement. ✅** `/setup/status|geoip|threats` (loopback-only) +
`setup.rs` (the Rust twin of the downloader scripts): paste a MaxMind key in the
System panel → the agent downloads both GeoLite2 editions and hot-reloads the
enricher (`Enricher::reload_geo`); one click → threat feeds download and hot-swap
into the shared `ThreatDb`. No terminal, no restart; the scripts remain for CLI
users.
**G3.3. Good zero-config defaults. ✅** The System panel's hints now lead with
the in-app path; everything that needs no key (offline narrator, live view,
severity signals, exposure score) works out of the box.

## Phase G4 — Pro telemetry layer (devs & security folk)

Single-machine by design — depth, not fleet infrastructure.

**G4.1. Local history + export. ✅** `history.rs`: opt-in
(`NETSCOPE_HISTORY_DIR`) JSONL log of flow lifecycle events (open with full
metadata / close by id — never activity churn), rotated at 10 MB with one
predecessor; recorded in the coordinator before publish. HUD gains CSV/JSON
export of the current (filtered) view, fully client-side. Shipped **with** the
new "Data at rest" section in `docs/threat-model.md`; the ephemeral default
stands.
**G4.2. Deeper classification. ✅** `classify::category_with` accepts
user-supplied tracker keywords; the enricher loads them from
`NETSCOPE_TRACKER_KEYWORDS` (one substring per line, `#` comments). Extends the
curated built-ins, never replaces; the eval still grades the built-ins only so
the published numbers stay comparable.
**G4.3. Documented local API. ✅** `docs/protocol.md` gains "Consuming the feed
from your own tooling": the WS stream, the point-in-time JSON endpoints, and the
file surfaces (export + history JSONL), with the same compatibility contract the
frontend lives by.

*Deferred, deliberately:* multi-host fleet aggregation (a different product;
revisit if demand shows up); macOS capture backend (worthy, separate track).
Npcap/raw packet capture was on this list — it has since been taken as **G5**,
below, in a shape that keeps both original objections intact (opt-in twice, so
the default build/run still carries the measured <1 %-CPU, no-driver story).

## Phase G5 — Packet capture (the Npcap fork, taken)

The documented v2 upgrade: catch flows shorter than a poll tick and show
byte-true activity — as an **augmentation of** the polling engine, never a
replacement. Off unless compiled (`--features pcap`) *and* asked for
(`NETSCOPE_PCAP=1`) *and* the device opens (capture privilege).

**G5.1. Pure packet path. ✅** `capture/packet.rs`: header-only parsing
(Ethernet II + one VLAN tag / BSD-null / raw-IP framing; IPv4 + IPv6; TCP/UDP
port words and nothing past them), local↔remote orientation by interface
address, and the `PacketObserve` seam — all pure, compiled and tested on every
platform with no capture library.
**G5.2. Engine merge. ✅** Table-confirmed flows that moved bytes get log-scaled
byte-true activity in place of the coarse state placeholder; conversations the
table never showed are synthesized under the same flow-id scheme (so a later
table sighting is an update, not churn — and hands the table the lifecycle),
lingering `PKT_TTL` (3 s) past their last packet. No process attribution from
packets — pids come only from the table.
**G5.3. Device glue + surfacing. ✅** `capture/pcap.rs` (feature `pcap`):
libpcap/Npcap capture at snaplen 96 (headers are structurally all we ever hold),
kernel BPF `tcp or udp`, per-conversation counters drained once per poll.
Status ("active (eth0)" / off / unavailable / not built) in `/setup/status` and
the System panel. CI builds, lints, and tests the feature on Linux; release
builds stay feature-off. Windows needs the Npcap SDK at build time and the
Npcap driver at runtime — a from-source path today, documented honestly.

---

## Sequencing

G1 first (headline value, zero new risk), G2 alongside it (an afternoon), G3 next
(unlocks the features most users never turn on), G4 last (new persistence surface
deserves the most care). Each phase lands with its artifact: G1's score formula in
the code and Legend, G3's config schema in the README, G4's threat-model section
before the first byte hits disk.
