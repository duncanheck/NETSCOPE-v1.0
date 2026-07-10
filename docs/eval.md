# docs/eval.md — Does the AI layer actually get it right? (D3)

*Status: **landed (D3).** A reproducible, offline eval of the classification the
whole narrator rests on — run in CI, numbers below are real and include the
failures.*

## Why eval the classifier, not the prose

The narrator (D2) explains your traffic. But an LLM narrating a session can only be
as right as the **classification** underneath it — is this flow a tracker? a CDN? is
it plaintext? If the classifier is wrong, the explanation is confidently wrong. So
the honest, gradeable question — *"when are the explanations wrong?"* — reduces to
*"how often is the classifier wrong?"*, which is measurable without a model.

This is the part that separates the feature from portfolio-cliché AI integration:
not "we called an LLM," but "here is a labeled set, here is the accuracy, here are
the cases we miss."

## Method

`netscope-narrator::eval` runs a labeled set of 36 real-world-shaped endpoints
through the **exact** [`classify`](../agent/crates/narrator/src/classify.rs) policy
the agent ships (the same `category` / `security_flags` functions used in the live
capture path — there is no separate eval-only copy). It tallies category accuracy,
tracker precision/recall, and plaintext-detection accuracy. The dataset deliberately
includes endpoints the curated keyword heuristic **cannot** catch, because the point
of an eval is to surface the misses, not hide them.

Reproduce:

```bash
cargo test -p netscope-narrator eval -- --nocapture
```

## Results (n = 36)

| Metric | Score |
|---|---|
| **Category accuracy** | **83.3 %** (30/36) |
| Tracker **precision** | 90.9 % |
| Tracker **recall** | 71.4 % (tp 10 · fp 1 · fn 4) |
| Plaintext detection | 100 % |

### Where it's wrong, and why (the honest part)

| Endpoint | Truth | Classifier | Why it misses |
|---|---|---|---|
| `connect.facebook.net` | tracker | service | Facebook's tracking pixels carry no keyword in host or org |
| `graph.facebook.com` | tracker | service | same — "Facebook" isn't in the tracker keyword list |
| `pixel.tapad.com` | tracker | service | identity-graph vendor, not in the curated list |
| `t.co` | tracker | service | Twitter's click-tracker; nothing to match on |
| `app.acme-analytics-suite.com` | service | tracker | the **one false positive**: a legit BI tool trips the `analytics` substring |
| `fonts.gstatic.com` | cdn | service | Google's static CDN; org is "Google", host has no CDN keyword |

The pattern is clear and expected: the keyword heuristic has **high precision, lower
recall** — it rarely cries wolf (one FP in 36), but it misses trackers that don't
advertise themselves in their name or org (first-party tracking endpoints from big
platforms). Plaintext detection is exact because it's a pure function of the port /
encrypted flag, not a heuristic.

## What this tells the narrator

When the narrator says "no trackers here," it's trustworthy when the trackers are
the obvious third-party ones (DoubleClick, ScoreCardResearch, Amplitude, …) and
**under-counts** first-party platform tracking. The README and the explanation copy
should — and do — frame the classification as *a curated heuristic, not a
comprehensive blocklist*. The path to higher recall is a real tracker list (e.g. a
DisconnectMe/EasyList-derived set), which this eval is built to measure the gain of.

## The LLM layer

The LLM providers (Ollama, Claude) narrate on top of this same classified, scrubbed
substrate, so their factual accuracy is bounded by the numbers above. Grading
free-text explanations needs a model in the loop, so it's a manual step rather than
a CI gate — but it grades against this dataset, so the ground truth is shared.
