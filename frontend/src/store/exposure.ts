// The exposure score (GROWTH G1.2) — the "am I okay right now?" number. The HUD's
// old exposure row was raw counts; this turns the same live signals into one
// graded 0–100 score a non-technical viewer can read at a glance, with the counts
// kept underneath as the drill-down.
//
// The eval-culture rule applies (docs/eval.md): the formula is published here, in
// one pure, tested function — not vibes. What it measures and what it can't:
// it grades the *visible* session (alive flows, this machine, right now) on the
// same flags the agent already emits (tracker, plaintext, unresolved_org). It is
// not a malware verdict and inherits the classifier's measured limits (83.3 %
// category accuracy, 71.4 % tracker recall — docs/eval.md).
//
// The formula, in full:
//   Only *alive, non-local* flows count (local-network chatter isn't exposure;
//   closed-but-lingering flows are history, not posture).
//   ratio penalty (up to 70 pts): 70 × (0.50·trackerRatio + 0.35·plaintextRatio
//     + 0.15·unresolvedRatio) — what *fraction* of your traffic is risky.
//   presence penalty (up to 30 pts): any tracker −15, any plaintext −10, any
//     unresolved-org −5 — so a single tracker among 200 clean flows still moves
//     the grade, because "one tracker" matters to a person even at 0.5 % of flows.
//   score = 100 − ratio − presence, clamped to [0, 100].
// Grades: ≥90 protected · ≥70 guarded · ≥40 exposed · <40 at risk.

import type { Flow } from "../protocol";

export type Grade = "protected" | "guarded" | "exposed" | "at risk";

export interface Exposure {
  score: number; // 0–100, integer
  grade: Grade;
  /** Alive, non-local flows the score was computed over. */
  considered: number;
  trackers: number;
  plaintext: number;
  unresolved: number;
}

const RATIO_POINTS = 70;
const W_TRACKER = 0.5;
const W_PLAINTEXT = 0.35;
const W_UNRESOLVED = 0.15;
const PRESENCE_TRACKER = 15;
const PRESENCE_PLAINTEXT = 10;
const PRESENCE_UNRESOLVED = 5;

export function gradeOf(score: number): Grade {
  if (score >= 90) return "protected";
  if (score >= 70) return "guarded";
  if (score >= 40) return "exposed";
  return "at risk";
}

export function exposureScore(flows: Iterable<Flow>): Exposure {
  let considered = 0;
  let trackers = 0;
  let plaintext = 0;
  let unresolved = 0;

  for (const f of flows) {
    if (!f.alive || f.category === "local") continue;
    considered++;
    if (f.category === "tracker" || f.flags.includes("tracker")) trackers++;
    if (!f.encrypted) plaintext++;
    if (f.flags.includes("unresolved_org")) unresolved++;
  }

  if (considered === 0) {
    return { score: 100, grade: "protected", considered, trackers, plaintext, unresolved };
  }

  const ratio =
    RATIO_POINTS *
    ((W_TRACKER * trackers + W_PLAINTEXT * plaintext + W_UNRESOLVED * unresolved) / considered);
  const presence =
    (trackers > 0 ? PRESENCE_TRACKER : 0) +
    (plaintext > 0 ? PRESENCE_PLAINTEXT : 0) +
    (unresolved > 0 ? PRESENCE_UNRESOLVED : 0);

  const score = Math.max(0, Math.min(100, Math.round(100 - ratio - presence)));
  return { score, grade: gradeOf(score), considered, trackers, plaintext, unresolved };
}

/** Grade → the HUD accent colour the score renders in (matches the chip palette). */
export function gradeColor(grade: Grade): string {
  switch (grade) {
    case "protected":
      return "var(--accent)";
    case "guarded":
      return "#ffb347";
    default:
      return "#ff8da3";
  }
}

// Per-node severity (G1.3): the *should I worry* channel the scene renders as a
// warm rim, distinct from category hue. Graded, worst first, so worse reads
// hotter; local flows are never severe (they're inside your own network — the
// Warden's protected floor makes the same call).
export function severityOf(f: Flow): number {
  if (f.category === "local") return 0;
  const tracker = f.category === "tracker" || f.flags.includes("tracker");
  if (tracker && !f.encrypted) return 1.0;
  if (tracker) return 0.7;
  if (!f.encrypted) return 0.5;
  if (f.flags.includes("unresolved_org")) return 0.25;
  return 0;
}

// The exposure trend (G1.4): a rolling window of score samples so the HUD can show
// where the session has been, not just where it is. Persisted to localStorage —
// the same client-side pattern as the Warden audit log — so the agent's
// ephemeral, nothing-on-disk data model is untouched.

export interface TrendSample {
  ts: number;
  score: number;
}

export const TREND_KEY = "netscope.exposure.trend";
export const TREND_WINDOW_MS = 30 * 60 * 1000; // 30 minutes
export const TREND_SAMPLE_MS = 20 * 1000; // one sample per 20 s

/** Drop samples older than the window; oldest-first order is preserved. */
export function pruneTrend(samples: TrendSample[], now: number): TrendSample[] {
  return samples.filter((s) => now - s.ts <= TREND_WINDOW_MS);
}

/**
 * Append a sample if the newest one is older than the sample interval; always
 * prunes. Pure — the caller owns persistence.
 */
export function appendSample(samples: TrendSample[], score: number, now: number): TrendSample[] {
  const kept = pruneTrend(samples, now);
  const last = kept[kept.length - 1];
  if (last && now - last.ts < TREND_SAMPLE_MS) return kept;
  return [...kept, { ts: now, score }];
}

export function loadTrend(): TrendSample[] {
  try {
    const raw = localStorage.getItem(TREND_KEY);
    return raw ? pruneTrend(JSON.parse(raw) as TrendSample[], Date.now()) : [];
  } catch {
    return [];
  }
}

function saveTrend(samples: TrendSample[]) {
  try {
    localStorage.setItem(TREND_KEY, JSON.stringify(samples));
  } catch {
    /* private mode / quota — non-fatal */
  }
}

/** Load-append-save in one step; returns the updated window for rendering. */
export function recordSample(score: number, now = Date.now()): TrendSample[] {
  const next = appendSample(loadTrend(), score, now);
  saveTrend(next);
  return next;
}
