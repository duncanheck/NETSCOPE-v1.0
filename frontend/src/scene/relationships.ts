// Relationship model for the graph-exploration layer. The agent already attributes
// every flow to a process, an org (ASN), a country and a category — rich structure
// that the old "cluster by category anchor" layout threw away. This module turns
// that structure into two things the scene draws:
//
//   1. group keys   — which dimension nodes cluster by (process / org / country /
//                     category), so position becomes *meaningful* rather than a
//                     fixed blob per category (see layout.groupAnchor).
//   2. edges        — luminous links between endpoints that share a key (e.g. every
//                     flow owned by chrome, or every flow to AS15169), so the scene
//                     shows real relationships, not just a host→endpoint star.
//
// It is deliberately pure and dependency-light (only the protocol types + three's
// Color) so it can be unit-tested without a browser, like the force sim.

import * as THREE from "three";
import type { Flow } from "../protocol";

/** The dimension a relationship / grouping is keyed on. */
export type RelationKey = "process" | "org" | "country" | "category";

/** The value of `flow` along `key`, or null when the flow lacks it (e.g. a local
 *  flow has no org/country, a protected flow has no process). */
export function relationValue(flow: Flow, key: RelationKey): string | null {
  switch (key) {
    case "process":
      return flow.process?.name ?? null;
    case "org":
      return flow.asn?.org ?? null;
    case "country":
      return flow.location?.country ? flow.location.country : null;
    case "category":
      return flow.category;
  }
}

const UNKNOWN_LABEL: Record<RelationKey, string> = {
  process: "protected",
  org: "no org",
  country: "no geo",
  category: "unknown",
};

/** A human label for a flow's value along `key` (never null — for hulls/breadcrumbs). */
export function relationLabel(flow: Flow, key: RelationKey): string {
  return relationValue(flow, key) ?? UNKNOWN_LABEL[key];
}

/** A stable grouping key string for `flow` along `key`. Nulls collapse to a single
 *  "unknown" bucket so unattributable flows still cluster together (rather than each
 *  flying off to its own anchor). */
export function groupKey(flow: Flow, key: RelationKey): string {
  return relationValue(flow, key) ?? `∅${key}`;
}

// --- Focus / drill-down -----------------------------------------------------

/** What a focused node relates the rest of the world by. Prefers the owning process
 *  ("everything this app is talking to"), then the org, then the category — the same
 *  order the breadcrumb reads. */
export function focusRelation(flow: Flow): { key: RelationKey; value: string | null } {
  if (flow.process?.name) return { key: "process", value: flow.process.name };
  if (flow.asn?.org) return { key: "org", value: flow.asn.org };
  return { key: "category", value: flow.category };
}

export interface FocusState {
  id: string;
  key: RelationKey;
  value: string | null;
}

/** Build the focus descriptor for the focused flow, or null when nothing is focused. */
export function focusStateFor(flow: Flow | undefined): FocusState | null {
  if (!flow) return null;
  const rel = focusRelation(flow);
  return { id: flow.id, key: rel.key, value: rel.value };
}

/** True when `flow` is the focused node or shares its relation value — i.e. it should
 *  stay lit while everything else dims. */
export function isRelated(flow: Flow, focus: FocusState | null): boolean {
  if (!focus) return true;
  if (flow.id === focus.id) return true;
  if (focus.value == null) return false;
  return relationValue(flow, focus.key) === focus.value;
}

/** Free-text match across a flow's host / process / org / category / ip / port —
 *  the predicate behind both the connection list filter and the scene isolation, so
 *  typing a query lights only the matching nodes in 3D. Empty query matches all.
 *
 *  A few structured shortcuts are recognised so the exposure chips (and a typed
 *  query) can isolate by security posture, which has no plain text field:
 *  `plaintext` / `unencrypted` → unencrypted flows, `encrypted` → encrypted ones. */
export function flowMatches(flow: Flow, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  if (q === "plaintext" || q === "unencrypted") return !flow.encrypted;
  if (q === "encrypted") return flow.encrypted;
  return [flow.name, flow.process?.name, flow.asn?.org, flow.category, flow.ip, String(flow.port)]
    .filter(Boolean)
    .some((field) => (field as string).toLowerCase().includes(q));
}

// --- Edges ------------------------------------------------------------------

/** Edges are colored by the relation dimension so the link type reads at a glance. */
export const EDGE_COLOR: Record<RelationKey, THREE.Color> = {
  process: new THREE.Color("#7ad7c4"),
  org: new THREE.Color("#5ec8ff"),
  country: new THREE.Color("#b79cff"),
  category: new THREE.Color("#9fb4c7"),
};

export interface Edge {
  aId: string;
  bId: string;
  key: RelationKey;
  value: string;
}

/** A hard cap so a pathological world (one huge group) can't exceed the instanced
 *  buffer or flood the scene; the busiest groups win. */
export const EDGE_MAX = 384;

/**
 * Compute relationship edges among `flows` keyed on `key`. To stay O(n) and legible,
 * each group is drawn as a **star** to its busiest (highest-activity) member — the
 * natural hub — rather than a full mesh (which would be O(n²) edges and visual soup).
 * Groups of one contribute nothing. Nulls are skipped (an "unknown" star would be
 * meaningless). Capped at {@link EDGE_MAX}, busiest groups first.
 */
export function computeEdges(flows: Iterable<Flow>, key: RelationKey): Edge[] {
  const groups = new Map<string, Flow[]>();
  for (const f of flows) {
    const v = relationValue(f, key);
    if (v == null) continue;
    const bucket = groups.get(v);
    if (bucket) bucket.push(f);
    else groups.set(v, [f]);
  }

  // Order groups by total activity so the most significant relationships survive the cap.
  const ordered = [...groups.entries()]
    .filter(([, members]) => members.length >= 2)
    .sort(
      (a, b) =>
        b[1].reduce((s, f) => s + f.activity, 0) - a[1].reduce((s, f) => s + f.activity, 0),
    );

  const edges: Edge[] = [];
  for (const [value, members] of ordered) {
    // Hub = busiest member (ties broken by id for determinism).
    const hub = members.reduce((best, f) =>
      f.activity > best.activity || (f.activity === best.activity && f.id < best.id) ? f : best,
    );
    for (const m of members) {
      if (m.id === hub.id) continue;
      edges.push({ aId: hub.id, bId: m.id, key, value });
      if (edges.length >= EDGE_MAX) return edges;
    }
  }
  return edges;
}
