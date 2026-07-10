// Relationship edges — the graph-exploration layer. Draws a faint instanced ribbon
// between every pair of endpoint nodes that share the chosen relationship key (same
// process / org / country), turning the host→endpoint star into an actual graph.
//
// It follows the TendrilField pattern exactly: one InstancedMesh, per-instance
// endpoints (aStart/aEnd) refreshed at UI rate when the edge set changes, and a
// per-frame rewrite of just the moving endpoints when a dynamic layout is active —
// no per-frame CPU geometry rebuild. The edge set itself is recomputed (cheaply,
// O(n)) only when the world or the relationship key changes.

import { useEffect, useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

import type { Flow } from "../protocol";
import { useNetscopeStore } from "../store/useNetscopeStore";
import { useViewStore } from "../store/useViewStore";
import { useRenderStore } from "./useRenderStore";
import { forceLayout } from "./force/forceLayout";
import {
  EDGE_COLOR,
  EDGE_MAX,
  computeEdges,
  focusStateFor,
  isRelated,
  flowMatches,
  relationValue,
  type Edge,
} from "./relationships";
import { edgeVertexShader, edgeFragmentShader } from "./shaders/edges";

const SEGMENTS = 12;
const FOCUS_DIM = 0.12;

export function RelationshipEdges() {
  const flows = useNetscopeStore((s) => s.flows);
  const showEdges = useViewStore((s) => s.showEdges);
  const edgeBy = useViewStore((s) => s.edgeBy);
  const layout = useViewStore((s) => s.layout);
  const focusId = useRenderStore((s) => s.focusId);
  const selectedId = useRenderStore((s) => s.selectedId);
  const filter = useRenderStore((s) => s.filter);

  const meshRef = useRef<THREE.InstancedMesh>(null);
  // Per-instance endpoint flows for the per-frame rewrite when the layout moves.
  const pairsRef = useRef<{ a: Flow; b: Flow }[]>([]);
  const lastVersion = useRef(-1);
  const tmpA = useMemo(() => new THREE.Vector3(), []);
  const tmpB = useMemo(() => new THREE.Vector3(), []);

  // The "anchor" node whose specific links we always show, even when the global
  // edges toggle is off — so selecting (or focusing) a node reveals exactly its
  // connections without flooding a 200-node world with every relationship.
  const anchorId = focusId ?? selectedId;

  // The edge set: all relationships when globally on; otherwise just the anchor
  // node's group (its specific links). Cheap to recompute, only on real changes.
  const edges = useMemo<Edge[]>(() => {
    if (showEdges) return computeEdges(flows.values(), edgeBy);
    if (anchorId) {
      const f = flows.get(anchorId);
      const value = f ? relationValue(f, edgeBy) : null;
      if (value == null) return [];
      const group = [...flows.values()].filter((g) => relationValue(g, edgeBy) === value);
      return computeEdges(group, edgeBy);
    }
    return [];
  }, [flows, edgeBy, showEdges, anchorId]);

  // Focus descriptor (for dimming edges outside the focused relationship).
  const focus = useMemo(
    () => focusStateFor(focusId ? flows.get(focusId) : undefined),
    [focusId, flows],
  );

  const gpu = useMemo(() => {
    const verts = (SEGMENTS + 1) * 2;
    const positions = new Float32Array(verts * 3);
    for (let i = 0; i <= SEGMENTS; i++) {
      const t = i / SEGMENTS;
      for (let s = 0; s < 2; s++) {
        const idx = i * 2 + s;
        positions[idx * 3] = t;
        positions[idx * 3 + 1] = s === 0 ? -1 : 1;
        positions[idx * 3 + 2] = 0;
      }
    }
    const indices: number[] = [];
    for (let i = 0; i < SEGMENTS; i++) {
      const a = i * 2;
      const b = i * 2 + 1;
      const c = (i + 1) * 2;
      const d = (i + 1) * 2 + 1;
      indices.push(a, b, c, b, d, c);
    }
    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    geo.setIndex(indices);

    const f32 = (n: number) =>
      new THREE.InstancedBufferAttribute(new Float32Array(EDGE_MAX * n), n);
    const attrs = {
      aStart: f32(3),
      aEnd: f32(3),
      aColor: f32(3),
      aDim: f32(1),
    };
    for (const [name, attr] of Object.entries(attrs)) geo.setAttribute(name, attr);

    const material = new THREE.ShaderMaterial({
      vertexShader: edgeVertexShader,
      fragmentShader: edgeFragmentShader,
      uniforms: { uTime: { value: 0 } },
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      side: THREE.DoubleSide,
    });

    return { geo, material, attrs };
  }, []);

  useEffect(() => {
    return () => {
      gpu.geo.dispose();
      gpu.material.dispose();
    };
  }, [gpu]);

  // Fill instance data when the edge set, layout or focus changes (UI rate).
  useEffect(() => {
    const mesh = meshRef.current;
    if (!mesh) return;
    const { aStart, aEnd, aColor, aDim } = gpu.attrs;

    const pairs: { a: Flow; b: Flow }[] = [];
    const count = Math.min(edges.length, EDGE_MAX);
    for (let i = 0; i < count; i++) {
      const e = edges[i];
      const a = flows.get(e.aId);
      const b = flows.get(e.bId);
      if (!a || !b) continue;
      pairs.push({ a, b });
      const idx = pairs.length - 1;
      forceLayout.getPosition(a, layout, tmpA);
      forceLayout.getPosition(b, layout, tmpB);
      aStart.setXYZ(idx, tmpA.x, tmpA.y, tmpA.z);
      aEnd.setXYZ(idx, tmpB.x, tmpB.y, tmpB.z);
      const c = EDGE_COLOR[e.key];
      aColor.setXYZ(idx, c.r, c.g, c.b);
      // An edge is lit only when both ends are in the focused relationship and match
      // the active filter — so links follow the same isolation as the nodes.
      const lit =
        isRelated(a, focus) &&
        isRelated(b, focus) &&
        flowMatches(a, filter) &&
        flowMatches(b, filter);
      aDim.setX(idx, lit ? 1 : FOCUS_DIM);
    }

    pairsRef.current = pairs;
    mesh.count = pairs.length;
    for (const attr of Object.values(gpu.attrs)) attr.needsUpdate = true;
  }, [edges, flows, layout, focus, filter, gpu, tmpA, tmpB]);

  useFrame((_, delta) => {
    gpu.material.uniforms.uTime.value += delta;

    // Stream moving endpoints when a dynamic layout is active — only on frames where
    // positions changed, so a settled layout stops re-uploading.
    if (layout === "category") return;
    if (forceLayout.version === lastVersion.current) return;
    lastVersion.current = forceLayout.version;
    const mesh = meshRef.current;
    if (!mesh) return;
    const pairs = pairsRef.current;
    const { aStart, aEnd } = gpu.attrs;
    for (let i = 0; i < pairs.length; i++) {
      forceLayout.getPosition(pairs[i].a, layout, tmpA);
      forceLayout.getPosition(pairs[i].b, layout, tmpB);
      aStart.setXYZ(i, tmpA.x, tmpA.y, tmpA.z);
      aEnd.setXYZ(i, tmpB.x, tmpB.y, tmpB.z);
    }
    aStart.needsUpdate = true;
    aEnd.needsUpdate = true;
  });

  return (
    <instancedMesh
      ref={meshRef}
      args={[gpu.geo, gpu.material, EDGE_MAX]}
      frustumCulled={false}
      raycast={() => null}
    />
  );
}
