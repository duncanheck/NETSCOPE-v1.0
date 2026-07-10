// Organism nodes (ROADMAP B3). The whole endpoint set is drawn as ONE InstancedMesh
// of vertex-displaced icospheres (the bioluminescent cells), with a second instanced
// layer of additive glow halos behind them as bloom accents. Per-node colour,
// activity, exposed/plaintext, selection, liveness and focus-dim all ride as
// per-instance attributes, so node count costs draw calls of one each (PITFALLS B3).
//
// Picking is R3F's raycast against the *undisplaced* icospheres (the displacement
// is shader-only), exactly the PITFALLS B3 rule: pick the logical sphere, not the
// wobbling surface. Click selects (opens the inspector); double-click *focuses* the
// node for drill-down. Selection/hover/focus live in the render store, shared with
// the HUD; the layout mode lives in the view store, shared with the tendrils + edges.

import { useEffect, useMemo, useRef } from "react";
import { useFrame, type ThreeEvent } from "@react-three/fiber";
import * as THREE from "three";

import type { Flow } from "../protocol";
import { CATEGORY_COLOR } from "./palette";
import { severityOf } from "../store/exposure";
import { useNetscopeStore } from "../store/useNetscopeStore";
import { useViewStore } from "../store/useViewStore";
import { useRenderStore } from "./useRenderStore";
import { nodePhase } from "./layout";
import { forceLayout } from "./force/forceLayout";
import { focusStateFor, isRelated, flowMatches, groupKey, type RelationKey } from "./relationships";
import {
  nodeVertexShader,
  nodeFragmentShader,
  glowVertexShader,
  glowFragmentShader,
} from "./shaders/organism";

// Instanced-buffer ceiling. Sized for busy professional machines (a few hundred
// live connections) so the organism doesn't silently render fewer nodes than the
// connection list reports.
const MAX = 512;
const FOCUS_DIM = 0.12;

export function OrganismNodes() {
  const flows = useNetscopeStore((s) => s.flows);
  const selectedId = useRenderStore((s) => s.selectedId);
  const hoveredId = useRenderStore((s) => s.hoveredId);
  const focusId = useRenderStore((s) => s.focusId);
  const select = useRenderStore((s) => s.select);
  const hover = useRenderStore((s) => s.hover);
  const setFocus = useRenderStore((s) => s.setFocus);
  const filter = useRenderStore((s) => s.filter);
  const layout = useViewStore((s) => s.layout);
  // Node roundness scales with the measured GPU tier (4 = glassy on capable
  // hardware, 3 = cheap on weak/mobile). Falls back to 3 until the probe lands.
  const nodeDetail = useRenderStore((s) => s.tier?.nodeDetail ?? 3);

  const nodeRef = useRef<THREE.InstancedMesh>(null);
  const glowRef = useRef<THREE.InstancedMesh>(null);

  // Stable instance order (by id) so a node keeps its slot across updates.
  const list = useMemo(
    () => [...flows.values()].sort((a, b) => a.id.localeCompare(b.id)),
    [flows],
  );
  // Per-instance bookkeeping: ids for click→flow lookup, the flow + radius at each
  // index for the per-frame matrix rewrite when a dynamic layout is active.
  const idsRef = useRef<string[]>([]);
  const listRef = useRef<Flow[]>([]);
  const radiiRef = useRef<number[]>([]);
  // The forceLayout position-version we last wrote, so we skip the per-frame matrix
  // rewrite + GPU upload on frames where nothing moved (e.g. a settled layout).
  const lastVersion = useRef(-1);
  // Reusable temporaries for the per-frame force-position rewrite.
  const tmp = useMemo(
    () => ({
      pos: new THREE.Vector3(),
      mat: new THREE.Matrix4(),
      tr: new THREE.Matrix4(),
      quat: new THREE.Quaternion(),
      scl: new THREE.Vector3(),
    }),
    [],
  );

  // The focus descriptor (the relationship lit while everything else dims).
  const focus = useMemo(
    () => focusStateFor(focusId ? flows.get(focusId) : undefined),
    [focusId, flows],
  );

  // A signature of only the layout-relevant state: the node set + each node's group
  // under the current mode (plus count, which drives the spread). It deliberately
  // ignores activity — which drifts on nearly every delta — so we don't re-push the
  // world to the force worker constantly and prevent the sim from ever settling.
  const layoutSig = useMemo(() => {
    if (layout === "category") return `category:${list.length}`;
    const relKey: RelationKey =
      layout === "process" || layout === "org" || layout === "country" ? layout : "category";
    let h = 2166136261 >>> 0;
    for (const f of list) {
      const s = `${f.id}|${groupKey(f, relKey)}`;
      for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
    }
    return `${layout}:${list.length}:${(h >>> 0).toString(36)}`;
  }, [list, layout]);

  // Drive the force-layout worker only when that signature changes (a node added/
  // removed, a re-grouping, or a mode switch) — not on activity-only deltas.
  useEffect(() => {
    forceLayout.update(flows, layout);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layoutSig]);
  useEffect(() => () => forceLayout.dispose(), []);

  // GPU resources: geometries, shared instanced attributes, and materials.
  const gpu = useMemo(() => {
    const nodeGeo = new THREE.IcosahedronGeometry(1, nodeDetail);
    const glowGeo = new THREE.PlaneGeometry(1, 1);

    const f32 = (n: number) => new THREE.InstancedBufferAttribute(new Float32Array(MAX * n), n);
    // Shared between node + glow where the value is identical.
    const aColor = f32(3);
    const aActivity = f32(1);
    const aSeverity = f32(1);
    const aSelected = f32(1);
    const aAlive = f32(1);
    const aDim = f32(1);
    // Node-only.
    const aPhase = f32(1);
    const aExposed = f32(1);
    // Glow-only.
    const aSize = f32(1);

    for (const [name, attr] of [
      ["aColor", aColor],
      ["aActivity", aActivity],
      ["aSeverity", aSeverity],
      ["aSelected", aSelected],
      ["aAlive", aAlive],
      ["aDim", aDim],
      ["aPhase", aPhase],
      ["aExposed", aExposed],
    ] as const) {
      nodeGeo.setAttribute(name, attr);
    }
    for (const [name, attr] of [
      ["aColor", aColor],
      ["aActivity", aActivity],
      ["aSeverity", aSeverity],
      ["aSelected", aSelected],
      ["aAlive", aAlive],
      ["aDim", aDim],
      ["aSize", aSize],
    ] as const) {
      glowGeo.setAttribute(name, attr);
    }

    const nodeMat = new THREE.ShaderMaterial({
      vertexShader: nodeVertexShader,
      fragmentShader: nodeFragmentShader,
      uniforms: { uTime: { value: 0 } },
    });
    const glowMat = new THREE.ShaderMaterial({
      vertexShader: glowVertexShader,
      fragmentShader: glowFragmentShader,
      uniforms: { uTime: { value: 0 } },
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
    });

    return {
      nodeGeo,
      glowGeo,
      nodeMat,
      glowMat,
      attrs: { aColor, aActivity, aSeverity, aSelected, aAlive, aDim, aPhase, aExposed, aSize },
    };
    // Rebuilt only if the node subdivision changes (i.e. the GPU tier probe
    // lands and bumps LOW→HIGH). The `[gpu]` cleanup effect disposes the old
    // geometry/materials on the swap, so it's a clean one-time startup blip.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeDetail]);

  useEffect(() => {
    return () => {
      gpu.nodeGeo.dispose();
      gpu.glowGeo.dispose();
      gpu.nodeMat.dispose();
      gpu.glowMat.dispose();
    };
  }, [gpu]);

  // Re-fill instance data whenever the world, selection/hover, layout or focus
  // changes. UI-rate work (PITFALLS B1); per-frame values (uTime, moving positions)
  // go through the uniform / the per-frame loop instead.
  useEffect(() => {
    const nodeMesh = nodeRef.current;
    const glowMesh = glowRef.current;
    if (!nodeMesh || !glowMesh) return;

    const { aColor, aActivity, aSeverity, aSelected, aAlive, aDim, aPhase, aExposed, aSize } =
      gpu.attrs;
    const m = new THREE.Matrix4();
    const t = new THREE.Matrix4();
    const q = new THREE.Quaternion();
    const scale = new THREE.Vector3();
    const pos = new THREE.Vector3();
    const ids: string[] = [];
    const radii: number[] = [];

    const count = Math.min(list.length, MAX);
    for (let i = 0; i < count; i++) {
      const f: Flow = list[i];
      ids.push(f.id);
      forceLayout.getPosition(f, layout, pos);
      const radius = 0.32 + f.activity * 0.5;
      radii.push(radius);

      scale.setScalar(radius);
      m.compose(pos, q, scale);
      nodeMesh.setMatrixAt(i, m);
      t.makeTranslation(pos.x, pos.y, pos.z);
      glowMesh.setMatrixAt(i, t);

      const c = CATEGORY_COLOR[f.category] ?? CATEGORY_COLOR.unknown;
      aColor.setXYZ(i, c.r, c.g, c.b);
      aActivity.setX(i, f.activity);
      aPhase.setX(i, nodePhase(f.id));
      aExposed.setX(i, f.encrypted ? 0 : 1); // plaintext = exposed
      aSeverity.setX(i, severityOf(f)); // G1.3 warm warning rim, graded
      aAlive.setX(i, f.alive ? 1 : 0);
      aSize.setX(i, radius * 4.4);
      // Lit only when in the focused relationship AND matching the active filter —
      // so the search box and focus both isolate the nodes you care about.
      const lit = isRelated(f, focus) && flowMatches(f, filter);
      aDim.setX(i, lit ? 1 : FOCUS_DIM);
      const sel = f.id === selectedId ? 1 : f.id === hoveredId ? 0.5 : 0;
      aSelected.setX(i, sel);
    }

    idsRef.current = ids;
    listRef.current = list.slice(0, count);
    radiiRef.current = radii;
    nodeMesh.count = count;
    glowMesh.count = count;
    nodeMesh.instanceMatrix.needsUpdate = true;
    glowMesh.instanceMatrix.needsUpdate = true;
    for (const a of [aColor, aActivity, aSeverity, aSelected, aAlive, aDim, aPhase, aExposed, aSize]) {
      a.needsUpdate = true;
    }
    // Bounds for correct frustum/raycast after matrices change.
    nodeMesh.computeBoundingSphere();
  }, [list, selectedId, hoveredId, layout, focus, filter, gpu]);

  useFrame((_, delta) => {
    gpu.nodeMat.uniforms.uTime.value += delta;
    gpu.glowMat.uniforms.uTime.value += delta;

    // When a dynamic layout is active, the worker streams new positions; rewrite the
    // instance matrices from them (per-frame transform work, not React state —
    // PITFALLS B1). The static `category` layout skips this, and a settled layout
    // (no version change since last write) skips the rewrite + upload entirely.
    if (layout === "category") return;
    if (forceLayout.version === lastVersion.current) return;
    lastVersion.current = forceLayout.version;
    const nodeMesh = nodeRef.current;
    const glowMesh = glowRef.current;
    if (!nodeMesh || !glowMesh) return;
    const nodes = listRef.current;
    const radii = radiiRef.current;
    for (let i = 0; i < nodes.length; i++) {
      forceLayout.getPosition(nodes[i], layout, tmp.pos);
      tmp.scl.setScalar(radii[i]);
      tmp.mat.compose(tmp.pos, tmp.quat, tmp.scl);
      nodeMesh.setMatrixAt(i, tmp.mat);
      tmp.tr.makeTranslation(tmp.pos.x, tmp.pos.y, tmp.pos.z);
      glowMesh.setMatrixAt(i, tmp.tr);
    }
    nodeMesh.instanceMatrix.needsUpdate = true;
    glowMesh.instanceMatrix.needsUpdate = true;
  });

  const onClick = (e: ThreeEvent<MouseEvent>) => {
    e.stopPropagation();
    const id = e.instanceId != null ? idsRef.current[e.instanceId] : undefined;
    if (id) select(id);
  };
  const onDoubleClick = (e: ThreeEvent<MouseEvent>) => {
    e.stopPropagation();
    const id = e.instanceId != null ? idsRef.current[e.instanceId] : undefined;
    if (id) setFocus(id);
  };
  const onMove = (e: ThreeEvent<PointerEvent>) => {
    const id = e.instanceId != null ? idsRef.current[e.instanceId] : undefined;
    hover(id ?? null);
    document.body.style.cursor = id ? "pointer" : "auto";
  };
  const onOut = () => {
    hover(null);
    document.body.style.cursor = "auto";
  };

  return (
    <group>
      {/* Glow halos behind the cells; never intercept picking. */}
      <instancedMesh
        ref={glowRef}
        args={[gpu.glowGeo, gpu.glowMat, MAX]}
        frustumCulled={false}
        raycast={() => null}
      />
      {/* The cells — picked against their undisplaced spheres. */}
      <instancedMesh
        ref={nodeRef}
        args={[gpu.nodeGeo, gpu.nodeMat, MAX]}
        frustumCulled={false}
        onClick={onClick}
        onDoubleClick={onDoubleClick}
        onPointerMove={onMove}
        onPointerOut={onOut}
      />
    </group>
  );
}
