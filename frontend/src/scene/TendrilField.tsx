// Tendrils (ROADMAP B4): a luminous thread from the host core to every endpoint
// node, drawn as ONE instanced ribbon — the GPU path, no per-frame CPU rebuild
// (PITFALLS B4). The base geometry is a flat strip carrying only `t` (position.x)
// and the cross-side `±1` (position.y); the swaying 3D curve and camera-facing
// width are built in the vertex shader. Per-tendril data rides as instanced
// attributes, refreshed at UI rate when the world changes.
//
// A small central core marks the host machine where the tendrils converge.

import { useEffect, useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

import type { Flow } from "../protocol";
import { CATEGORY_COLOR } from "./palette";
import { severityOf } from "../store/exposure";
import { useNetscopeStore } from "../store/useNetscopeStore";
import { useViewStore } from "../store/useViewStore";
import { useRenderStore } from "./useRenderStore";
import { nodePhase, HOST_CENTER } from "./layout";
import { forceLayout } from "./force/forceLayout";
import { focusStateFor, isRelated, flowMatches } from "./relationships";
import { tendrilVertexShader, tendrilFragmentShader } from "./shaders/tendrils";

const MAX = 512; // matches OrganismNodes — one tendril per node
const SEGMENTS = 24;
const FOCUS_DIM = 0.12;

export function TendrilField() {
  const flows = useNetscopeStore((s) => s.flows);
  const selectedId = useRenderStore((s) => s.selectedId);
  const hoveredId = useRenderStore((s) => s.hoveredId);
  const focusId = useRenderStore((s) => s.focusId);
  const filter = useRenderStore((s) => s.filter);
  const layout = useViewStore((s) => s.layout);

  const meshRef = useRef<THREE.InstancedMesh>(null);
  // Per-instance flows for the per-frame endpoint rewrite when a dynamic layout runs.
  const listRef = useRef<Flow[]>([]);
  const lastVersion = useRef(-1);
  const tmpEnd = useMemo(() => new THREE.Vector3(), []);

  const list = useMemo(
    () => [...flows.values()].sort((a, b) => a.id.localeCompare(b.id)),
    [flows],
  );

  const focus = useMemo(
    () => focusStateFor(focusId ? flows.get(focusId) : undefined),
    [focusId, flows],
  );

  const gpu = useMemo(() => {
    // Strip geometry: (SEGMENTS+1) rings × 2 sides. position = (t, side, 0).
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
      new THREE.InstancedBufferAttribute(new Float32Array(MAX * n), n);
    const attrs = {
      aEnd: f32(3),
      aColor: f32(3),
      aActivity: f32(1),
      aPhase: f32(1),
      aAlive: f32(1),
      aSeverity: f32(1),
      aSelected: f32(1),
      aDim: f32(1),
    };
    for (const [name, attr] of Object.entries(attrs)) {
      geo.setAttribute(name, attr);
    }

    const material = new THREE.ShaderMaterial({
      vertexShader: tendrilVertexShader,
      fragmentShader: tendrilFragmentShader,
      uniforms: {
        uTime: { value: 0 },
        uStart: { value: HOST_CENTER.clone() },
      },
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

  useEffect(() => {
    const mesh = meshRef.current;
    if (!mesh) return;
    const { aEnd, aColor, aActivity, aPhase, aAlive, aSeverity, aSelected, aDim } = gpu.attrs;

    const count = Math.min(list.length, MAX);
    for (let i = 0; i < count; i++) {
      const f = list[i];
      forceLayout.getPosition(f, layout, tmpEnd);
      aEnd.setXYZ(i, tmpEnd.x, tmpEnd.y, tmpEnd.z);
      const c = CATEGORY_COLOR[f.category] ?? CATEGORY_COLOR.unknown;
      aColor.setXYZ(i, c.r, c.g, c.b);
      aActivity.setX(i, f.activity);
      aPhase.setX(i, nodePhase(f.id));
      aAlive.setX(i, f.alive ? 1 : 0);
      aSeverity.setX(i, severityOf(f)); // G1.3: risky threads warm toward warning
      aSelected.setX(i, f.id === selectedId ? 1 : f.id === hoveredId ? 0.5 : 0);
      aDim.setX(i, isRelated(f, focus) && flowMatches(f, filter) ? 1 : FOCUS_DIM);
    }
    listRef.current = list.slice(0, count);
    mesh.count = count;
    for (const a of Object.values(gpu.attrs)) a.needsUpdate = true;
  }, [list, selectedId, hoveredId, layout, focus, filter, gpu, tmpEnd]);

  useFrame((_, delta) => {
    gpu.material.uniforms.uTime.value += delta;

    // Dynamic layout active: stream the moving endpoints into aEnd — but only on
    // frames where positions actually changed (a settled layout stops re-uploading).
    if (layout === "category") return;
    if (forceLayout.version === lastVersion.current) return;
    lastVersion.current = forceLayout.version;
    const mesh = meshRef.current;
    if (!mesh) return;
    const nodes = listRef.current;
    const aEnd = gpu.attrs.aEnd;
    for (let i = 0; i < nodes.length; i++) {
      forceLayout.getPosition(nodes[i], layout, tmpEnd);
      aEnd.setXYZ(i, tmpEnd.x, tmpEnd.y, tmpEnd.z);
    }
    aEnd.needsUpdate = true;
  });

  return (
    // The visible host core is its own component (HostCore); the tendrils only
    // need HOST_CENTER as their shared origin uniform (set in `gpu`).
    <instancedMesh
      ref={meshRef}
      args={[gpu.geo, gpu.material, MAX]}
      frustumCulled={false}
      raycast={() => null}
    />
  );
}
