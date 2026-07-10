// Marine snow (ROADMAP B2): three parallax layers of slowly sinking detritus,
// the prototype's particle field re-cast for the deep sea (SALVAGE.md). Each layer
// is a single `Points` draw with all motion in the vertex shader; the only
// per-frame CPU cost is one time-uniform write per layer (PITFALLS B1).

import { useMemo, useRef } from "react";
import { useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";

import { snowVertexShader, snowFragmentShader } from "./shaders/marineSnow";
import { useRenderStore } from "./useRenderStore";

interface LayerSpec {
  count: number; // particle count at full density
  spread: number; // half-width of the box volume
  halfHeight: number;
  fallSpeed: number;
  swayAmp: number;
  size: number;
  opacity: number;
}

// Near layer: fewer, larger, faster, brighter. Far layers: denser, finer, dimmer.
const LAYERS: LayerSpec[] = [
  { count: 140, spread: 9, halfHeight: 7, fallSpeed: 0.45, swayAmp: 0.25, size: 26, opacity: 0.5 },
  { count: 220, spread: 13, halfHeight: 9, fallSpeed: 0.3, swayAmp: 0.18, size: 16, opacity: 0.38 },
  { count: 320, spread: 18, halfHeight: 12, fallSpeed: 0.18, swayAmp: 0.12, size: 10, opacity: 0.26 },
];

const SNOW_COLOR = new THREE.Color("#bfeaf0");

export function MarineSnow() {
  const tier = useRenderStore((s) => s.tier);
  const density = tier?.snowDensity ?? 1;
  const animate = tier?.animate ?? true;

  return (
    <group>
      {LAYERS.map((spec, i) => (
        <SnowLayer key={i} spec={spec} density={density} animate={animate} />
      ))}
    </group>
  );
}

function SnowLayer({
  spec,
  density,
  animate,
}: {
  spec: LayerSpec;
  density: number;
  animate: boolean;
}) {
  const dpr = useThree((s) => s.viewport.dpr);
  const material = useRef<THREE.ShaderMaterial>(null);

  const geometry = useMemo(() => {
    const count = Math.max(1, Math.floor(spec.count * density));
    const positions = new Float32Array(count * 3);
    const seeds = new Float32Array(count);
    for (let i = 0; i < count; i++) {
      positions[i * 3 + 0] = (Math.random() * 2 - 1) * spec.spread;
      positions[i * 3 + 1] = (Math.random() * 2 - 1) * spec.halfHeight;
      positions[i * 3 + 2] = (Math.random() * 2 - 1) * spec.spread;
      seeds[i] = Math.random();
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    g.setAttribute("aSeed", new THREE.BufferAttribute(seeds, 1));
    return g;
  }, [spec, density]);

  // Dispose the geometry when it is replaced (density change) or on unmount.
  useMemo(() => () => geometry.dispose(), [geometry]);

  const uniforms = useMemo(
    () => ({
      uTime: { value: 0 },
      uFallSpeed: { value: spec.fallSpeed },
      uSwayAmp: { value: spec.swayAmp },
      uHalfHeight: { value: spec.halfHeight },
      uSize: { value: spec.size },
      uOpacity: { value: spec.opacity },
      uColor: { value: SNOW_COLOR },
      uMotion: { value: animate ? 1 : 0 },
      uPixelRatio: { value: dpr },
    }),
    [spec, animate, dpr],
  );

  useFrame((_, delta) => {
    if (material.current) material.current.uniforms.uTime.value += delta;
  });

  return (
    <points geometry={geometry}>
      <shaderMaterial
        ref={material}
        vertexShader={snowVertexShader}
        fragmentShader={snowFragmentShader}
        uniforms={uniforms}
        transparent
        depthWrite={false}
        blending={THREE.AdditiveBlending}
      />
    </points>
  );
}
