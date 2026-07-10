// The host core — the centre every tendril reaches from (B4). It stands for the
// machine you're watching: the one origin all these outbound conversations share.
// A plain bright ball said "here"; this says "*you* — the hub." A luminous reactor
// with a pulsing energy heart, a technological latitude/longitude shell, and slow
// orbiting sensor rings — kept gently floating (bob + drift-rotation) so it belongs
// to the same weightless deep-sea world as the nodes.
//
// It's a single fixed object (not per-node), so its handful of extra draws sits
// well inside the frame budget (docs/performance.md). The tendrils' origin is the
// HOST_CENTER uniform, independent of this mesh, so the visual and the geometry
// stay cleanly decoupled.

import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

import { HOST_CENTER } from "./layout";
import { snoise3 } from "./shaders/noise";

const coreVertex = /* glsl */ `
  varying vec3 vViewNormal;
  varying vec3 vViewPos;
  varying vec3 vSphere;

  uniform float uTime;

  ${snoise3}

  void main() {
    // A slow, low-amplitude breathing so the heart feels alive, not inflated.
    float wob = snoise(normal * 1.4 + vec3(0.0, 0.0, uTime * 0.5));
    vec3 displaced = position * (1.0 + wob * 0.03);
    vec4 mv = modelViewMatrix * vec4(displaced, 1.0);
    vViewPos = mv.xyz;
    vViewNormal = normalize(normalMatrix * normal);
    vSphere = normalize(position);
    gl_Position = projectionMatrix * mv;
  }
`;

const coreFragment = /* glsl */ `
  precision highp float;

  uniform float uTime;

  varying vec3 vViewNormal;
  varying vec3 vViewPos;
  varying vec3 vSphere;

  #define TAU 6.2831853

  void main() {
    vec3 N = normalize(vViewNormal);
    vec3 V = normalize(-vViewPos);
    float facing = clamp(dot(N, V), 0.0, 1.0);
    float fres = pow(1.0 - facing, 3.0);

    // A cool white-cyan reactor heart, brightest dead-centre, breathing.
    float beat = 0.7 + 0.3 * sin(uTime * 1.6);
    vec3 base = vec3(0.55, 0.85, 1.0);
    vec3 col = base * (0.25 + 0.9 * facing) * beat;

    // Denser instrument shell than the nodes: fine lat/long grid, energised.
    vec3 s = normalize(vSphere);
    float lon = atan(s.z, s.x);
    float lat = asin(clamp(s.y, -1.0, 1.0));
    float gx = abs(fract(lon / TAU * 18.0) - 0.5);
    float gy = abs(fract(lat / 3.14159 * 12.0 + 0.5) - 0.5);
    float grid = smoothstep(0.05, 0.0, min(gx, gy));
    // Twin scan bands crossing the shell.
    float scanA = smoothstep(0.08, 0.0, abs(fract(lat / 3.14159 + 0.5 - uTime * 0.18) - 0.5));
    float scanB = smoothstep(0.06, 0.0, abs(fract(lon / TAU - uTime * 0.10) - 0.5));
    float shell = facing * facing;
    col += vec3(0.8, 0.95, 1.0) * grid * shell * 1.4;
    col += vec3(0.9, 1.0, 1.0) * (scanA + scanB) * shell * 0.8;

    // Bright fresnel corona so it reads as an energy source, not a solid ball.
    col += base * fres * 2.2;

    gl_FragColor = vec4(col, 1.0);
  }
`;

// Additive halo behind the core — a soft camera-facing bloom seed.
const haloVertex = /* glsl */ `
  varying vec2 vUv;
  void main() {
    vUv = uv;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;
const haloFragment = /* glsl */ `
  precision mediump float;
  uniform float uTime;
  varying vec2 vUv;
  void main() {
    float d = length(vUv - 0.5) * 2.0;
    if (d > 1.0) discard;
    float a = smoothstep(1.0, 0.0, d);
    a *= a;
    float beat = 0.75 + 0.25 * sin(uTime * 1.6);
    gl_FragColor = vec4(vec3(0.5, 0.82, 1.0) * a * beat, a);
  }
`;

export function HostCore() {
  const group = useRef<THREE.Group>(null);
  const rings = useRef<THREE.Group>(null);
  const coreMat = useRef<THREE.ShaderMaterial>(null);
  const haloMat = useRef<THREE.ShaderMaterial>(null);

  const uniforms = useMemo(() => ({ core: { uTime: { value: 0 } }, halo: { uTime: { value: 0 } } }), []);

  useFrame((_, delta) => {
    uniforms.core.uTime.value += delta;
    uniforms.halo.uTime.value += delta;
    const t = uniforms.core.uTime.value;
    if (group.current) {
      // Gentle float: a slow vertical bob around the host anchor, plus a lazy yaw.
      group.current.position.set(HOST_CENTER.x, HOST_CENTER.y + Math.sin(t * 0.8) * 0.08, HOST_CENTER.z);
      group.current.rotation.y = t * 0.15;
    }
    if (rings.current) {
      // Sensor rings sweep on their own axes, a touch faster than the core.
      rings.current.rotation.z = t * 0.4;
      rings.current.rotation.x = Math.sin(t * 0.3) * 0.5;
    }
  });

  return (
    <group ref={group}>
      {/* Soft additive corona (billboarded quad). */}
      <mesh raycast={() => null}>
        <planeGeometry args={[3.4, 3.4]} />
        <shaderMaterial
          ref={haloMat}
          vertexShader={haloVertex}
          fragmentShader={haloFragment}
          uniforms={uniforms.halo}
          transparent
          depthWrite={false}
          blending={THREE.AdditiveBlending}
        />
      </mesh>

      {/* The reactor heart. */}
      <mesh raycast={() => null}>
        <icosahedronGeometry args={[0.52, 4]} />
        <shaderMaterial
          ref={coreMat}
          vertexShader={coreVertex}
          fragmentShader={coreFragment}
          uniforms={uniforms.core}
        />
      </mesh>

      {/* Two orbiting sensor rings — the "hub" read. */}
      <group ref={rings}>
        <mesh raycast={() => null}>
          <torusGeometry args={[0.95, 0.018, 8, 96]} />
          <meshBasicMaterial color="#8fe6ff" toneMapped={false} transparent opacity={0.85} />
        </mesh>
        <mesh raycast={() => null} rotation={[Math.PI / 2.3, 0.4, 0]}>
          <torusGeometry args={[1.25, 0.012, 8, 96]} />
          <meshBasicMaterial color="#bfefff" toneMapped={false} transparent opacity={0.6} />
        </mesh>
      </group>
    </group>
  );
}
