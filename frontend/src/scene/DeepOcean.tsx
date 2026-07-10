// The deep-ocean environment (ROADMAP B2). Renders the domain-warped fBm ocean to
// a HALF-RESOLUTION render target, composites it full-screen as the background,
// then draws the main scene (organism nodes + marine snow) on top.
//
// Why a render-target + manual render loop instead of a plain background mesh:
// fBm+warp is the frame's heaviest fragment work, so we pay for it at half the
// pixels and upscale (the documented quality/cost trade — soft, which murk wants).
// Driving the passes ourselves is the standard R3F way to do this without pulling
// in the postprocessing library: any `useFrame` with a non-zero priority disables
// R3F's auto-render, handing us the loop. We own the whole sequence:
//
//   1. ocean shader        → half-res target
//   2. composite (upscale) → screen   (background, no depth)
//   3. main scene          → screen   (on top, fresh depth)
//
// The octave count, RT scale, and motion come from the startup GPU probe
// (capability.ts) — measured, never user-agent-sniffed (PITFALLS B2).
//
// B6 — true bloom — folds in here rather than adding a second render owner. On
// the HIGH tier the final sequence becomes:
//
//   1. ocean shader            → half-res target
//   2. ocean composite + scene → full-res HDR target   (one combined frame)
//   3. UnrealBloomPass         → screen                 (glow on the bright bits)
//
// On a weaker GPU (LOW tier) `tier.bloom` is false and the original direct path
// (composite + scene straight to screen) runs unchanged — the capability gate.

import { useEffect, useMemo } from "react";
import { useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";
import { EffectComposer } from "three/examples/jsm/postprocessing/EffectComposer.js";
import { TexturePass } from "three/examples/jsm/postprocessing/TexturePass.js";
import { UnrealBloomPass } from "three/examples/jsm/postprocessing/UnrealBloomPass.js";
import { ShaderPass } from "three/examples/jsm/postprocessing/ShaderPass.js";
import { CopyShader } from "three/examples/jsm/shaders/CopyShader.js";

import {
  oceanVertexShader,
  oceanFragmentShader,
  compositeVertexShader,
  compositeFragmentShader,
} from "./shaders/ocean";
import { probeRenderTier, applyTierPrefs } from "./capability";
import { useRenderStore } from "./useRenderStore";
import { useViewStore } from "../store/useViewStore";

// Subtle, accent-not-wash bloom: a threshold above the ocean's murk so only the
// emissive organism (node cores, fresnel rims, traffic motes — which exceed 1.0)
// blooms, a moderate spread, and gentle strength.
const BLOOM_STRENGTH = 0.7;
const BLOOM_RADIUS = 0.45;
const BLOOM_THRESHOLD = 0.75;

export function DeepOcean() {
  const gl = useThree((s) => s.gl);
  const size = useThree((s) => s.size);
  const setTier = useRenderStore((s) => s.setTier);
  const tierPref = useViewStore((s) => s.tier);
  const bloomPref = useViewStore((s) => s.bloom);

  // Probe the GPU once (the measured base), then fold in the user's Settings-panel
  // overrides. Changing either pref re-derives `tier`, which re-keys the render rig
  // below (rebuilding/dropping the bloom composer) — so the change applies live.
  const base = useMemo(() => probeRenderTier(gl), [gl]);
  const tier = useMemo(
    () => applyTierPrefs(base, tierPref, bloomPref),
    [base, tierPref, bloomPref],
  );
  useEffect(() => setTier(tier), [tier, setTier]);

  // Static GPU resources, rebuilt only if the tier changes: the half-res target,
  // the ocean pass (its own scene/quad), and the composite pass.
  const rig = useMemo(() => {
    const fullscreenQuad = (material: THREE.Material) => {
      const scene = new THREE.Scene();
      scene.add(new THREE.Mesh(new THREE.PlaneGeometry(2, 2), material));
      return scene;
    };

    const target = new THREE.WebGLRenderTarget(1, 1, {
      // Bilinear so the upscale is smooth; no depth buffer — it's a flat pass.
      minFilter: THREE.LinearFilter,
      magFilter: THREE.LinearFilter,
      depthBuffer: false,
    });

    const oceanMaterial = new THREE.ShaderMaterial({
      vertexShader: oceanVertexShader,
      fragmentShader: oceanFragmentShader,
      defines: { OCTAVES: tier.octaves },
      uniforms: {
        uTime: { value: 0 },
        uResolution: { value: new THREE.Vector2(1, 1) },
        uMotion: { value: tier.animate ? 1 : 0 },
      },
      depthTest: false,
      depthWrite: false,
    });

    const compositeMaterial = new THREE.ShaderMaterial({
      vertexShader: compositeVertexShader,
      fragmentShader: compositeFragmentShader,
      uniforms: { uScene: { value: target.texture } },
      depthTest: false,
      depthWrite: false,
    });

    const quadCamera = new THREE.Camera(); // geometry is clip-space; no matrices used

    // B6 bloom rig (HIGH tier only): a full-res HDR target the combined frame
    // (ocean + scene) is drawn into, plus an EffectComposer that blooms it to
    // screen. HalfFloat so node highlights above 1.0 survive for the threshold.
    let sceneTarget: THREE.WebGLRenderTarget | null = null;
    let composer: EffectComposer | null = null;
    let bloomPass: UnrealBloomPass | null = null;
    if (tier.bloom) {
      sceneTarget = new THREE.WebGLRenderTarget(1, 1, {
        type: THREE.HalfFloatType,
        minFilter: THREE.LinearFilter,
        magFilter: THREE.LinearFilter,
        depthBuffer: true,
      });
      bloomPass = new UnrealBloomPass(
        new THREE.Vector2(1, 1),
        BLOOM_STRENGTH,
        BLOOM_RADIUS,
        BLOOM_THRESHOLD,
      );
      // CopyShader (not OutputPass) for the final blit so the base image keeps the
      // exact look of the direct path — bloom is purely additive on top.
      const copyPass = new ShaderPass(CopyShader);
      copyPass.renderToScreen = true;
      composer = new EffectComposer(gl);
      composer.renderToScreen = true;
      composer.addPass(new TexturePass(sceneTarget.texture));
      composer.addPass(bloomPass);
      composer.addPass(copyPass);
    }

    return {
      target,
      sceneTarget,
      composer,
      bloomPass,
      oceanMaterial,
      compositeMaterial,
      oceanScene: fullscreenQuad(oceanMaterial),
      compositeScene: fullscreenQuad(compositeMaterial),
      camera: quadCamera,
    };
  }, [tier, gl]);

  // Size the half-res ocean target (drawing buffer × tier scale), the full-res
  // bloom target, and the composer — and tell the ocean shader its true pixel
  // resolution (for aspect + sane noise scale).
  useEffect(() => {
    const dpr = gl.getPixelRatio();
    const w = Math.max(2, Math.floor(size.width * dpr * tier.rtScale));
    const h = Math.max(2, Math.floor(size.height * dpr * tier.rtScale));
    rig.target.setSize(w, h);
    rig.oceanMaterial.uniforms.uResolution.value.set(w, h);

    if (rig.composer && rig.sceneTarget) {
      const fw = Math.max(2, Math.floor(size.width * dpr));
      const fh = Math.max(2, Math.floor(size.height * dpr));
      rig.sceneTarget.setSize(fw, fh);
      rig.composer.setPixelRatio(dpr);
      rig.composer.setSize(size.width, size.height); // updates bloom mips too
    }
  }, [gl, size.width, size.height, tier.rtScale, rig]);

  // Dispose GPU resources on unmount / tier change, and restore auto-clear.
  useEffect(() => {
    return () => {
      rig.target.dispose();
      rig.oceanMaterial.dispose();
      rig.compositeMaterial.dispose();
      rig.oceanScene.traverse((o) => disposeMesh(o));
      rig.compositeScene.traverse((o) => disposeMesh(o));
      rig.sceneTarget?.dispose();
      rig.bloomPass?.dispose();
      rig.composer?.dispose();
      gl.autoClear = true;
    };
  }, [rig, gl]);

  // Own the render loop (priority 1 disables R3F's auto-render).
  useFrame((state, delta) => {
    rig.oceanMaterial.uniforms.uTime.value += delta;

    // 1. Ocean → half-res target (both paths).
    gl.setRenderTarget(rig.target);
    gl.clear(true, true, false);
    gl.render(rig.oceanScene, rig.camera);

    if (rig.composer && rig.sceneTarget) {
      // B6 path. 2. Combined frame (ocean composite + scene) → full-res HDR
      //    target: clear, lay the upscaled ocean (no depth), then the scene on
      //    fresh depth — exactly the direct path, but offscreen.
      gl.setRenderTarget(rig.sceneTarget);
      gl.autoClear = false;
      gl.clear(true, true, false);
      gl.render(rig.compositeScene, rig.camera);
      gl.render(state.scene, state.camera);

      // 3. Bloom the HDR frame to screen (additive glow over the base image).
      gl.setRenderTarget(null);
      rig.composer.render();
    } else {
      // Direct path (LOW tier). 2. Composite → screen, then 3. scene on top.
      gl.setRenderTarget(null);
      gl.autoClear = false;
      gl.clear(true, true, false);
      gl.render(rig.compositeScene, rig.camera);
      gl.render(state.scene, state.camera);
    }
  }, 1);

  return null;
}

function disposeMesh(o: THREE.Object3D) {
  if (o instanceof THREE.Mesh) o.geometry.dispose();
}
