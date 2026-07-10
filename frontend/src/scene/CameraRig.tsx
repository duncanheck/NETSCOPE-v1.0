// A compact orbit camera (B3 interactivity). Drag to rotate, wheel to dolly, with
// smoothing — enough to inspect the organism from any angle without pulling in a
// controls dependency. The salvaged prototype had a richer custom orbit (pinch,
// drag-vs-tap); this is the trimmed core, re-added now that there's something
// worth orbiting.
//
// It mutates `camera` each frame; DeepOcean's render loop draws `state.camera`, so
// the two cooperate without either knowing about the other.
//
// Focus / drill-down: when a node is focused (render store), the orbit target eases
// from the host core to that node and the radius pulls in, so the camera "flies to"
// the focused endpoint; clearing focus eases back to the host.

import { useEffect, useRef } from "react";
import { useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";

import { useRenderStore } from "./useRenderStore";
import { useNetscopeStore } from "../store/useNetscopeStore";
import { useViewStore } from "../store/useViewStore";
import { forceLayout } from "./force/forceLayout";
import { HOST_CENTER } from "./layout";

const MIN_POLAR = 0.2;
const MAX_POLAR = Math.PI - 0.2;
const MIN_RADIUS = 4;
// Wide enough to frame a busy network once the layout spreads it out (forceLayout
// scales the cloud up to ~1.9× at 150–200 nodes).
const MAX_RADIUS = 60;
const ROTATE_SPEED = 0.005;
const SMOOTH = 0.12;
const FOCUS_RADIUS = 6; // how close the camera pulls in on a focused node
const TARGET_SMOOTH = 0.08; // easing for the orbit-centre glide
const BASE_RADIUS = 12; // framing distance at the unscaled (small-world) layout

/** A framing distance that grows with the layout spread so a busy, spread-out
 *  network is fully in view. Tracks forceLayout's count-based scale. */
function framedRadius(): number {
  return THREE.MathUtils.clamp(BASE_RADIUS * forceLayout.spreadFactor, BASE_RADIUS, 44);
}

export function CameraRig() {
  const camera = useThree((s) => s.camera);
  const domElement = useThree((s) => s.gl.domElement);
  const focusId = useRenderStore((s) => s.focusId);
  const layout = useViewStore((s) => s.layout);

  const s = useRef({
    az: Math.PI / 2,
    pol: 1.05,
    rad: 12,
    tAz: Math.PI / 2,
    tPol: 1.05,
    tRad: 12,
    dragging: false,
    lastX: 0,
    lastY: 0,
    // The eased orbit centre (glides toward the focused node, back to host on clear).
    target: HOST_CENTER.clone(),
    // True once the user dollies while focused, so we stop forcing the close radius.
    userDollied: false,
  });

  useEffect(() => {
    const st = s.current;
    const onDown = (e: PointerEvent) => {
      st.dragging = true;
      st.lastX = e.clientX;
      st.lastY = e.clientY;
    };
    const onMove = (e: PointerEvent) => {
      if (!st.dragging) return;
      const dx = e.clientX - st.lastX;
      const dy = e.clientY - st.lastY;
      st.lastX = e.clientX;
      st.lastY = e.clientY;
      st.tAz -= dx * ROTATE_SPEED;
      st.tPol = THREE.MathUtils.clamp(st.tPol - dy * ROTATE_SPEED, MIN_POLAR, MAX_POLAR);
    };
    const onUp = () => {
      st.dragging = false;
    };
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const factor = Math.exp(e.deltaY * 0.001);
      st.tRad = THREE.MathUtils.clamp(st.tRad * factor, MIN_RADIUS, MAX_RADIUS);
      st.userDollied = true; // respect manual zoom over the focus pull-in
    };

    domElement.addEventListener("pointerdown", onDown);
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    domElement.addEventListener("wheel", onWheel, { passive: false });
    return () => {
      domElement.removeEventListener("pointerdown", onDown);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      domElement.removeEventListener("wheel", onWheel);
    };
  }, [domElement]);

  // Reset the "user dollied" latch and pull the radius in whenever focus changes.
  useEffect(() => {
    const st = s.current;
    st.userDollied = false;
    st.tRad = focusId ? FOCUS_RADIUS : framedRadius();
  }, [focusId]);

  const desired = useRef(new THREE.Vector3());

  useFrame(() => {
    const st = s.current;

    // Glide the orbit centre toward the focused node (or back to the host core).
    desired.current.copy(HOST_CENTER);
    if (focusId) {
      const flow = useNetscopeStore.getState().flows.get(focusId);
      if (flow) forceLayout.getPosition(flow, layout, desired.current);
    }
    st.target.lerp(desired.current, TARGET_SMOOTH);

    // Auto-frame the whole cloud while not focused and until the user takes manual
    // control (a wheel/dolly): as the layout spreads with node count, ease the
    // radius out so a busy network isn't half off-screen on load.
    if (!focusId && !st.userDollied) st.tRad = framedRadius();

    st.az += (st.tAz - st.az) * SMOOTH;
    st.pol += (st.tPol - st.pol) * SMOOTH;
    st.rad += (st.tRad - st.rad) * SMOOTH;

    const sinPol = Math.sin(st.pol);
    camera.position.set(
      st.target.x + st.rad * sinPol * Math.cos(st.az),
      st.target.y + st.rad * Math.cos(st.pol),
      st.target.z + st.rad * sinPol * Math.sin(st.az),
    );
    camera.lookAt(st.target);
  });

  return null;
}
