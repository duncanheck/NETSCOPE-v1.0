// The scene. DeepOcean (B2) owns the render loop — it paints the half-res ocean
// background, then draws everything in this scene on top: the marine-snow layers
// and the organism nodes (B3). Tendrils between nodes are B4.
//
// No solid <color> background here: the ocean composite IS the background, and a
// scene.background would overwrite it. Fog is tuned to the ocean's deep tone so
// distant nodes recede into the water column rather than popping against it.

import { Canvas } from "@react-three/fiber";
import { DeepOcean } from "./DeepOcean";
import { MarineSnow } from "./MarineSnow";
import { OrganismNodes } from "./OrganismNodes";
import { TendrilField } from "./TendrilField";
import { HostCore } from "./HostCore";
import { RelationshipEdges } from "./RelationshipEdges";
import { ClusterLabels } from "./ClusterLabels";
import { CameraRig } from "./CameraRig";
import { PerfProbe } from "./PerfProbe";

export function Scene() {
  return (
    <Canvas camera={{ position: [0, 5, 12], fov: 50 }} style={{ position: "absolute", inset: 0 }}>
      <fog attach="fog" args={["#04141a", 10, 30]} />
      <ambientLight intensity={0.25} />
      <pointLight position={[0, 6, 0]} intensity={30} color="#bfe9ff" />

      <CameraRig />
      <PerfProbe />
      <DeepOcean />
      <MarineSnow />
      <HostCore />
      <TendrilField />
      <RelationshipEdges />
      <OrganismNodes />
      <ClusterLabels />
    </Canvas>
  );
}
