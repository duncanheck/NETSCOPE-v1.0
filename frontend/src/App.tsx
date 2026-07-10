import { useEffect } from "react";
import { Scene } from "./scene/Scene";
import { Hud } from "./components/Hud";
import { PerfHud } from "./components/PerfHud";
import { SettingsPanel } from "./components/SettingsPanel";
import { SystemPanel } from "./components/SystemPanel";
import { FocusBreadcrumb } from "./components/FocusBreadcrumb";
import { ClusterLabelOverlay } from "./components/ClusterLabelOverlay";
import { HoverTooltip } from "./components/HoverTooltip";
import { HelpOverlay } from "./components/HelpOverlay";
import { Legend } from "./components/Legend";
import { ImmersiveControl } from "./components/ImmersiveControl";
import { useNetscopeStore } from "./store/useNetscopeStore";
import { useViewStore } from "./store/useViewStore";
import { defaultTransportKind } from "./transport";

export default function App() {
  const attach = useNetscopeStore((s) => s.attach);
  const detach = useNetscopeStore((s) => s.detach);
  // Cinematic mode hides all chrome; the Scene (and its GPU context, camera,
  // selection state) stays mounted throughout, so entering/leaving is instant
  // and never resets the view.
  const immersive = useViewStore((s) => s.immersive);

  useEffect(() => {
    attach(defaultTransportKind());
    return () => detach();
  }, [attach, detach]);

  return (
    <div className={`app${immersive ? " app--immersive" : ""}`}>
      <Scene />
      {!immersive && (
        <>
          <ClusterLabelOverlay />
          <Legend />
          <FocusBreadcrumb />
          <HoverTooltip />
          <Hud />
          <SettingsPanel />
          <SystemPanel />
          <PerfHud />
          <HelpOverlay />
        </>
      )}
      <ImmersiveControl />
    </div>
  );
}
