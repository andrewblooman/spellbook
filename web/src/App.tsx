import { HashRouter, Route, Routes } from "react-router-dom";
import { Sidebar } from "./components/Sidebar";
import { ComingSoon } from "./components/ComingSoon";
import { Dashboard } from "./views/Dashboard";
import { Findings } from "./views/Findings";
import { FindingDetail } from "./views/FindingDetail";
import { ManualBuilder } from "./views/ManualBuilder";

export function App() {
  return (
    <HashRouter>
      <div className="shell">
        <Sidebar />
        <main className="stage">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/findings/:id" element={<FindingDetail />} />
            <Route path="/new" element={<ManualBuilder />} />
            {/* Scaffolded for later phases — nav is complete now. */}
            <Route path="/agents" element={<ComingSoon title="Agent workers" note="The control-plane worker view lands next — live run status, posture, and per-worker health." />} />
            <Route path="/runs/:id" element={<ComingSoon title="Run result" note="The detailed results page is coming: verdict, evidence chain, per-step diagnosis, and the audit trail." />} />
            <Route path="/settings" element={<ComingSoon title="Settings" note="Secrets and user management will live here." />} />
            <Route path="/profile" element={<ComingSoon title="Profile" note="Profile preferences will live here — the light/dark toggle is in the sidebar for now." />} />
          </Routes>
        </main>
      </div>
    </HashRouter>
  );
}
