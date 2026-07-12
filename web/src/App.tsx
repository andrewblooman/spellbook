import { HashRouter, NavLink, Route, Routes } from "react-router-dom";
import { Findings } from "./views/Findings";
import { FindingDetail } from "./views/FindingDetail";
import { ManualBuilder } from "./views/ManualBuilder";

export function App() {
  return (
    <HashRouter>
      <div className="shell">
        <nav className="rail">
          <div className="brand">
            <span className="glyph">🪄</span>
            <div>
              <h1>Spellbook</h1>
              <small>exploit-path validation</small>
            </div>
          </div>
          <NavLink to="/" end className="navlink">
            <span className="dot" /> Findings
          </NavLink>
          <NavLink to="/new" className="navlink">
            <span className="dot" /> New manual test
          </NavLink>
        </nav>
        <main className="stage">
          <Routes>
            <Route path="/" element={<Findings />} />
            <Route path="/findings/:id" element={<FindingDetail />} />
            <Route path="/new" element={<ManualBuilder />} />
          </Routes>
        </main>
      </div>
    </HashRouter>
  );
}
