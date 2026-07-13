import { NavLink } from "react-router-dom";
import { useTheme } from "../lib/theme";

interface Item {
  to: string;
  label: string;
  glyph: string;
  end?: boolean;
}

const SECTIONS: { title: string; items: Item[] }[] = [
  { title: "Overview", items: [{ to: "/", label: "Dashboard", glyph: "🔮", end: true }] },
  {
    title: "Validate",
    items: [
      { to: "/findings", label: "Findings", glyph: "📜" },
      { to: "/new", label: "New vector", glyph: "✴️" },
    ],
  },
  { title: "Control plane", items: [{ to: "/agents", label: "Agents", glyph: "🧿" }] },
  {
    title: "System",
    items: [
      { to: "/settings", label: "Settings", glyph: "⚙️" },
      { to: "/profile", label: "Profile", glyph: "🧙" },
    ],
  },
];

export function Sidebar() {
  const { theme, toggle } = useTheme();
  return (
    <nav className="rail">
      <div className="brand">
        <span className="glyph">🪄</span>
        <div>
          <h1>Spellbook</h1>
          <small>exploit-path validation</small>
        </div>
      </div>

      {SECTIONS.map((section) => (
        <div className="nav-section" key={section.title}>
          <span className="nav-section-title">{section.title}</span>
          {section.items.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end} className="navlink">
              <span className="nav-glyph">{item.glyph}</span> {item.label}
            </NavLink>
          ))}
        </div>
      ))}

      <div className="nav-foot">
        <button
          type="button"
          className="theme-toggle"
          onClick={toggle}
          aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
          title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
        >
          <span>{theme === "dark" ? "☀️" : "🌙"}</span>
          {theme === "dark" ? "Light" : "Dark"} mode
        </button>
        <div className="user-chip">
          <span className="user-avatar">🧙</span>
          <div>
            <strong>Archmage</strong>
            <small>local session</small>
          </div>
        </div>
      </div>
    </nav>
  );
}
