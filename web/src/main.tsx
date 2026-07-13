import React from "react";
import ReactDOM from "react-dom/client";
// Self-hosted fonts (bundled into the build — no external CDN, CSP-safe / offline-ready).
import "@fontsource/poppins/400.css";
import "@fontsource/poppins/500.css";
import "@fontsource/poppins/600.css";
import "@fontsource/poppins/700.css";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "@fontsource/jetbrains-mono/700.css";
import { App } from "./App";
import { initTheme } from "./lib/theme";
import "./theme.css";

initTheme();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
