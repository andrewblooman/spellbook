// Theme controller — light/dark, persisted, applied via <html data-theme>.
// The CSS forks token values on :root[data-theme="…"] (see theme.css), so setting
// this attribute is all it takes to switch the whole palette.
import { useCallback, useEffect, useState } from "react";

export type Theme = "light" | "dark";

const KEY = "sb-theme";

function systemTheme(): Theme {
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export function getTheme(): Theme {
  const saved = localStorage.getItem(KEY);
  return saved === "light" || saved === "dark" ? saved : systemTheme();
}

export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
}

export function setTheme(theme: Theme): void {
  localStorage.setItem(KEY, theme);
  applyTheme(theme);
}

/** Apply the persisted/system theme once, before React renders (called from main.tsx). */
export function initTheme(): void {
  applyTheme(getTheme());
}

/** Hook: current theme + a toggle, kept in sync across components via a storage event. */
export function useTheme(): { theme: Theme; toggle: () => void; set: (t: Theme) => void } {
  const [theme, setLocal] = useState<Theme>(getTheme);

  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === KEY) setLocal(getTheme());
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const set = useCallback((t: Theme) => {
    setTheme(t);
    setLocal(t);
  }, []);

  const toggle = useCallback(() => set(theme === "dark" ? "light" : "dark"), [theme, set]);

  return { theme, toggle, set };
}
