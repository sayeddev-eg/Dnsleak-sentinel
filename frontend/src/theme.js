// Light / Dark theme manager (persisted, synced across components)
const KEY = "soc_theme";
const EVT = "soc-theme-change";

export function getTheme() {
  try {
    const saved = localStorage.getItem(KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch { /* ignore */ }
  return "dark";
}

export function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
}

export function setTheme(theme) {
  try { localStorage.setItem(KEY, theme); } catch { /* ignore */ }
  applyTheme(theme);
  window.dispatchEvent(new CustomEvent(EVT, { detail: theme }));
}

import { useEffect, useState } from "react";

export function useTheme() {
  const [theme, set] = useState(getTheme);
  useEffect(() => {
    const on = (e) => set(e.detail);
    window.addEventListener(EVT, on);
    return () => window.removeEventListener(EVT, on);
  }, []);
  const toggle = () => setTheme(theme === "dark" ? "light" : "dark");
  return [theme, toggle];
}
