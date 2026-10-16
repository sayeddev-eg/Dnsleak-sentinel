// Shared design tokens — every value is a CSS variable so Light/Dark themes switch instantly.
export const PALETTE = {
  teal: "var(--teal)",
  blue: "var(--blue)",
  violet: "var(--violet)",
  cyan: "var(--cyan)",
  amber: "var(--amber)",
  rose: "var(--rose)",
  gold: "var(--gold)",
  text: "var(--text)",
  soft: "var(--text-soft)",
  muted: "var(--muted)",
  faint: "var(--faint)",
  border: "var(--border)",
  grid: "var(--grid)",
};

/** Transparent tint of any color (works with CSS variables). */
export const tint = (color, pct) => `color-mix(in srgb, ${color} ${pct}%, transparent)`;

export const COLORS = { critical: "var(--rose)", high: "var(--amber)", medium: "var(--gold)", low: "var(--teal)" };

export const card = {
  background: "var(--surface)",
  border: "1px solid var(--border)",
  borderRadius: 16,
  padding: 20,
  "--card": 1, // marker used by CSS hover effect (no backdrop-filter: it is very GPU-expensive over the animated background)
  boxShadow: "var(--card-shadow)",
};

export const input = {
  background: "var(--input-bg)",
  border: "1px solid var(--border-strong)",
  color: "var(--text)",
  borderRadius: 10,
  padding: "9px 12px",
};

export const tooltipStyle = {
  background: "var(--tooltip-bg)",
  border: "1px solid var(--border-strong)",
  borderRadius: 10,
  color: "var(--text)",
};

export const th = { padding: "12px 10px", color: "var(--muted)", fontSize: 12, textAlign: "left", borderBottom: "1px solid var(--border)" };
export const td = { padding: "11px 10px", borderBottom: "1px solid var(--border-soft)" };
