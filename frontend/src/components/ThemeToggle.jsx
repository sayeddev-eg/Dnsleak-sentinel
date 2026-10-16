import { Sun, Moon } from "lucide-react";
import { useTheme } from "../theme";

export default function ThemeToggle() {
  const [theme, toggle] = useTheme();
  const light = theme === "light";

  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={toggle}
      title={light ? "Switch to dark mode" : "Switch to light mode"}
      aria-label="Toggle color theme"
    >
      <Moon size={13} className="ico" style={{ left: 9, opacity: light ? 1 : 0 }} />
      <Sun size={13} className="ico" style={{ right: 9, opacity: light ? 0 : 1 }} />
      <span className="knob">
        {light ? <Sun size={13} color="var(--amber)" /> : <Moon size={13} color="var(--violet)" />}
      </span>
    </button>
  );
}
