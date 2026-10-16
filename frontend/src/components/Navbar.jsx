import { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";
import { LogOut, Clock3, ChevronRight } from "lucide-react";
import { api } from "../api/client";
import ThemeToggle from "./ThemeToggle";

const TITLES = {
  "/dashboard": "Threat Overview",
  "/live": "Live Monitoring",
  "/devices": "Devices",
  "/alerts": "Alerts",
  "/incidents": "Incidents",
  "/analytics": "Analytics",
  "/ai-performance": "AI Performance",
  "/reports": "Reports",
  "/users": "User Management",
  "/audit": "Audit Log",
};

const ROLE_STYLE = {
  admin: { color: "var(--violet)", bg: "color-mix(in srgb, var(--violet) 10%, transparent)", border: "color-mix(in srgb, var(--violet) 25%, transparent)" },
  analyst: { color: "var(--blue)", bg: "color-mix(in srgb, var(--blue) 10%, transparent)", border: "color-mix(in srgb, var(--blue) 25%, transparent)" },
  viewer: { color: "var(--muted)", bg: "color-mix(in srgb, var(--muted) 10%, transparent)", border: "color-mix(in srgb, var(--muted) 25%, transparent)" },
};

export default function Navbar({ user, onLogout }) {
  const location = useLocation();
  const [online, setOnline] = useState(null);
  const [now, setNow] = useState(new Date());

  useEffect(() => {
    let active = true;
    const check = async () => {
      const ok = await api.checkHealth();
      if (active) setOnline(ok);
    };
    check();
    const h = setInterval(check, 5000);
    const c = setInterval(() => setNow(new Date()), 1000);
    return () => {
      active = false;
      clearInterval(h);
      clearInterval(c);
    };
  }, []);

  const segment = location.pathname.replace("/", "") || "dashboard";
  const title = TITLES[location.pathname] || "Security Operations";
  const role = ROLE_STYLE[user.role] || ROLE_STYLE.viewer;
  const initials = (user.name || user.username || "U")
    .split(" ")
    .map((s) => s[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  const statusColor = online === null ? "var(--muted)" : online ? "var(--teal)" : "var(--amber)";
  const statusText = online === null ? "Connecting" : online ? "Engine Online" : "Engine Offline";

  return (
    <header
      style={{
        position: "sticky",
        top: 0,
        zIndex: 3,
        height: 64,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 28px",
        background: "var(--header-bg)",
        borderBottom: "1px solid var(--border)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
        <div>
          <div className="mono" style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 10.5, color: "var(--faint)", letterSpacing: "0.06em" }}>
            soc <ChevronRight size={11} /> <span style={{ color: "var(--muted)" }}>{segment}</span>
          </div>
          <div style={{ fontSize: 16, fontWeight: 600, color: "var(--text)", letterSpacing: "-0.01em" }}>{title}</div>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
        {/* Status */}
        <div
          title={online ? "Connected to FastAPI backend" : "Backend not reachable"}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "6px 12px",
            borderRadius: 999,
            fontSize: 12,
            fontWeight: 500,
            color: statusColor,
            background: "color-mix(in srgb, var(--ink) 4%, transparent)",
            border: `1px solid ${online ? "color-mix(in srgb, var(--teal) 22%, transparent)" : "var(--border)"}`,
          }}
        >
          <span className={online ? "pulse-dot" : ""} style={{ width: 7, height: 7, borderRadius: 99, background: statusColor, color: statusColor }} />
          {statusText}
        </div>

        {/* Clock */}
        <div className="mono" style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--muted)" }}>
          <Clock3 size={14} />
          {now.toLocaleTimeString("en-GB")}
        </div>

        <div style={{ width: 1, height: 26, background: "var(--border)" }} />

        {/* User */}
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div
            style={{
              width: 34,
              height: 34,
              borderRadius: 10,
              display: "grid",
              placeItems: "center",
              fontSize: 12.5,
              fontWeight: 700,
              color: role.color,
              background: role.bg,
              border: `1px solid ${role.border}`,
            }}
          >
            {initials}
          </div>
          <div style={{ lineHeight: 1.2 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text)" }}>{user.name}</div>
            <div className="mono" style={{ fontSize: 10.5, color: role.color, textTransform: "uppercase", letterSpacing: "0.1em" }}>
              {user.role}
            </div>
          </div>
        </div>

        <ThemeToggle />

        <button className="icon-btn danger" onClick={onLogout} title="Sign out">
          <LogOut size={16} />
        </button>
      </div>
    </header>
  );
}
