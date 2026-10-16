import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { api } from "../api/client";
import {
  LayoutDashboard,
  Radar,
  MonitorSmartphone,
  BellRing,
  Siren,
  BarChart3,
  BrainCircuit,
  FileText,
  Users,
  ShieldHalf,
  Cpu,
  History,
} from "lucide-react";

const sections = [
  {
    title: "Overview",
    links: [
      { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard, roles: ["admin", "analyst", "viewer"] },
      { to: "/live", label: "Live Monitoring", icon: Radar, roles: ["admin", "analyst"] },
      { to: "/analytics", label: "Analytics", icon: BarChart3, roles: ["admin", "analyst", "viewer"] },
    ],
  },
  {
    title: "Threats",
    links: [
      { to: "/alerts", label: "Alerts", icon: BellRing, roles: ["admin", "analyst"] },
      { to: "/incidents", label: "Incidents", icon: Siren, roles: ["admin", "analyst"] },
      { to: "/devices", label: "Devices", icon: MonitorSmartphone, roles: ["admin", "analyst"] },
    ],
  },
  {
    title: "Intelligence",
    links: [
      { to: "/ai-performance", label: "AI Performance", icon: BrainCircuit, roles: ["admin", "analyst", "viewer"] },
      { to: "/reports", label: "Reports", icon: FileText, roles: ["admin", "analyst", "viewer"] },
    ],
  },
  {
    title: "Administration",
    links: [
      { to: "/users", label: "User Management", icon: Users, roles: ["admin"] },
      { to: "/audit", label: "Audit Log", icon: History, roles: ["admin"] },
    ],
  },
];

export default function Sidebar({ role }) {
  const [pending, setPending] = useState(0);

  // Admins: poll for new account requests
  useEffect(() => {
    if (role !== "admin") return;
    let alive = true;
    const check = async () => {
      const n = await api.getPendingCount();
      if (alive) setPending(n);
    };
    check();
    const id = setInterval(check, 20000);
    window.addEventListener("soc-users-changed", check);
    return () => {
      alive = false;
      clearInterval(id);
      window.removeEventListener("soc-users-changed", check);
    };
  }, [role]);

  return (
    <aside
      style={{
        width: 248,
        flexShrink: 0,
        position: "sticky",
        top: 0,
        height: "100vh",
        zIndex: 2,
        display: "flex",
        flexDirection: "column",
        padding: "20px 12px",
        background: "var(--sidebar-bg)",
        borderRight: "1px solid var(--border)",
      }}
    >
      {/* Brand */}
      <div style={{ display: "flex", alignItems: "center", gap: 11, padding: "2px 10px 22px" }}>
        <div
          style={{
            width: 38,
            height: 38,
            borderRadius: 11,
            display: "grid",
            placeItems: "center",
            background: "linear-gradient(135deg, color-mix(in srgb, var(--teal) 18%, transparent), color-mix(in srgb, var(--blue) 18%, transparent))",
            border: "1px solid color-mix(in srgb, var(--teal) 28%, transparent)",
            boxShadow: "0 0 24px -6px color-mix(in srgb, var(--teal) 45%, transparent)",
          }}
        >
          <ShieldHalf size={20} color="var(--teal)" strokeWidth={2} />
        </div>
        <div style={{ lineHeight: 1.15 }}>
          <div style={{ fontWeight: 700, fontSize: 15.5, color: "var(--text)", letterSpacing: "-0.01em" }}>DNSLeak</div>
          <div className="mono" style={{ fontSize: 10.5, color: "var(--accent)", letterSpacing: "0.18em" }}>SENTINEL</div>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: 18, paddingLeft: 12 }}>
        {sections.map((s) => {
          const visible = s.links.filter((l) => l.roles.includes(role));
          if (visible.length === 0) return null;
          return (
            <div key={s.title}>
              <div
                className="mono"
                style={{ fontSize: 10, letterSpacing: "0.16em", textTransform: "uppercase", color: "var(--faint)", padding: "0 12px 8px" }}
              >
                {s.title}
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                {visible.map(({ to, label, icon: Icon }) => (
                  <NavLink key={to} to={to} className={({ isActive }) => "nav-link" + (isActive ? " active" : "")}>
                    <Icon size={17} strokeWidth={1.8} />
                    {label}
                    {to === "/users" && pending > 0 && (
                      <span
                        title={`${pending} account request(s) awaiting approval`}
                        style={{
                          marginLeft: "auto", minWidth: 20, height: 20, padding: "0 6px", borderRadius: 10,
                          display: "grid", placeItems: "center", fontSize: 11, fontWeight: 700, color: "#fff",
                          background: "var(--amber)", boxShadow: "0 0 12px color-mix(in srgb, var(--amber) 50%, transparent)",
                        }}
                      >
                        {pending}
                      </span>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          );
        })}
      </nav>

      {/* Engine status */}
      <div
        style={{
          marginTop: 14,
          padding: 12,
          borderRadius: 12,
          background: "color-mix(in srgb, var(--ink) 4%, transparent)",
          border: "1px solid var(--border)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
          <Cpu size={14} color="var(--violet)" />
          <span style={{ fontSize: 12, fontWeight: 600, color: "var(--text-soft)" }}>Detection Engine</span>
        </div>
        <div className="mono" style={{ fontSize: 10.5, color: "var(--muted)", lineHeight: 1.7 }}>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span>model</span>
            <span style={{ color: "var(--violet)" }}>XGBoost</span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span>fallback</span>
            <span style={{ color: "var(--cyan)" }}>heuristic</span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span>features</span>
            <span style={{ color: "var(--accent)" }}>16</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
