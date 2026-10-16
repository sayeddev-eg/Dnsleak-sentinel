import { useState, useEffect } from "react";
import { HashRouter, Routes, Route, Navigate, Link } from "react-router-dom";
import Layout from "./components/Layout";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import LiveMonitoring from "./pages/LiveMonitoring";
import Devices from "./pages/Devices";
import Alerts from "./pages/Alerts";
import Incidents from "./pages/Incidents";
import Analytics from "./pages/Analytics";
import AIPerformance from "./pages/AIPerformance";
import Reports from "./pages/Reports";
import UserManagement from "./pages/UserManagement";
import AuditLog from "./pages/AuditLog";
import { api } from "./api/client";

const pages = [
  { path: "/dashboard", title: "Dashboard", roles: ["admin", "analyst", "viewer"], element: <Dashboard /> },
  { path: "/live", title: "Live Monitoring", roles: ["admin", "analyst"], element: <LiveMonitoring /> },
  { path: "/devices", title: "Devices", roles: ["admin", "analyst"], element: <Devices /> },
  { path: "/alerts", title: "Alerts", roles: ["admin", "analyst"], element: <Alerts /> },
  { path: "/incidents", title: "Incidents", roles: ["admin", "analyst"], element: <Incidents /> },
  { path: "/analytics", title: "Analytics", roles: ["admin", "analyst", "viewer"], element: <Analytics /> },
  { path: "/ai-performance", title: "AI Performance", roles: ["admin", "analyst", "viewer"], element: <AIPerformance /> },
  { path: "/reports", title: "Reports", roles: ["admin", "analyst", "viewer"], element: <Reports /> },
  { path: "/users", title: "User Management", roles: ["admin"], element: <UserManagement /> },
  { path: "/audit", title: "Audit Log", roles: ["admin"], element: <AuditLog /> },
];

function Placeholder({ title }) {
  return (
    <div style={{ padding: 24, color: "var(--text)" }}>
      <h1 style={{ fontSize: 28, fontWeight: 700 }}>{title}</h1>
      <p style={{ color: "var(--muted)", marginTop: 8 }}>This module is ready for future cyber operations.</p>
    </div>
  );
}

function AccessDenied() {
  return (
    <div style={{ padding: 48, textAlign: "center", color: "var(--text)" }}>
      <h1 style={{ fontSize: 28, fontWeight: 700, color: "var(--rose)", margin: 0 }}>403 · Access Denied</h1>
      <p style={{ color: "var(--muted)", marginTop: 10, marginBottom: 22 }}>
        Your current security role does not have authorization to view this resource.
      </p>
      <Link
        to="/dashboard"
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 8,
          padding: "10px 18px",
          borderRadius: 10,
          textDecoration: "none",
          fontWeight: 600,
          fontSize: 13.5,
          color: "var(--on-accent)",
          background: "linear-gradient(135deg, var(--teal), var(--cyan))",
        }}
      >
        Back to Dashboard
      </Link>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState(() => {
    try {
      const saved = JSON.parse(localStorage.getItem("soc_user") || "null");
      // Sessions created before token auth existed must sign in again
      return saved && saved.token ? saved : null;
    } catch {
      return null;
    }
  });

  const clearSession = () => {
    localStorage.removeItem("soc_user");
    window.location.hash = "#/";
    setUser(null);
  };

  const handleLogin = (loggedInUser) => {
    window.location.hash = "#/dashboard";
    setUser(loggedInUser);
  };

  const handleLogout = async () => {
    await api.logout();
    clearSession();
  };

  // Backend rejected our token (expired / server secret changed) → back to login
  useEffect(() => {
    const onExpired = () => clearSession();
    window.addEventListener("soc-auth-expired", onExpired);
    return () => window.removeEventListener("soc-auth-expired", onExpired);
  }, []);

  if (!user) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <HashRouter>
      <Routes>
        <Route element={<Layout user={user} onLogout={handleLogout} />}>
          <Route path="/" element={<Navigate to="/dashboard" />} />
          {pages.map((p) => (
            <Route
              key={p.path}
              path={p.path}
              element={
                p.roles.includes(user.role) ? (p.element ?? <Placeholder title={p.title} />) : <AccessDenied />
              }
            />
          ))}
          <Route path="*" element={<Navigate to="/dashboard" />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}
