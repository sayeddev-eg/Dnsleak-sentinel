import { useEffect } from "react";
import { Outlet, useLocation } from "react-router-dom";
import Sidebar from "./Sidebar";
import Navbar from "./Navbar";
import CyberBackground from "./CyberBackground";
import { api } from "../api/client";

export default function Layout({ user, onLogout }) {
  const location = useLocation();

  // Record page views in the audit log
  useEffect(() => {
    api.logEvent("page.view", location.pathname);
  }, [location.pathname]);

  return (
    <div style={{ display: "flex", minHeight: "100vh", position: "relative" }}>
      <CyberBackground density={0.8} />

      <Sidebar role={user.role} />

      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, position: "relative", zIndex: 1 }}>
        <Navbar user={user} onLogout={onLogout} />

        <main style={{ flex: 1, padding: "24px 28px 40px", color: "var(--text)" }}>
          <div key={location.pathname} className="page-enter" style={{ maxWidth: 1480, margin: "0 auto" }}>
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
