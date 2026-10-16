import { useState, useEffect } from "react";
import { Trash2, RefreshCw, AlertOctagon, Download, Search } from "lucide-react";
import { api } from "../api/client";
import { card, th, td, COLORS } from "../ui";

export default function Alerts() {
  const [alertsList, setAlertsList] = useState([]);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [clearing, setClearing] = useState(false);

  const fetchAlerts = async () => {
    try {
      const data = await api.getAlerts(100);
      if (data) setAlertsList(data);
    } catch (e) {
      console.warn("Failed fetching alerts:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleClear = async () => {
    if (!window.confirm("Are you sure you want to clear all logged alerts?")) return;
    setClearing(true);
    try {
      await api.clearAlerts();
      setAlertsList([]);
    } catch (e) {
      alert("Failed to clear alerts.");
    } finally {
      setClearing(false);
    }
  };

  const handleExport = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(alertsList, null, 2));
    const dlAnchor = document.createElement("a");
    dlAnchor.setAttribute("href", dataStr);
    dlAnchor.setAttribute("download", `dns_alerts_${new Date().toISOString().slice(0, 10)}.json`);
    dlAnchor.click();
    api.logEvent("alerts.export", `dns_alerts_${new Date().toISOString().slice(0, 10)}.json`, { records: alertsList.length, format: "json" });
  };

  const filtered = alertsList.filter((a) => {
    const dev = a.device || "";
    const dom = a.domain || "";
    const matchText = dev.includes(search) || dom.includes(search);
    const matchSev = severityFilter === "all" || a.severity === severityFilter;
    return matchText && matchSev;
  });

  return (
    <div style={{ color: "var(--text)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 26, fontWeight: 700 }}>Security Incident Alerts</h1>
          <p style={{ margin: "4px 0 0", color: "var(--muted)", fontSize: 14 }}>
            Classified high-risk anomalies, tunneling indicators, and data leak alerts ({alertsList.length})
          </p>
        </div>

        <div style={{ display: "flex", gap: 10 }}>
          <button
            onClick={handleExport}
            disabled={alertsList.length === 0}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              background: "var(--border)",
              border: "1px solid var(--border-strong)",
              color: "var(--text-soft)",
              padding: "8px 14px",
              borderRadius: 8,
              cursor: alertsList.length === 0 ? "not-allowed" : "pointer",
              fontSize: 13,
              fontWeight: 600,
            }}
          >
            <Download size={15} />
            Export
          </button>

          <button
            onClick={handleClear}
            disabled={clearing || alertsList.length === 0}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              background: "color-mix(in srgb, var(--rose) 15%, transparent)",
              border: "1px solid color-mix(in srgb, var(--rose) 40%, transparent)",
              color: "var(--rose)",
              padding: "8px 14px",
              borderRadius: 8,
              cursor: clearing || alertsList.length === 0 ? "not-allowed" : "pointer",
              fontSize: 13,
              fontWeight: 600,
            }}
          >
            <Trash2 size={15} />
            {clearing ? "Clearing..." : "Clear Alerts"}
          </button>

          <button
            onClick={fetchAlerts}
            style={{
              background: "var(--input-bg)",
              border: "1px solid var(--border)",
              color: "var(--muted)",
              padding: "8px",
              borderRadius: 8,
              cursor: "pointer",
            }}
          >
            <RefreshCw size={16} />
          </button>
        </div>
      </div>

      {/* Filter and Search */}
      <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
        <input
          style={{ background: "var(--input-bg)", border: "1px solid var(--border)", color: "var(--text)", borderRadius: 8, padding: "8px 12px", width: 280, outline: "none" }}
          placeholder="Filter by IP or domain..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          style={{ background: "var(--input-bg)", border: "1px solid var(--border)", color: "var(--text)", borderRadius: 8, padding: "8px 12px", outline: "none" }}
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical (&gt;89%)</option>
          <option value="suspicious">Suspicious (&gt;60%)</option>
        </select>
      </div>

      <div style={{ ...card, overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={th}>Alert ID</th>
              <th style={th}>Time</th>
              <th style={th}>Source Device</th>
              <th style={th}>Target Domain</th>
              <th style={th}>Risk Score</th>
              <th style={th}>Severity</th>
              <th style={th}>Inference Reasons</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: "center", padding: 30, color: "var(--faint)" }}>
                  {loading ? "Loading alerts..." : "No alerts found in database."}
                </td>
              </tr>
            ) : (
              filtered.map((a, i) => (
                <tr key={i} style={{ borderTop: "1px solid var(--border)" }}>
                  <td style={td}>{a.id}</td>
                  <td style={{ ...td, color: "var(--muted)" }}>{a.timestamp}</td>
                  <td style={td}>{a.device}</td>
                  <td style={{ ...td, color: "var(--blue)" }}>{a.domain}</td>
                  <td style={{ ...td, color: (COLORS && COLORS[a.severity]) || "var(--rose)", fontWeight: 700 }}>
                    {a.riskScore}%
                  </td>
                  <td style={{ ...td, textTransform: "capitalize", fontWeight: 600, color: (COLORS && COLORS[a.severity]) || "var(--rose)" }}>
                    {a.severity}
                  </td>
                  <td style={{ ...td, color: "var(--muted)", fontSize: 12 }}>
                    {Array.isArray(a.reasons) ? a.reasons.join(", ") : a.reasons || "—"}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
