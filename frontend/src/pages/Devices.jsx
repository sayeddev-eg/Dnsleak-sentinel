import { useState, useEffect } from "react";
import { RefreshCw, Monitor, ShieldAlert } from "lucide-react";
import { api } from "../api/client";
import { card, th, td } from "../ui";

export default function Devices() {
  const [deviceList, setDeviceList] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchDevices = async () => {
    try {
      const data = await api.getDevices();
      if (data) setDeviceList(data);
    } catch (e) {
      console.warn("Error fetching devices:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDevices();
    const interval = setInterval(fetchDevices, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ color: "var(--text)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 26, fontWeight: 700 }}>Monitored Network Devices</h1>
          <p style={{ margin: "4px 0 0", color: "var(--muted)", fontSize: 14 }}>
            Aggregated traffic profiling and threat scoring per endpoint ({deviceList.length} devices)
          </p>
        </div>

        <button
          onClick={fetchDevices}
          style={{
            background: "var(--input-bg)",
            border: "1px solid var(--border)",
            color: "var(--muted)",
            padding: "8px 12px",
            borderRadius: 8,
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            gap: 6,
          }}
        >
          <RefreshCw size={15} />
          Refresh
        </button>
      </div>

      <div style={{ ...card, overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={th}>Device IP Address</th>
              <th style={th}>Total Queries</th>
              <th style={th}>Suspicious Queries</th>
              <th style={th}>Max Risk Score</th>
              <th style={th}>Security Status</th>
            </tr>
          </thead>
          <tbody>
            {deviceList.length === 0 ? (
              <tr>
                <td colSpan={5} style={{ textAlign: "center", padding: 30, color: "var(--faint)" }}>
                  {loading ? "Discovering active devices..." : "No network devices found in current database."}
                </td>
              </tr>
            ) : (
              deviceList.map((d, i) => (
                <tr key={i} style={{ borderTop: "1px solid var(--border)" }}>
                  <td style={{ ...td, fontWeight: 600, color: "var(--text-soft)" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <Monitor size={16} color="var(--blue)" />
                      {d.ip}
                    </div>
                  </td>
                  <td style={td}>{d.totalQueries}</td>
                  <td style={{ ...td, color: d.suspiciousQueries > 0 ? "var(--amber)" : "var(--muted)", fontWeight: 600 }}>
                    {d.suspiciousQueries}
                  </td>
                  <td style={{ ...td, color: d.maxRisk >= 80 ? "var(--rose)" : d.maxRisk >= 50 ? "var(--amber)" : "var(--teal)", fontWeight: 700 }}>
                    {d.maxRisk}%
                  </td>
                  <td style={td}>
                    <span
                      style={{
                        padding: "3px 8px",
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 700,
                        textTransform: "uppercase",
                        background: d.status === "suspicious" ? "color-mix(in srgb, var(--rose) 15%, transparent)" : "color-mix(in srgb, var(--teal) 15%, transparent)",
                        color: d.status === "suspicious" ? "var(--rose)" : "var(--teal)",
                      }}
                    >
                      {d.status}
                    </span>
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
