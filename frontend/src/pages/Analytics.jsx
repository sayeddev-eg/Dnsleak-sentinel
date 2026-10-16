import { useState, useEffect } from "react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer, Cell
} from "recharts";
import { RefreshCw, TrendingUp, ShieldAlert, Globe, Server } from "lucide-react";
import { api } from "../api/client";
import { card, tooltipStyle } from "../ui";

export default function Analytics() {
  const [events, setEvents] = useState([]);
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      const [eventsData, devicesData] = await Promise.all([
        api.getDnsEvents(200),
        api.getDevices(),
      ]);
      if (eventsData) setEvents(eventsData);
      if (devicesData) setDevices(devicesData);
    } catch (e) {
      console.warn("Failed to load analytics data:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  // 1. Risk Buckets (0-100)
  const buckets = [
    { range: "0-19%", min: 0, max: 19, label: "Normal" },
    { range: "20-39%", min: 20, max: 39, label: "Guarded" },
    { range: "40-59%", min: 40, max: 59, label: "Elevated" },
    { range: "60-79%", min: 60, max: 79, label: "Suspicious" },
    { range: "80-100%", min: 80, max: 100, label: "Critical" },
  ].map((b) => ({
    range: b.range,
    label: b.label,
    count: events.filter((e) => {
      const score = Number(e.riskScore ?? (e.confidence ? e.confidence * 100 : 0));
      return score >= b.min && score <= b.max;
    }).length,
  }));

  // 2. Suspicious Devices (Endpoints)
  const deviceData = devices
    .filter((d) => d.suspiciousQueries > 0 || d.maxRisk >= 50)
    .slice(0, 6)
    .map((d) => ({
      ip: d.ip,
      count: d.suspiciousQueries || 1,
      risk: d.maxRisk,
    }));

  // If no suspicious devices found in current live log, fallback to top querying IPs
  const displayDeviceData =
    deviceData.length > 0
      ? deviceData
      : devices.slice(0, 5).map((d) => ({ ip: d.ip, count: d.totalQueries, risk: d.maxRisk }));

  // 3. Top Suspicious / Exfiltration Target Domains (Formatted with clean full names)
  const suspiciousEvents = events.filter(
    (e) => (e.prediction && e.prediction !== "normal") || (e.riskScore && e.riskScore >= 50)
  );

  const domainCounts = {};
  suspiciousEvents.forEach((e) => {
    if (e.domain) {
      domainCounts[e.domain] = (domainCounts[e.domain] || 0) + 1;
    }
  });

  const topDomains = Object.entries(domainCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([domain, count]) => {
      // Display name for vertical axis: truncate nicely with ellipsis if too long
      const displayName = domain.length > 24 ? domain.slice(0, 22) + "..." : domain;
      return {
        fullDomain: domain,
        displayName,
        count,
      };
    });

  // 4. DNS Query Types Breakdown (Protocol Distribution)
  const qtypeMap = {};
  events.forEach((e) => {
    const qt = (e.queryType || "A").toUpperCase();
    qtypeMap[qt] = (qtypeMap[qt] || 0) + 1;
  });

  const qtypeData = Object.entries(qtypeMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([type, count]) => ({ type, count }));

  return (
    <div style={{ color: "var(--text)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 26, fontWeight: 700 }}>Security Analytics & Threat Profiling</h1>
          <p style={{ margin: "4px 0 0", color: "var(--muted)", fontSize: 14 }}>
            Aggregated statistical telemetry across {events.length} inspected DNS records
          </p>
        </div>

        <button
          onClick={loadData}
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

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {/* Chart 1: Threat Score Distribution */}
        <div style={card}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
            <TrendingUp size={18} color="var(--amber)" />
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Risk Score Distribution</h3>
          </div>
          <p style={{ margin: "0 0 16px", color: "var(--faint)", fontSize: 12 }}>
            Frequency of DNS queries by model risk percentage tier
          </p>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={buckets}>
              <CartesianGrid stroke="var(--border)" />
              <XAxis dataKey="range" stroke="var(--muted)" tick={{ fontSize: 12 }} />
              <YAxis stroke="var(--muted)" allowDecimals={false} />
              <Tooltip
                contentStyle={tooltipStyle}
                formatter={(value, name, item) => [`${value} queries (${item.payload.label})`, "Count"]}
              />
              <Bar dataKey="count" fill="var(--amber)" radius={[4, 4, 0, 0]}>
                {buckets.map((b, i) => (
                  <Cell
                    key={i}
                    fill={b.range.startsWith("80") ? "var(--rose)" : b.range.startsWith("60") ? "var(--amber)" : "var(--blue)"}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Chart 2: Top Suspicious Devices */}
        <div style={card}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
            <Server size={18} color="var(--rose)" />
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Suspicious Source Devices</h3>
          </div>
          <p style={{ margin: "0 0 16px", color: "var(--faint)", fontSize: 12 }}>
            Internal endpoints generating anomalous or suspicious DNS requests
          </p>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={displayDeviceData}>
              <CartesianGrid stroke="var(--border)" />
              <XAxis dataKey="ip" stroke="var(--muted)" tick={{ fontSize: 11 }} />
              <YAxis stroke="var(--muted)" allowDecimals={false} />
              <Tooltip contentStyle={tooltipStyle} formatter={(val) => [`${val} suspicious queries`, "Count"]} />
              <Bar dataKey="count" fill="var(--rose)" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Chart 3: Top Suspicious / Exfiltration Target Domains (HORIZONTAL BAR CHART TO PREVENT OVERLAP) */}
        <div style={card}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
            <ShieldAlert size={18} color="var(--blue)" />
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>Top Suspicious Target Domains</h3>
          </div>
          <p style={{ margin: "0 0 16px", color: "var(--faint)", fontSize: 12 }}>
            Domains flagged for high entropy, long subdomains, or C2 tunneling
          </p>

          {topDomains.length === 0 ? (
            <div style={{ height: 260, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--faint)" }}>
              No suspicious domains detected yet.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={topDomains} layout="vertical" margin={{ left: 10, right: 30, top: 10, bottom: 10 }}>
                <CartesianGrid stroke="var(--border)" />
                <XAxis type="number" stroke="var(--muted)" allowDecimals={false} />
                <YAxis
                  type="category"
                  dataKey="displayName"
                  stroke="var(--muted)"
                  width={160}
                  tick={{ fontSize: 12, fill: "var(--text-soft)" }}
                />
                <Tooltip
                  contentStyle={tooltipStyle}
                  formatter={(value, name, item) => [
                    `${value} queries`,
                    item.payload.fullDomain
                  ]}
                />
                <Bar dataKey="count" fill="var(--cyan)" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Chart 4: DNS Query Protocol Types */}
        <div style={card}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
            <Globe size={18} color="var(--violet)" />
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>DNS Record Types Distribution</h3>
          </div>
          <p style={{ margin: "0 0 16px", color: "var(--faint)", fontSize: 12 }}>
            Distribution of DNS query types (A, TXT payload carriers, CNAME, etc.)
          </p>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={qtypeData.length > 0 ? qtypeData : [{ type: "A", count: 1 }]}>
              <CartesianGrid stroke="var(--border)" />
              <XAxis dataKey="type" stroke="var(--muted)" tick={{ fontSize: 12 }} />
              <YAxis stroke="var(--muted)" allowDecimals={false} />
              <Tooltip contentStyle={tooltipStyle} formatter={(val) => [`${val} requests`, "Count"]} />
              <Bar dataKey="count" fill="var(--violet)" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
