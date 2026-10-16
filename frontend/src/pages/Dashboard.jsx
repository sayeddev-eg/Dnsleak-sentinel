import { useState, useEffect } from "react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid,
  PieChart, Pie, Cell, ResponsiveContainer,
} from "recharts";
import {
  UploadCloud, RefreshCw, Zap, Activity, ShieldCheck, TriangleAlert, ShieldX,
  Globe, Monitor, Loader2, CheckCircle2, XCircle, Inbox,
} from "lucide-react";
import { api } from "../api/client";
import { card, PALETTE, tooltipStyle, tint } from "../ui";

const SEV = {
  critical: { c: PALETTE.rose, bg: "color-mix(in srgb, var(--rose) 10%, transparent)", b: "color-mix(in srgb, var(--rose) 25%, transparent)" },
  high: { c: PALETTE.amber, bg: "color-mix(in srgb, var(--amber) 10%, transparent)", b: "color-mix(in srgb, var(--amber) 25%, transparent)" },
  suspicious: { c: PALETTE.amber, bg: "color-mix(in srgb, var(--amber) 10%, transparent)", b: "color-mix(in srgb, var(--amber) 25%, transparent)" },
  medium: { c: "var(--gold)", bg: "color-mix(in srgb, var(--gold) 10%, transparent)", b: "color-mix(in srgb, var(--gold) 25%, transparent)" },
  low: { c: PALETTE.teal, bg: "color-mix(in srgb, var(--teal) 10%, transparent)", b: "color-mix(in srgb, var(--teal) 25%, transparent)" },
};

function StatCard({ label, value, color, icon: Icon, share, hint }) {
  return (
    <div style={{ ...card, padding: 18, position: "relative", overflow: "hidden" }}>
      <div
        style={{
          position: "absolute", right: -30, top: -30, width: 120, height: 120, borderRadius: 999,
          background: `radial-gradient(circle, ${tint(color, 14)}, transparent 70%)`,
        }}
      />
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <span style={{ color: PALETTE.muted, fontSize: 13, fontWeight: 500 }}>{label}</span>
        <div
          style={{
            width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center",
            background: tint(color, 9), border: `1px solid ${tint(color, 22)}`,
          }}
        >
          <Icon size={17} color={color} />
        </div>
      </div>
      <div style={{ fontSize: 32, fontWeight: 700, marginTop: 8, letterSpacing: "-0.02em", color: PALETTE.text }}>
        {Number(value).toLocaleString()}
      </div>
      <div style={{ marginTop: 10 }}>
        <div style={{ height: 4, borderRadius: 4, background: "var(--border)", overflow: "hidden" }}>
          <div style={{ width: `${Math.min(100, share)}%`, height: "100%", background: color, borderRadius: 4, transition: "width .6s ease" }} />
        </div>
        <div className="mono" style={{ fontSize: 11, color: PALETTE.faint, marginTop: 6 }}>{hint}</div>
      </div>
    </div>
  );
}

function SectionTitle({ icon: Icon, color, title, right }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <Icon size={16} color={color} />
        <h3 style={{ margin: 0, fontSize: 15, fontWeight: 600, color: PALETTE.text }}>{title}</h3>
      </div>
      {right}
    </div>
  );
}

function Empty({ text }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8, padding: "28px 0", color: PALETTE.faint, fontSize: 13 }}>
      <Inbox size={22} />
      {text}
    </div>
  );
}

const btn = {
  display: "flex", alignItems: "center", gap: 7, padding: "8px 14px", borderRadius: 10,
  fontSize: 13, fontWeight: 600, cursor: "pointer", border: "1px solid color-mix(in srgb, var(--ink) 14%, transparent)",
  background: "color-mix(in srgb, var(--ink) 5%, transparent)", color: PALETTE.soft,
};

export default function Dashboard() {
  const [kpi, setKpi] = useState({ total_queries: 0, normal: 0, suspicious: 0, critical: 0 });
  const [traffic, setTraffic] = useState([]);
  const [topAlerts, setTopAlerts] = useState([]);
  const [topDevices, setTopDevices] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [uploadMsg, setUploadMsg] = useState(null);
  const [spinning, setSpinning] = useState(false);

  const loadData = async () => {
    try {
      const [kpiData, trendData, alertsData, devicesData] = await Promise.all([
        api.getKpi(), api.getTrafficTrend(), api.getAlerts(5), api.getDevices(),
      ]);
      if (kpiData) setKpi(kpiData);
      if (trendData && trendData.length > 0) setTraffic(trendData);
      if (alertsData) setTopAlerts(alertsData.slice(0, 5));
      if (devicesData) setTopDevices(devicesData.slice(0, 5));
    } catch (e) {
      console.warn("Failed loading live dashboard data:", e);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 4000);
    return () => clearInterval(interval);
  }, []);

  const refresh = async () => {
    setSpinning(true);
    await loadData();
    setTimeout(() => setSpinning(false), 500);
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    setUploadMsg({ type: "info", text: `Analyzing ${file.name}…` });
    try {
      const res = await api.uploadPcap(file);
      setUploadMsg({
        type: "ok",
        text: `Analyzed ${res.summary?.total_dns_queries || 0} DNS queries — ${res.summary?.critical || 0} critical, ${res.summary?.suspicious || 0} suspicious.`,
      });
      loadData();
    } catch (err) {
      setUploadMsg({ type: "err", text: `Upload error: ${err.message}` });
    } finally {
      setUploading(false);
      e.target.value = "";
    }
  };

  const handleSimulate = async () => {
    try {
      await api.simulateQuery(true);
      loadData();
    } catch (e) {
      console.warn("Simulation failed:", e);
    }
  };

  const total = kpi.total_queries || 0;
  const normal = kpi.normal || 0;
  const suspicious = kpi.suspicious || 0;
  const critical = kpi.critical || 0;
  const pct = (v) => (total ? (v / total) * 100 : 0);

  const pieData = [
    { name: "Normal", value: normal, color: PALETTE.teal },
    { name: "Suspicious", value: suspicious, color: PALETTE.amber },
    { name: "Critical", value: critical, color: PALETTE.rose },
  ];
  const pieHasData = pieData.some((d) => d.value > 0);

  const msgStyle = {
    ok: { c: PALETTE.teal, bg: "color-mix(in srgb, var(--teal) 8%, transparent)", b: "color-mix(in srgb, var(--teal) 25%, transparent)", I: CheckCircle2 },
    err: { c: PALETTE.rose, bg: "color-mix(in srgb, var(--rose) 8%, transparent)", b: "color-mix(in srgb, var(--rose) 25%, transparent)", I: XCircle },
    info: { c: PALETTE.blue, bg: "color-mix(in srgb, var(--blue) 8%, transparent)", b: "color-mix(in srgb, var(--blue) 25%, transparent)", I: Loader2 },
  };

  return (
    <div style={{ color: PALETTE.text }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", flexWrap: "wrap", gap: 16, marginBottom: 22 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 24, fontWeight: 700 }}>Threat Intelligence Dashboard</h1>
          <p style={{ margin: "6px 0 0", color: PALETTE.muted, fontSize: 13.5 }}>
            Real-time DNS exfiltration & tunneling monitoring
          </p>
        </div>

        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <label style={{ ...btn, cursor: uploading ? "wait" : "pointer" }}>
            {uploading ? <Loader2 size={16} className="animate-spin" color={PALETTE.blue} /> : <UploadCloud size={16} color={PALETTE.blue} />}
            {uploading ? "Analyzing…" : "Analyze PCAP"}
            <input type="file" accept=".pcap,.pcapng" onChange={handleFileUpload} disabled={uploading} style={{ display: "none" }} />
          </label>

          <button
            onClick={handleSimulate}
            style={{ ...btn, color: PALETTE.rose, background: "color-mix(in srgb, var(--rose) 7%, transparent)", border: "1px solid color-mix(in srgb, var(--rose) 25%, transparent)" }}
            title="Inject a simulated DNS exfiltration query"
          >
            <Zap size={15} /> Simulate Attack
          </button>

          <button onClick={refresh} style={{ ...btn, padding: 9 }} title="Refresh">
            <RefreshCw size={16} style={{ transition: "transform .5s", transform: spinning ? "rotate(360deg)" : "none" }} />
          </button>
        </div>
      </div>

      {uploadMsg && (() => {
        const s = msgStyle[uploadMsg.type];
        return (
          <div
            className="fade-up"
            style={{
              display: "flex", alignItems: "center", gap: 10, padding: "11px 14px", borderRadius: 12, fontSize: 13,
              marginBottom: 16, color: s.c, background: s.bg, border: `1px solid ${s.b}`,
            }}
          >
            <s.I size={16} className={uploadMsg.type === "info" ? "animate-spin" : ""} />
            <span style={{ flex: 1 }}>{uploadMsg.text}</span>
            <button onClick={() => setUploadMsg(null)} style={{ background: "none", border: "none", color: "inherit", cursor: "pointer", opacity: 0.7 }}>✕</button>
          </div>
        );
      })()}

      {/* KPI */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 16, marginBottom: 16 }}>
        <StatCard label="Total DNS Queries" value={total} color={PALETTE.blue} icon={Activity} share={100} hint="inspected since start" />
        <StatCard label="Benign Traffic" value={normal} color={PALETTE.teal} icon={ShieldCheck} share={pct(normal)} hint={`${pct(normal).toFixed(1)}% of traffic`} />
        <StatCard label="Suspicious" value={suspicious} color={PALETTE.amber} icon={TriangleAlert} share={pct(suspicious)} hint={`${pct(suspicious).toFixed(1)}% of traffic`} />
        <StatCard label="Critical Threats" value={critical} color={PALETTE.rose} icon={ShieldX} share={pct(critical)} hint={`${pct(critical).toFixed(1)}% of traffic`} />
      </div>

      {/* Charts */}
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 2fr) minmax(280px, 1fr)", gap: 16, marginBottom: 16 }}>
        <div style={card}>
          <SectionTitle
            icon={Activity}
            color={PALETTE.cyan}
            title="Traffic Dynamics"
            right={
              <div style={{ display: "flex", gap: 14, fontSize: 12, color: PALETTE.muted }}>
                <span style={{ display: "flex", alignItems: "center", gap: 6 }}><i style={{ width: 8, height: 8, borderRadius: 9, background: PALETTE.teal }} />Normal</span>
                <span style={{ display: "flex", alignItems: "center", gap: 6 }}><i style={{ width: 8, height: 8, borderRadius: 9, background: PALETTE.rose }} />Suspicious</span>
              </div>
            }
          />
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={traffic.length > 0 ? traffic : [{ time: "--:--", normal: 0, suspicious: 0 }]} margin={{ left: -18, right: 6, top: 6 }}>
              <defs>
                <linearGradient id="gNormal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={PALETTE.teal} stopOpacity={0.35} />
                  <stop offset="100%" stopColor={PALETTE.teal} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gSusp" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={PALETTE.rose} stopOpacity={0.35} />
                  <stop offset="100%" stopColor={PALETTE.rose} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke={PALETTE.grid} vertical={false} />
              <XAxis dataKey="time" tickLine={false} axisLine={false} />
              <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={tooltipStyle} />
              <Area type="monotone" dataKey="normal" name="Normal" stroke={PALETTE.teal} strokeWidth={2} fill="url(#gNormal)" />
              <Area type="monotone" dataKey="suspicious" name="Suspicious" stroke={PALETTE.rose} strokeWidth={2} fill="url(#gSusp)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div style={card}>
          <SectionTitle icon={ShieldCheck} color={PALETTE.violet} title="Threat Distribution" />
          <div style={{ position: "relative", height: 190 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieHasData ? pieData : [{ name: "No data", value: 1, color: "color-mix(in srgb, var(--ink) 12%, transparent)" }]}
                  dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={62} outerRadius={84}
                  paddingAngle={pieHasData ? 3 : 0} stroke="none" cornerRadius={6}
                >
                  {(pieHasData ? pieData : [{ color: "color-mix(in srgb, var(--ink) 12%, transparent)" }]).map((e, i) => <Cell key={i} fill={e.color} />)}
                </Pie>
                {pieHasData && <Tooltip contentStyle={tooltipStyle} />}
              </PieChart>
            </ResponsiveContainer>
            <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", pointerEvents: "none" }}>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 24, fontWeight: 700 }}>{total.toLocaleString()}</div>
                <div className="mono" style={{ fontSize: 10.5, color: PALETTE.faint, letterSpacing: "0.1em" }}>QUERIES</div>
              </div>
            </div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 10 }}>
            {pieData.map((d) => (
              <div key={d.name} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: 13 }}>
                <span style={{ display: "flex", alignItems: "center", gap: 8, color: PALETTE.muted }}>
                  <i style={{ width: 8, height: 8, borderRadius: 3, background: d.color }} />
                  {d.name}
                </span>
                <span className="mono" style={{ color: PALETTE.soft }}>
                  {d.value} <span style={{ color: PALETTE.faint }}>· {pct(d.value).toFixed(0)}%</span>
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom */}
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1.4fr) minmax(0, 1fr)", gap: 16 }}>
        <div style={card}>
          <SectionTitle
            icon={Globe}
            color={PALETTE.rose}
            title="Latest Security Alerts"
            right={<span className="mono" style={{ fontSize: 11, color: PALETTE.faint }}>live · db</span>}
          />
          {topAlerts.length === 0 ? (
            <Empty text="No alerts yet — upload a PCAP or simulate an attack." />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {topAlerts.map((a, i) => {
                const s = SEV[a.severity] || SEV.high;
                return (
                  <div
                    key={i}
                    style={{
                      display: "flex", alignItems: "center", gap: 12, padding: "10px 12px", borderRadius: 12,
                      background: "var(--surface-2)", border: "1px solid color-mix(in srgb, var(--ink) 6%, transparent)",
                    }}
                  >
                    <span style={{ width: 8, height: 8, borderRadius: 99, background: s.c, boxShadow: `0 0 10px ${s.c}` }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="mono" style={{ color: PALETTE.soft, fontSize: 12.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={a.domain}>
                        {a.domain}
                      </div>
                      <div style={{ color: PALETTE.faint, fontSize: 11.5, marginTop: 2 }}>
                        {a.device} · {a.timestamp}
                      </div>
                    </div>
                    <span
                      className="mono"
                      style={{
                        padding: "3px 9px", borderRadius: 999, fontSize: 10.5, fontWeight: 600, textTransform: "uppercase",
                        letterSpacing: "0.05em", color: s.c, background: s.bg, border: `1px solid ${s.b}`, whiteSpace: "nowrap",
                      }}
                    >
                      {a.severity} · {a.riskScore}%
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div style={card}>
          <SectionTitle icon={Monitor} color={PALETTE.amber} title="High-Risk Devices" />
          {topDevices.length === 0 ? (
            <Empty text="No high-risk devices identified." />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              {topDevices.map((d, i) => {
                const risk = Number(d.maxRisk) || 0;
                const c = risk >= 85 ? PALETTE.rose : risk >= 50 ? PALETTE.amber : PALETTE.teal;
                return (
                  <div key={i}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 6 }}>
                      <span className="mono" style={{ fontSize: 12.5, color: PALETTE.soft }}>{d.ip}</span>
                      <span style={{ fontSize: 12, color: PALETTE.faint }}>
                        {d.suspiciousQueries} flagged ·{" "}
                        <b className="mono" style={{ color: c, fontWeight: 600 }}>{risk}%</b>
                      </span>
                    </div>
                    <div style={{ height: 5, borderRadius: 5, background: "var(--border)", overflow: "hidden" }}>
                      <div style={{ width: `${risk}%`, height: "100%", borderRadius: 5, background: `linear-gradient(90deg, ${tint(c, 55)}, ${c})`, transition: "width .6s ease" }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
