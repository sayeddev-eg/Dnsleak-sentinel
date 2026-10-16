import { useState, useEffect } from "react";
import { Upload, RefreshCw, Zap, Search, ShieldAlert, CheckCircle2 } from "lucide-react";
import { api } from "../api/client";

const COLORS = { critical: "var(--rose)", high: "var(--amber)", medium: "var(--gold)", low: "var(--teal)", normal: "var(--teal)", suspicious: "var(--amber)" };
const card = { background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 16, padding: 20 };
const input = { background: "var(--input-bg)", border: "1px solid var(--border)", color: "var(--text)", borderRadius: 8, padding: "8px 12px", outline: "none" };

export default function LiveMonitoring() {
  const [events, setEvents] = useState([]);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [statusMsg, setStatusMsg] = useState("");

  const fetchEvents = async () => {
    try {
      const data = await api.getDnsEvents(150);
      if (data && data.length > 0) {
        setEvents(data);
      }
    } catch (e) {
      console.warn("Failed fetching live events:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
    const interval = setInterval(fetchEvents, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    setStatusMsg(`Processing ${file.name}...`);
    try {
      const res = await api.uploadPcap(file);
      setStatusMsg(`Analyzed ${res.summary?.total_dns_queries || 0} packets (${res.summary?.critical || 0} critical).`);
      fetchEvents();
    } catch (err) {
      setStatusMsg(`Upload error: ${err.message}`);
    } finally {
      setUploading(false);
    }
  };

  const handleSimulate = async (isAttack) => {
    setStatusMsg(isAttack ? "Simulating attack DNS query..." : "Simulating benign query...");
    try {
      await api.simulateQuery(isAttack);
      setStatusMsg(isAttack ? "Injected suspicious tunnel DNS query." : "Injected normal DNS query.");
      fetchEvents();
    } catch (e) {
      setStatusMsg("Simulation failed.");
    }
  };

  const rows = events.filter((e) => {
    const ip = e.sourceIp || "";
    const dom = e.domain || "";
    const matchText = ip.toLowerCase().includes(search.toLowerCase()) || dom.toLowerCase().includes(search.toLowerCase());
    const matchFilter =
      filter === "all" ||
      e.prediction === filter ||
      e.severity === filter;
    return matchText && matchFilter;
  });

  return (
    <div style={{ color: "var(--text)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 26, fontWeight: 700 }}>Live DNS Stream & Monitoring</h1>
          <p style={{ margin: "4px 0 0", color: "var(--muted)", fontSize: 14 }}>Real-time packet inspection from network sensors & collectors</p>
        </div>

        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <label
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              background: "var(--border)",
              border: "1px solid var(--border-strong)",
              color: "var(--text)",
              padding: "8px 14px",
              borderRadius: 8,
              cursor: uploading ? "wait" : "pointer",
              fontSize: 13,
              fontWeight: 600,
            }}
          >
            <Upload size={16} color="var(--blue)" />
            {uploading ? "Analyzing PCAP..." : "Upload .PCAP Stream"}
            <input type="file" accept=".pcap,.pcapng" onChange={handleFileUpload} disabled={uploading} style={{ display: "none" }} />
          </label>

          <button
            onClick={() => handleSimulate(true)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              background: "color-mix(in srgb, var(--rose) 15%, transparent)",
              border: "1px solid color-mix(in srgb, var(--rose) 40%, transparent)",
              color: "var(--rose)",
              padding: "8px 12px",
              borderRadius: 8,
              cursor: "pointer",
              fontSize: 13,
              fontWeight: 600,
            }}
          >
            <Zap size={15} />
            Simulate Threat
          </button>

          <button
            onClick={fetchEvents}
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

      {statusMsg && (
        <div style={{ background: "var(--surface-2)", border: "1px solid var(--border-strong)", color: "var(--muted)", padding: "8px 14px", borderRadius: 8, fontSize: 13, marginBottom: 16 }}>
          {statusMsg}
        </div>
      )}

      {/* Filter and Search Bar */}
      <div style={{ display: "flex", gap: 12, marginBottom: 16, alignItems: "center" }}>
        <div style={{ position: "relative", width: 320 }}>
          <Search size={16} style={{ position: "absolute", left: 12, top: 11, color: "var(--faint)" }} />
          <input
            style={{ ...input, width: "100%", paddingLeft: 36 }}
            placeholder="Search by IP, domain, or subdomain..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <select style={input} value={filter} onChange={(e) => setFilter(e.target.value)}>
          <option value="all">All Statuses ({events.length})</option>
          <option value="critical">Critical Threats</option>
          <option value="suspicious">Suspicious</option>
          <option value="normal">Benign Traffic</option>
        </select>

        <span style={{ color: "var(--faint)", fontSize: 13, marginLeft: "auto" }}>
          Showing {rows.length} of {events.length} logged queries
        </span>
      </div>

      {/* Events Table */}
      <div style={{ ...card, overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left" }}>
          <thead>
            <tr style={{ color: "var(--muted)", fontSize: 13, borderBottom: "1px solid var(--border)" }}>
              <th style={{ padding: "12px 10px" }}>Timestamp</th>
              <th>Source IP</th>
              <th>Queried Domain</th>
              <th>Type</th>
              <th>AI Risk Score</th>
              <th>Verdict</th>
              <th>Detection Reasons</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: "center", padding: 30, color: "var(--faint)" }}>
                  {loading ? "Streaming live DNS events..." : "No DNS traffic matching current filter."}
                </td>
              </tr>
            ) : (
              rows.slice(0, 100).map((e, idx) => (
                <tr key={idx} style={{ borderTop: "1px solid var(--border)", fontSize: 13 }}>
                  <td style={{ padding: 10, color: "var(--muted)", whiteSpace: "nowrap" }}>{e.timestamp}</td>
                  <td style={{ fontWeight: 600, color: "var(--text-soft)" }}>{e.sourceIp}</td>
                  <td style={{ color: "var(--blue)", maxWidth: 280, wordBreak: "break-all" }}>{e.domain}</td>
                  <td>
                    <span style={{ background: "var(--border)", padding: "2px 6px", borderRadius: 4, fontSize: 11 }}>{e.queryType}</span>
                  </td>
                  <td style={{ fontWeight: 700, color: (e.riskScore || 0) >= 80 ? "var(--rose)" : (e.riskScore || 0) >= 50 ? "var(--amber)" : "var(--teal)" }}>
                    {e.riskScore}%
                  </td>
                  <td>
                    <span
                      style={{
                        padding: "3px 8px",
                        borderRadius: 4,
                        fontSize: 11,
                        fontWeight: 700,
                        textTransform: "uppercase",
                        background:
                          e.prediction === "suspicious" || e.severity === "critical"
                            ? "color-mix(in srgb, var(--rose) 15%, transparent)"
                            : "color-mix(in srgb, var(--teal) 15%, transparent)",
                        color:
                          e.prediction === "suspicious" || e.severity === "critical"
                            ? "var(--rose)"
                            : "var(--teal)",
                      }}
                    >
                      {e.severity || e.prediction}
                    </span>
                  </td>
                  <td style={{ color: "var(--muted)", fontSize: 12 }}>
                    {Array.isArray(e.reasons) && e.reasons.length > 0 ? e.reasons.join(", ") : "—"}
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
