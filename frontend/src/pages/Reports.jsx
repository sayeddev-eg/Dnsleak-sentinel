import { alerts } from "../mocks/alerts"
import { incidents } from "../mocks/incidents"
import { devices } from "../mocks/devices"
import { dnsEvents } from "../mocks/dnsEvents"
import { card } from "../ui"
import { api } from "../api/client"

function download(name, rows) {
  const csv = [Object.keys(rows[0]).join(","), ...rows.map((r) => Object.values(r).map((v) => `"${v}"`).join(","))].join("\n")
  const a = document.createElement("a")
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }))
  a.download = `${name}.csv`
  a.click()
  api.logEvent("report.download", `${name}.csv`, { records: rows.length, format: "csv" })
}

const reports = [
  { name: "alerts", title: "Alerts Report", data: alerts.map((a) => ({ ...a, reasons: a.reasons.join("; ") })) },
  { name: "incidents", title: "Incidents Report", data: incidents.map((i) => ({ ...i, reasons: i.reasons.join("; ") })) },
  { name: "devices", title: "Devices Report", data: devices },
  { name: "dns-activity", title: "DNS Activity Report", data: dnsEvents.map((e) => ({ ...e, reasons: e.reasons.join("; ") })) },
]

export default function Reports() {
  return (
    <div style={{ color: "var(--text)" }}>
      <h1 style={{ marginBottom: 24 }}>Reports</h1>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {reports.map((r) => (
          <div key={r.name} style={card}>
            <h3 style={{ marginTop: 0 }}>{r.title}</h3>
            <p style={{ color: "var(--muted)" }}>{r.data.length} records</p>
            <button
              onClick={() => download(r.name, r.data)}
              style={{ background: "var(--rose)", color: "var(--text)", border: "none", borderRadius: 8, padding: "10px 16px", cursor: "pointer" }}
            >
              Download CSV
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}
