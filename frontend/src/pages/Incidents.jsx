import { useState } from "react"
import { incidents as initial } from "../mocks/incidents"
import { card, th, td, input, COLORS } from "../ui"

const STATUSES = ["open", "investigating", "contained", "resolved", "false_positive"]

export default function Incidents() {
  const [list, setList] = useState(initial)
  const [selected, setSelected] = useState(null)

  const changeStatus = (id, status) =>
    setList(list.map((i) => (i.id === id ? { ...i, status } : i)))

  const current = list.find((i) => i.id === selected)

  return (
    <div style={{ color: "var(--text)" }}>
      <h1 style={{ marginBottom: 24 }}>Incidents</h1>

      <div style={{ ...card, overflowX: "auto", marginBottom: 16 }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={th}>ID</th>
              <th style={th}>Threat</th>
              <th style={th}>Device</th>
              <th style={th}>Risk</th>
              <th style={th}>Severity</th>
              <th style={th}>Status</th>
              <th style={th}></th>
            </tr>
          </thead>
          <tbody>
            {list.map((i) => (
              <tr key={i.id} style={{ borderTop: "1px solid var(--border)" }}>
                <td style={td}>{i.id}</td>
                <td style={td}>{i.threat}</td>
                <td style={td}>{i.device}</td>
                <td style={{ ...td, color: COLORS[i.severity], fontWeight: 700 }}>{i.riskScore}</td>
                <td style={{ ...td, color: COLORS[i.severity], textTransform: "capitalize" }}>{i.severity}</td>
                <td style={td}>
                  <select style={input} value={i.status} onChange={(e) => changeStatus(i.id, e.target.value)}>
                    {STATUSES.map((s) => (
                      <option key={s} value={s}>{s.replace("_", " ")}</option>
                    ))}
                  </select>
                </td>
                <td style={td}>
                  <button style={{ ...input, cursor: "pointer" }} onClick={() => setSelected(i.id)}>Details</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {current && (
        <div style={card}>
          <h3 style={{ marginTop: 0 }}>Incident {current.id}</h3>
          <p>Threat: {current.threat}</p>
          <p>Device: {current.device}</p>
          <p>Domain: <span style={{ color: "var(--blue)" }}>{current.domain}</span></p>
          <p>Detected: {current.detectedAt?.replace("T", " ")}</p>
          <p>Status: {current.status.replace("_", " ")}</p>
          <p>Reasons:</p>
          <ul>{current.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
        </div>
      )}
    </div>
  )
}
