import { useState, useEffect, useCallback } from "react";
import {
  History, RefreshCw, Search, Trash2, Eye, X, ChevronLeft, ChevronRight, FileDown, KeyRound, FileUp,
  Zap, Database, Download, Compass, ShieldAlert, Activity, CalendarDays, CheckCircle2, XCircle, Loader2,
  Users, UserX, Inbox, FilterX, AlertTriangle,
} from "lucide-react";
import { api } from "../api/client";
import { card, PALETTE, tint, input } from "../ui";

// ------------------------------------------------------------------ presentation maps
const CATEGORY = {
  auth: { color: PALETTE.blue, icon: KeyRound, label: "Auth" },
  upload: { color: PALETTE.violet, icon: FileUp, label: "Upload" },
  analysis: { color: PALETTE.cyan, icon: Search, label: "Analysis" },
  simulation: { color: PALETTE.amber, icon: Zap, label: "Simulation" },
  data: { color: PALETTE.rose, icon: Database, label: "Data" },
  export: { color: PALETTE.teal, icon: Download, label: "Export" },
  navigation: { color: PALETTE.muted, icon: Compass, label: "Navigation" },
  admin: { color: PALETTE.rose, icon: ShieldAlert, label: "Admin" },
};

const ACTION_LABEL = {
  "auth.login": "Signed in",
  "auth.logout": "Signed out",
  "pcap.upload": "Uploaded PCAP file",
  "analyze.domain": "Analyzed domain",
  "analyze.features": "Feature-based analysis",
  "simulate.attack": "Simulated attack query",
  "simulate.normal": "Simulated normal query",
  "traffic.replay": "Replayed baseline traffic",
  "alerts.clear": "Cleared all DNS records",
  "alerts.export": "Exported alerts",
  "report.download": "Downloaded report",
  "audit.export": "Exported audit log",
  "page.view": "Viewed page",
  "audit.delete": "Deleted audit entries",
  "audit.purge": "Purged audit log",
  "auth.register": "Requested an account",
  "user.approve": "Approved account",
  "user.reject": "Rejected account request",
  "user.update": "Changed user role / status",
  "user.delete": "Deleted user account",
};

const ROLE_COLOR = { admin: PALETTE.violet, analyst: PALETTE.blue, viewer: PALETTE.muted, guest: PALETTE.faint };

const STATUS = {
  success: { color: PALETTE.teal, icon: CheckCircle2 },
  failed: { color: PALETTE.rose, icon: XCircle },
  running: { color: PALETTE.blue, icon: Loader2 },
};

const PAGE_SIZE = 25;

const fmtBytes = (n) => {
  if (n == null || isNaN(n)) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
};

const label = (e) =>
  e.action === "auth.login" && e.status === "failed" ? "Failed sign-in attempt" : ACTION_LABEL[e.action] || e.action;

function summary(e) {
  const d = e.details || {};
  if (e.action === "pcap.upload") {
    if (d.total_dns_queries != null)
      return `${fmtBytes(d.size_bytes)} · ${d.total_dns_queries} queries · ${d.critical || 0} critical`;
    return d.reason || d.error || d.state || fmtBytes(d.size_bytes);
  }
  if (e.action.startsWith("simulate.") || e.action.startsWith("analyze."))
    return `${d.level || ""}${d.risk != null ? ` · risk ${Math.round(d.risk * 100)}%` : ""}`;
  if (e.action === "alerts.clear") return `${d.records_deleted ?? 0} records deleted`;
  if (e.action === "traffic.replay") return d.records_replayed != null ? `${d.records_replayed} records` : d.state || "";
  if (e.action.startsWith("audit.")) return `${d.audit_deleted ?? 0} entries${d.queries_deleted ? ` + ${d.queries_deleted} DNS records` : ""}`;
  if (d.records != null) return `${d.records} records · ${d.format || ""}`;
  if (d.reason) return d.reason;
  return "";
}

// ------------------------------------------------------------------ small components
function Avatar({ name, role }) {
  const c = ROLE_COLOR[role] || PALETTE.muted;
  return (
    <div
      style={{
        width: 28, height: 28, borderRadius: 8, display: "grid", placeItems: "center", flexShrink: 0,
        fontSize: 11, fontWeight: 700, color: c, background: tint(c, 12), border: `1px solid ${tint(c, 28)}`,
      }}
    >
      {(name || "?").slice(0, 2).toUpperCase()}
    </div>
  );
}

function CategoryBadge({ category }) {
  const c = CATEGORY[category] || { color: PALETTE.muted, icon: Activity, label: category };
  const Icon = c.icon;
  return (
    <span
      style={{
        display: "inline-flex", alignItems: "center", gap: 5, padding: "3px 8px", borderRadius: 999, fontSize: 11,
        fontWeight: 600, color: c.color, background: tint(c.color, 10), border: `1px solid ${tint(c.color, 24)}`,
        whiteSpace: "nowrap",
      }}
    >
      <Icon size={12} /> {c.label}
    </span>
  );
}

function StatusChip({ status }) {
  const s = STATUS[status] || STATUS.success;
  const Icon = s.icon;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 12, color: s.color, textTransform: "capitalize" }}>
      <Icon size={13} className={status === "running" ? "animate-spin" : ""} /> {status}
    </span>
  );
}

function Stat({ icon: Icon, label: l, value, color }) {
  return (
    <div style={{ ...card, padding: 16, display: "flex", alignItems: "center", gap: 14 }}>
      <div style={{ width: 40, height: 40, borderRadius: 12, display: "grid", placeItems: "center", background: tint(color, 10), border: `1px solid ${tint(color, 24)}` }}>
        <Icon size={19} color={color} />
      </div>
      <div>
        <div style={{ fontSize: 22, fontWeight: 700, color: PALETTE.text }}>{Number(value || 0).toLocaleString()}</div>
        <div style={{ fontSize: 12.5, color: PALETTE.muted }}>{l}</div>
      </div>
    </div>
  );
}

const btn = {
  display: "inline-flex", alignItems: "center", gap: 7, padding: "8px 13px", borderRadius: 10, fontSize: 13,
  fontWeight: 600, cursor: "pointer", border: "1px solid var(--border-strong)", background: tint("var(--ink)", 5),
  color: PALETTE.soft,
};
const dangerBtn = { ...btn, color: PALETTE.rose, background: tint(PALETTE.rose, 7), border: `1px solid ${tint(PALETTE.rose, 28)}` };
const iconBtn = { background: "none", border: "1px solid transparent", borderRadius: 8, padding: 6, cursor: "pointer", display: "inline-flex", color: PALETTE.muted };
const field = { ...input, fontSize: 13, height: 36 };

// ------------------------------------------------------------------ confirm dialog
function ConfirmDialog({ open, title, message, showCascade, onCancel, onConfirm, busy }) {
  const [cascade, setCascade] = useState(false);
  useEffect(() => { if (open) setCascade(false); }, [open]);
  if (!open) return null;
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 60, display: "grid", placeItems: "center", background: "rgba(0,0,0,0.45)" }} onClick={onCancel}>
      <div className="fade-up" onClick={(e) => e.stopPropagation()} style={{ ...card, background: "var(--surface-strong)", width: 440, maxWidth: "92vw", padding: 24 }}>
        <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
          <div style={{ width: 40, height: 40, borderRadius: 12, display: "grid", placeItems: "center", flexShrink: 0, background: tint(PALETTE.rose, 12) }}>
            <AlertTriangle size={20} color={PALETTE.rose} />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, color: PALETTE.text }}>{title}</h3>
            <p style={{ margin: "6px 0 0", fontSize: 13.5, color: PALETTE.muted, lineHeight: 1.6 }}>{message}</p>
          </div>
        </div>
        {showCascade && (
          <label style={{ display: "flex", gap: 10, alignItems: "flex-start", marginTop: 18, padding: 12, borderRadius: 10, background: "var(--surface-2)", border: "1px solid var(--border)", cursor: "pointer", fontSize: 13, color: PALETTE.soft }}>
            <input type="checkbox" checked={cascade} onChange={(e) => setCascade(e.target.checked)} style={{ marginTop: 2, accentColor: "var(--rose)" }} />
            <span>
              Also delete the DNS records produced by these actions
              <span style={{ display: "block", color: PALETTE.faint, fontSize: 12, marginTop: 2 }}>e.g. all queries extracted from an uploaded PCAP file</span>
            </span>
          </label>
        )}
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 22 }}>
          <button style={btn} onClick={onCancel} disabled={busy}>Cancel</button>
          <button style={{ ...dangerBtn, background: PALETTE.rose, color: "#fff", border: "none" }} onClick={() => onConfirm(cascade)} disabled={busy}>
            {busy ? <Loader2 size={15} className="animate-spin" /> : <Trash2 size={15} />} Delete
          </button>
        </div>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ detail drawer
function DetailDrawer({ id, onClose, onDelete }) {
  const [item, setItem] = useState(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!id) return;
    setItem(null);
    setErr("");
    api.getAuditEntry(id).then(setItem).catch((e) => setErr(e.message));
  }, [id]);

  if (!id) return null;
  const d = item?.details || {};
  const levelColor = (l) => (l === "CRITICAL" ? PALETTE.rose : l === "SUSPICIOUS" ? PALETTE.amber : PALETTE.teal);

  const prettyVal = (k, v) => {
    if (k === "size_bytes") return fmtBytes(v);
    if (k === "risk") return `${Math.round(v * 100)}%`;
    if (typeof v === "object") return JSON.stringify(v);
    return String(v);
  };

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 50 }} onClick={onClose}>
      <div style={{ position: "absolute", inset: 0, background: "rgba(0,0,0,0.3)" }} />
      <aside
        onClick={(e) => e.stopPropagation()}
        style={{
          position: "absolute", top: 0, right: 0, bottom: 0, width: 520, maxWidth: "95vw", overflowY: "auto",
          background: "var(--surface-strong)", borderLeft: "1px solid var(--border-strong)",
          boxShadow: "var(--pop-shadow)", padding: 24, animation: "pageIn .3s ease both",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
          <div className="mono" style={{ fontSize: 12, color: PALETTE.faint }}>AUDIT ENTRY #{id}</div>
          <button style={iconBtn} onClick={onClose} title="Close"><X size={18} /></button>
        </div>

        {err && <div style={{ color: PALETTE.rose, fontSize: 13 }}>{err}</div>}
        {!item && !err && <div style={{ display: "flex", gap: 8, color: PALETTE.muted, fontSize: 13 }}><Loader2 size={16} className="animate-spin" /> Loading…</div>}

        {item && (
          <>
            <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 6 }}>
              <CategoryBadge category={item.category} />
              <StatusChip status={item.status} />
            </div>
            <h2 style={{ margin: "8px 0 4px", fontSize: 20, color: PALETTE.text }}>{label(item)}</h2>
            {item.target && <div className="mono" style={{ fontSize: 12.5, color: PALETTE.soft, wordBreak: "break-all" }}>{item.target}</div>}

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, margin: "20px 0" }}>
              {[
                ["User", <span key="u" style={{ display: "flex", alignItems: "center", gap: 8 }}><Avatar name={item.username} role={item.role} />{item.username}</span>],
                ["Role", <span key="r" style={{ color: ROLE_COLOR[item.role], textTransform: "capitalize" }}>{item.role}</span>],
                ["Date & time", <span key="t" className="mono">{item.timestamp}</span>],
                ["IP address", <span key="i" className="mono">{item.ip || "—"}</span>],
              ].map(([k, v]) => (
                <div key={k} style={{ padding: 12, borderRadius: 12, background: "var(--surface-2)", border: "1px solid var(--border)" }}>
                  <div style={{ fontSize: 11, color: PALETTE.faint, marginBottom: 6, textTransform: "uppercase", letterSpacing: ".06em" }}>{k}</div>
                  <div style={{ fontSize: 13, color: PALETTE.text }}>{v}</div>
                </div>
              ))}
            </div>

            {Object.keys(d).length > 0 && (
              <>
                <h4 style={{ fontSize: 13, color: PALETTE.muted, margin: "0 0 8px" }}>Details</h4>
                <div style={{ borderRadius: 12, border: "1px solid var(--border)", overflow: "hidden", marginBottom: 20 }}>
                  {Object.entries(d).map(([k, v]) => (
                    <div key={k} style={{ display: "flex", gap: 12, padding: "9px 12px", borderBottom: "1px solid var(--border-soft)", fontSize: 12.5 }}>
                      <span className="mono" style={{ width: 150, flexShrink: 0, color: PALETTE.faint }}>{k}</span>
                      <span className="mono" style={{ color: PALETTE.soft, wordBreak: "break-all" }}>{prettyVal(k, v)}</span>
                    </div>
                  ))}
                </div>
              </>
            )}

            {item.user_agent && (
              <div style={{ fontSize: 11.5, color: PALETTE.faint, marginBottom: 20, wordBreak: "break-all" }}>
                <b style={{ fontWeight: 600 }}>User agent:</b> {item.user_agent}
              </div>
            )}

            {item.linked_query_count > 0 && (
              <>
                <h4 style={{ fontSize: 13, color: PALETTE.muted, margin: "0 0 8px", display: "flex", justifyContent: "space-between" }}>
                  DNS records produced by this action
                  <span className="mono" style={{ color: PALETTE.faint }}>{item.linked_query_count}</span>
                </h4>
                <div style={{ maxHeight: 280, overflowY: "auto", borderRadius: 12, border: "1px solid var(--border)", marginBottom: 20 }}>
                  {item.linked_queries.map((q) => (
                    <div key={q.id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", borderBottom: "1px solid var(--border-soft)", fontSize: 12 }}>
                      <span style={{ width: 7, height: 7, borderRadius: 9, background: levelColor(q.level), flexShrink: 0 }} />
                      <span className="mono" style={{ flex: 1, color: PALETTE.soft, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={q.domain}>{q.domain}</span>
                      <span className="mono" style={{ color: PALETTE.faint }}>{q.src_ip}</span>
                      <span className="mono" style={{ color: levelColor(q.level), width: 44, textAlign: "right" }}>{q.risk}%</span>
                    </div>
                  ))}
                </div>
              </>
            )}

            <div style={{ display: "flex", gap: 10 }}>
              <button style={dangerBtn} onClick={() => onDelete([item.id], item.linked_query_count > 0)}>
                <Trash2 size={15} /> Delete entry
              </button>
            </div>
          </>
        )}
      </aside>
    </div>
  );
}

// ------------------------------------------------------------------ page
export default function AuditLog() {
  const [data, setData] = useState({ items: [], total: 0, stats: {} });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState(new Set());
  const [detailId, setDetailId] = useState(null);
  const [confirm, setConfirm] = useState(null); // {title, message, showCascade, run(cascade)}
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState("");
  const [filters, setFilters] = useState({ q: "", username: "", category: "", status: "", date_from: "", date_to: "", hide_nav: true });
  const [qInput, setQInput] = useState("");

  const activeFilters = { ...filters, hide_nav: filters.hide_nav ? "true" : "" };

  const load = useCallback(async () => {
    try {
      const res = await api.getAudit(activeFilters, PAGE_SIZE, page * PAGE_SIZE);
      setData(res);
      setError("");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(filters), page]);

  useEffect(() => {
    load();
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, [load]);

  // debounce search box
  useEffect(() => {
    const t = setTimeout(() => setFilters((f) => (f.q === qInput ? f : { ...f, q: qInput })), 350);
    return () => clearTimeout(t);
  }, [qInput]);

  useEffect(() => { setPage(0); setSelected(new Set()); }, [JSON.stringify(filters)]);

  const showToast = (m) => { setToast(m); setTimeout(() => setToast(""), 3500); };
  const setF = (k, v) => setFilters((f) => ({ ...f, [k]: v }));
  const hasFilters = filters.q || filters.username || filters.category || filters.status || filters.date_from || filters.date_to;

  const toggle = (id) => setSelected((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const allOnPage = data.items.length > 0 && data.items.every((i) => selected.has(i.id));
  const toggleAll = () => setSelected((s) => {
    const n = new Set(s);
    if (allOnPage) data.items.forEach((i) => n.delete(i.id)); else data.items.forEach((i) => n.add(i.id));
    return n;
  });

  const runDelete = async (fn) => {
    setBusy(true);
    try {
      const r = await fn();
      showToast(`Deleted ${r.audit_deleted} entr${r.audit_deleted === 1 ? "y" : "ies"}${r.queries_deleted ? ` and ${r.queries_deleted} DNS records` : ""}.`);
      setSelected(new Set());
      setDetailId(null);
      setConfirm(null);
      load();
    } catch (e) {
      showToast(`Error: ${e.message}`);
    } finally {
      setBusy(false);
    }
  };

  const askDeleteIds = (ids, showCascade = true) =>
    setConfirm({
      title: ids.length === 1 ? "Delete this audit entry?" : `Delete ${ids.length} audit entries?`,
      message: "This permanently removes the selected records from the audit log. This action is itself recorded.",
      showCascade,
      run: (cascade) => runDelete(() => api.deleteAudit(ids, cascade)),
    });

  const askPurge = () =>
    setConfirm({
      title: hasFilters ? `Delete all ${data.total} matching entries?` : "Purge the entire audit log?",
      message: hasFilters
        ? "Every entry matching the current filters will be permanently deleted."
        : "Every audit entry will be permanently deleted. Consider exporting a CSV first.",
      showCascade: true,
      run: (cascade) => runDelete(() => api.purgeAudit(activeFilters, cascade)),
    });

  const exportCsv = async () => {
    try {
      const res = await api.getAudit(activeFilters, 500, 0);
      const head = ["id", "timestamp", "username", "role", "category", "action", "target", "status", "ip", "details"];
      const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
      const rows = res.items.map((e) => [e.id, e.timestamp, e.username, e.role, e.category, e.action, e.target, e.status, e.ip, JSON.stringify(e.details)].map(esc).join(","));
      const blob = new Blob(["\uFEFF" + [head.join(","), ...rows].join("\n")], { type: "text/csv;charset=utf-8" });
      const a = document.createElement("a");
      const name = `audit_log_${new Date().toISOString().slice(0, 10)}.csv`;
      a.href = URL.createObjectURL(blob);
      a.download = name;
      a.click();
      api.logEvent("audit.export", name, { records: res.items.length, format: "csv" });
    } catch (e) {
      showToast(`Export failed: ${e.message}`);
    }
  };

  const s = data.stats || {};
  const from = data.total === 0 ? 0 : page * PAGE_SIZE + 1;
  const to = Math.min(data.total, (page + 1) * PAGE_SIZE);
  const pages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));

  return (
    <div style={{ color: PALETTE.text }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", flexWrap: "wrap", gap: 16, marginBottom: 22 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 24, fontWeight: 700, display: "flex", alignItems: "center", gap: 10 }}>
            <History size={22} color={PALETTE.teal} /> Audit Log
          </h1>
          <p style={{ margin: "6px 0 0", color: PALETTE.muted, fontSize: 13.5 }}>
            Every sign-in, file upload, analysis, simulation, export and deletion — with user, IP and timestamp.
          </p>
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button style={btn} onClick={load} title="Refresh"><RefreshCw size={15} /> Refresh</button>
          <button style={btn} onClick={exportCsv}><FileDown size={15} /> Export CSV</button>
          {selected.size > 0 && (
            <button style={dangerBtn} onClick={() => askDeleteIds([...selected])}>
              <Trash2 size={15} /> Delete selected ({selected.size})
            </button>
          )}
          <button style={dangerBtn} onClick={askPurge} disabled={data.total === 0}>
            <Trash2 size={15} /> {hasFilters ? "Delete filtered" : "Purge all"}
          </button>
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 14, marginBottom: 16 }}>
        <Stat icon={Activity} label="Total events" value={s.total} color={PALETTE.blue} />
        <Stat icon={CalendarDays} label="Events today" value={s.today} color={PALETTE.teal} />
        <Stat icon={FileUp} label="PCAP uploads" value={s.uploads} color={PALETTE.violet} />
        <Stat icon={UserX} label="Failed sign-ins" value={s.failed_logins} color={PALETTE.rose} />
      </div>

      {/* Filters */}
      <div style={{ ...card, padding: 14, marginBottom: 16, display: "flex", flexWrap: "wrap", gap: 10, alignItems: "center" }}>
        <div style={{ position: "relative", flex: "1 1 240px" }}>
          <Search size={15} color="var(--faint)" style={{ position: "absolute", left: 11, top: "50%", transform: "translateY(-50%)" }} />
          <input style={{ ...field, width: "100%", paddingLeft: 34 }} placeholder="Search file, domain, user, IP, action…" value={qInput} onChange={(e) => setQInput(e.target.value)} />
        </div>
        <select style={field} value={filters.username} onChange={(e) => setF("username", e.target.value)}>
          <option value="">All users</option>
          {(s.users || []).map((u) => <option key={u} value={u}>{u}</option>)}
        </select>
        <select style={field} value={filters.category} onChange={(e) => setF("category", e.target.value)}>
          <option value="">All categories</option>
          {Object.entries(CATEGORY).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>
        <select style={field} value={filters.status} onChange={(e) => setF("status", e.target.value)}>
          <option value="">Any result</option>
          <option value="success">Success</option>
          <option value="failed">Failed</option>
          <option value="running">Running</option>
        </select>
        <input type="date" style={field} value={filters.date_from} onChange={(e) => setF("date_from", e.target.value)} title="From date" />
        <span style={{ color: PALETTE.faint, fontSize: 12 }}>→</span>
        <input type="date" style={field} value={filters.date_to} onChange={(e) => setF("date_to", e.target.value)} title="To date" />
        <label style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 12.5, color: PALETTE.muted, cursor: "pointer", userSelect: "none" }}>
          <input type="checkbox" checked={filters.hide_nav} onChange={(e) => setF("hide_nav", e.target.checked)} style={{ accentColor: "var(--teal)" }} />
          Hide page views
        </label>
        {hasFilters && (
          <button style={{ ...btn, padding: "7px 10px" }} onClick={() => { setQInput(""); setFilters((f) => ({ ...f, q: "", username: "", category: "", status: "", date_from: "", date_to: "" })); }}>
            <FilterX size={14} /> Clear
          </button>
        )}
      </div>

      {/* Table */}
      <div style={{ ...card, padding: 0, overflow: "hidden" }}>
        {error ? (
          <div style={{ padding: 30, textAlign: "center", color: PALETTE.rose, fontSize: 13.5 }}>{error}</div>
        ) : loading ? (
          <div style={{ padding: 30, display: "flex", justifyContent: "center", gap: 8, color: PALETTE.muted }}><Loader2 size={16} className="animate-spin" /> Loading audit log…</div>
        ) : data.items.length === 0 ? (
          <div style={{ padding: 40, display: "flex", flexDirection: "column", alignItems: "center", gap: 8, color: PALETTE.faint, fontSize: 13.5 }}>
            <Inbox size={26} /> No audit entries {hasFilters ? "match these filters" : "yet"}.
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", fontSize: 13 }}>
              <thead>
                <tr style={{ background: "var(--surface-2)" }}>
                  <th style={{ padding: "12px 14px", width: 36, borderBottom: "1px solid var(--border)" }}>
                    <input type="checkbox" checked={allOnPage} onChange={toggleAll} style={{ accentColor: "var(--teal)" }} />
                  </th>
                  {["Time", "User", "Action", "Target", "Details", "Result", "IP", ""].map((h) => (
                    <th key={h} style={{ padding: "12px 10px", textAlign: "left", color: PALETTE.muted, borderBottom: "1px solid var(--border)", whiteSpace: "nowrap" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.items.map((e) => {
                  const [date, time] = String(e.timestamp).split(" ");
                  const isSel = selected.has(e.id);
                  return (
                    <tr key={e.id} style={{ borderBottom: "1px solid var(--border-soft)", background: isSel ? tint(PALETTE.teal, 6) : undefined, cursor: "pointer" }} onClick={() => setDetailId(e.id)}>
                      <td style={{ padding: "10px 14px" }} onClick={(ev) => ev.stopPropagation()}>
                        <input type="checkbox" checked={isSel} onChange={() => toggle(e.id)} style={{ accentColor: "var(--teal)" }} />
                      </td>
                      <td style={{ padding: "10px", whiteSpace: "nowrap" }}>
                        <div className="mono" style={{ color: PALETTE.soft, fontSize: 12.5 }}>{time}</div>
                        <div className="mono" style={{ color: PALETTE.faint, fontSize: 11 }}>{date}</div>
                      </td>
                      <td style={{ padding: "10px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
                          <Avatar name={e.username} role={e.role} />
                          <div style={{ lineHeight: 1.25 }}>
                            <div style={{ color: PALETTE.text, fontWeight: 500 }}>{e.username}</div>
                            <div style={{ fontSize: 11, color: ROLE_COLOR[e.role] || PALETTE.faint, textTransform: "capitalize" }}>{e.role}</div>
                          </div>
                        </div>
                      </td>
                      <td style={{ padding: "10px" }}>
                        <div style={{ display: "flex", flexDirection: "column", gap: 5, alignItems: "flex-start" }}>
                          <span style={{ color: PALETTE.text, fontWeight: 500, whiteSpace: "nowrap" }}>{label(e)}</span>
                          <CategoryBadge category={e.category} />
                        </div>
                      </td>
                      <td style={{ padding: "10px", maxWidth: 260 }}>
                        <div className="mono" style={{ color: PALETTE.soft, fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={e.target}>{e.target || "—"}</div>
                      </td>
                      <td style={{ padding: "10px", color: PALETTE.muted, fontSize: 12.5, maxWidth: 240 }}>
                        <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{summary(e) || "—"}</div>
                      </td>
                      <td style={{ padding: "10px" }}><StatusChip status={e.status} /></td>
                      <td className="mono" style={{ padding: "10px", color: PALETTE.faint, fontSize: 12 }}>{e.ip || "—"}</td>
                      <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }} onClick={(ev) => ev.stopPropagation()}>
                        <button style={iconBtn} title="View details" onClick={() => setDetailId(e.id)}><Eye size={16} /></button>
                        <button style={{ ...iconBtn, color: PALETTE.rose }} title="Delete" onClick={() => askDeleteIds([e.id], e.category === "upload" || e.category === "simulation" || e.category === "analysis")}><Trash2 size={16} /></button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {data.total > 0 && (
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", borderTop: "1px solid var(--border)", fontSize: 12.5, color: PALETTE.muted }}>
            <span>Showing <b style={{ color: PALETTE.text }}>{from}–{to}</b> of <b style={{ color: PALETTE.text }}>{data.total}</b></span>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <button style={{ ...btn, padding: 6 }} disabled={page === 0} onClick={() => setPage((p) => p - 1)}><ChevronLeft size={16} /></button>
              <span className="mono">{page + 1} / {pages}</span>
              <button style={{ ...btn, padding: 6 }} disabled={page + 1 >= pages} onClick={() => setPage((p) => p + 1)}><ChevronRight size={16} /></button>
            </div>
          </div>
        )}
      </div>

      <p style={{ marginTop: 12, fontSize: 12, color: PALETTE.faint, display: "flex", alignItems: "center", gap: 6 }}>
        <Users size={13} /> User identity is taken from the server-signed session token, not from the browser.
      </p>

      <DetailDrawer id={detailId} onClose={() => setDetailId(null)} onDelete={(ids, cascade) => askDeleteIds(ids, cascade)} />
      <ConfirmDialog
        open={!!confirm}
        title={confirm?.title}
        message={confirm?.message}
        showCascade={confirm?.showCascade}
        busy={busy}
        onCancel={() => !busy && setConfirm(null)}
        onConfirm={(cascade) => confirm?.run(cascade)}
      />

      {toast && (
        <div className="fade-up" style={{ position: "fixed", bottom: 24, right: 24, zIndex: 70, ...card, background: "var(--surface-strong)", padding: "12px 16px", fontSize: 13, color: PALETTE.text }}>
          {toast}
        </div>
      )}
    </div>
  );
}
