import { useState, useEffect, useCallback } from "react";
import {
  Users, UserCheck, UserX, Clock, ShieldBan, RefreshCw, Check, X, Trash2, Loader2, Search, Crown, Eye,
  Inbox, Mail, CalendarDays, MessageSquare, Power, AlertTriangle,
} from "lucide-react";
import { api } from "../api/client";
import { card, PALETTE, tint, input } from "../ui";

const ROLE = {
  admin: { color: PALETTE.violet, icon: Crown, label: "Admin" },
  analyst: { color: PALETTE.blue, icon: Search, label: "Analyst" },
  viewer: { color: PALETTE.muted, icon: Eye, label: "Viewer" },
};
const STATUS = {
  pending: { color: PALETTE.amber, icon: Clock, label: "Pending" },
  active: { color: PALETTE.teal, icon: UserCheck, label: "Active" },
  rejected: { color: PALETTE.rose, icon: UserX, label: "Rejected" },
  disabled: { color: PALETTE.faint, icon: ShieldBan, label: "Disabled" },
};
const TABS = [
  { k: "pending", label: "Pending requests" },
  { k: "", label: "All users" },
  { k: "active", label: "Active" },
  { k: "disabled", label: "Disabled" },
  { k: "rejected", label: "Rejected" },
];

const btn = {
  display: "inline-flex", alignItems: "center", gap: 6, padding: "7px 12px", borderRadius: 10, fontSize: 12.5,
  fontWeight: 600, cursor: "pointer", border: "1px solid var(--border-strong)", background: tint("var(--ink)", 5), color: PALETTE.soft,
};
const colorBtn = (c, solid = false) => ({
  ...btn, color: solid ? "#fff" : c, background: solid ? c : tint(c, 8), border: solid ? "none" : `1px solid ${tint(c, 28)}`,
});

function Pill({ map, k }) {
  const m = map[k] || { color: PALETTE.muted, icon: Users, label: k };
  const I = m.icon;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: "3px 9px", borderRadius: 999, fontSize: 11.5, fontWeight: 600, color: m.color, background: tint(m.color, 10), border: `1px solid ${tint(m.color, 25)}`, whiteSpace: "nowrap" }}>
      <I size={12} /> {m.label}
    </span>
  );
}

function Avatar({ u, size = 38 }) {
  const c = (ROLE[u.role] || ROLE.viewer).color;
  const initials = (u.name || u.username).split(" ").map((s) => s[0]).join("").slice(0, 2).toUpperCase();
  return (
    <div style={{ width: size, height: size, borderRadius: size / 3.2, display: "grid", placeItems: "center", flexShrink: 0, fontSize: size / 3, fontWeight: 700, color: c, background: tint(c, 12), border: `1px solid ${tint(c, 28)}` }}>
      {initials}
    </div>
  );
}

function RoleSelect({ value, onChange, disabled }) {
  return (
    <select value={value} disabled={disabled} onChange={(e) => onChange(e.target.value)} style={{ ...input, fontSize: 12.5, height: 32, padding: "4px 10px" }}>
      <option value="viewer">Viewer</option>
      <option value="analyst">Analyst</option>
      <option value="admin">Admin</option>
    </select>
  );
}

// --------------------------------------------------------- pending request card
function RequestCard({ u, onApprove, onReject, busy }) {
  const [role, setRole] = useState(u.requested_role || "viewer");
  return (
    <div className="fade-up" style={{ ...card, padding: 18, display: "flex", flexDirection: "column", gap: 14, borderColor: tint(PALETTE.amber, 22) }}>
      <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
        <Avatar u={{ ...u, role }} size={44} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 600, fontSize: 15, color: PALETTE.text }}>{u.name}</div>
          <div className="mono" style={{ fontSize: 12, color: PALETTE.muted }}>@{u.username}</div>
        </div>
        <Pill map={STATUS} k={u.status} />
      </div>

      <div style={{ display: "grid", gap: 7, fontSize: 12.5, color: PALETTE.muted }}>
        {u.email && <div style={{ display: "flex", alignItems: "center", gap: 8 }}><Mail size={14} /> {u.email}</div>}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}><CalendarDays size={14} /> Requested <span className="mono">{u.created_at}</span></div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {(() => { const I = (ROLE[u.requested_role] || ROLE.viewer).icon; return <I size={14} />; })()}
          Asked for <b style={{ color: (ROLE[u.requested_role] || ROLE.viewer).color }}>{(ROLE[u.requested_role] || ROLE.viewer).label}</b>
        </div>
        {u.reason && (
          <div style={{ display: "flex", gap: 8, padding: 10, borderRadius: 10, background: "var(--surface-2)", border: "1px solid var(--border)", color: PALETTE.soft }}>
            <MessageSquare size={14} style={{ flexShrink: 0, marginTop: 2 }} /> {u.reason}
          </div>
        )}
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", paddingTop: 12, borderTop: "1px solid var(--border)" }}>
        <span style={{ fontSize: 12, color: PALETTE.faint }}>Grant role</span>
        <RoleSelect value={role} onChange={setRole} disabled={busy} />
        <div style={{ flex: 1 }} />
        <button style={colorBtn(PALETTE.rose)} disabled={busy} onClick={() => onReject(u)}><X size={14} /> Reject</button>
        <button style={colorBtn(PALETTE.teal, true)} disabled={busy} onClick={() => onApprove(u, role)}>
          {busy ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />} Approve
        </button>
      </div>
    </div>
  );
}

// --------------------------------------------------------- page
export default function UserManagement() {
  const me = (() => { try { return JSON.parse(localStorage.getItem("soc_user"))?.username; } catch { return null; } })();
  const [tab, setTab] = useState("pending");
  const [data, setData] = useState({ items: [], counts: {} });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState(null);
  const [q, setQ] = useState("");
  const [toast, setToast] = useState(null);
  const [confirm, setConfirm] = useState(null);

  const load = useCallback(async () => {
    try {
      setData(await api.getUsers(tab));
      setError("");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [tab]);

  useEffect(() => {
    setLoading(true);
    load();
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, [load]);

  const notify = (text, ok = true) => { setToast({ text, ok }); setTimeout(() => setToast(null), 3500); };

  const act = async (u, fn, okMsg) => {
    setBusyId(u.id);
    try {
      await fn();
      notify(okMsg);
      load();
      window.dispatchEvent(new CustomEvent("soc-users-changed"));
    } catch (e) {
      notify(e.message, false);
    } finally {
      setBusyId(null);
      setConfirm(null);
    }
  };

  const approve = (u, role) => act(u, () => api.approveUser(u.id, role), `${u.name} approved as ${ROLE[role].label}.`);
  const reject = (u) => setConfirm({
    title: `Reject ${u.name}?`, msg: "They won't be able to sign in. You can still approve them later from the Rejected tab.",
    color: PALETTE.rose, label: "Reject", run: () => act(u, () => api.rejectUser(u.id), `${u.name}'s request was rejected.`),
  });
  const changeRole = (u, role) => act(u, () => api.updateUser(u.id, { role }), `${u.name} is now ${ROLE[role].label}.`);
  const toggleDisabled = (u) => {
    const disabling = u.status === "active";
    setConfirm({
      title: `${disabling ? "Disable" : "Re-enable"} ${u.name}?`,
      msg: disabling ? "Their current session ends immediately and they can't sign in until re-enabled." : "They will be able to sign in again.",
      color: disabling ? PALETTE.amber : PALETTE.teal, label: disabling ? "Disable" : "Enable",
      run: () => act(u, () => api.updateUser(u.id, { status: disabling ? "disabled" : "active" }), `${u.name} ${disabling ? "disabled" : "re-enabled"}.`),
    });
  };
  const remove = (u) => setConfirm({
    title: `Delete ${u.name}'s account?`, msg: "The account is permanently removed. Their past actions stay in the Audit Log.",
    color: PALETTE.rose, label: "Delete", run: () => act(u, () => api.deleteUser(u.id), `${u.name}'s account was deleted.`),
  });

  const c = data.counts || {};
  const items = data.items.filter((u) => !q || `${u.name} ${u.username} ${u.email || ""}`.toLowerCase().includes(q.toLowerCase()));

  return (
    <div style={{ color: PALETTE.text }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", flexWrap: "wrap", gap: 16, marginBottom: 22 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 24, fontWeight: 700, display: "flex", alignItems: "center", gap: 10 }}>
            <Users size={22} color={PALETTE.teal} /> User Management
          </h1>
          <p style={{ margin: "6px 0 0", color: PALETTE.muted, fontSize: 13.5 }}>Review access requests, assign roles and manage accounts.</p>
        </div>
        <button style={btn} onClick={load}><RefreshCw size={14} /> Refresh</button>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 14, marginBottom: 18 }}>
        {["pending", "active", "disabled", "rejected"].map((k) => {
          const s = STATUS[k];
          return (
            <button key={k} onClick={() => setTab(k)} style={{ ...card, padding: 16, display: "flex", alignItems: "center", gap: 14, cursor: "pointer", textAlign: "left", color: "inherit", borderColor: tab === k ? tint(s.color, 40) : undefined }}>
              <div style={{ width: 40, height: 40, borderRadius: 12, display: "grid", placeItems: "center", background: tint(s.color, 10), border: `1px solid ${tint(s.color, 24)}` }}>
                <s.icon size={19} color={s.color} />
              </div>
              <div>
                <div style={{ fontSize: 22, fontWeight: 700 }}>{c[k] || 0}</div>
                <div style={{ fontSize: 12.5, color: PALETTE.muted }}>{s.label}</div>
              </div>
            </button>
          );
        })}
      </div>

      {/* Tabs + search */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12, marginBottom: 16 }}>
        <div style={{ display: "flex", gap: 4, padding: 4, borderRadius: 12, background: "var(--surface)", border: "1px solid var(--border)" }}>
          {TABS.map((t) => (
            <button
              key={t.k || "all"}
              onClick={() => setTab(t.k)}
              style={{
                display: "flex", alignItems: "center", gap: 6, padding: "7px 14px", borderRadius: 9, border: "none", cursor: "pointer", fontSize: 13, fontWeight: 500,
                color: tab === t.k ? PALETTE.text : PALETTE.muted, background: tab === t.k ? tint(PALETTE.teal, 12) : "transparent",
              }}
            >
              {t.label}
              {t.k === "pending" && c.pending > 0 && (
                <span style={{ minWidth: 18, height: 18, padding: "0 5px", borderRadius: 9, fontSize: 11, fontWeight: 700, display: "grid", placeItems: "center", color: "#fff", background: PALETTE.amber }}>{c.pending}</span>
              )}
            </button>
          ))}
        </div>
        <div style={{ position: "relative" }}>
          <Search size={15} color="var(--faint)" style={{ position: "absolute", left: 11, top: "50%", transform: "translateY(-50%)" }} />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search users…" style={{ ...input, paddingLeft: 34, fontSize: 13, height: 36, width: 240 }} />
        </div>
      </div>

      {error ? (
        <div style={{ ...card, color: PALETTE.rose, textAlign: "center" }}>{error}</div>
      ) : loading ? (
        <div style={{ ...card, display: "flex", justifyContent: "center", gap: 8, color: PALETTE.muted }}><Loader2 size={16} className="animate-spin" /> Loading users…</div>
      ) : items.length === 0 ? (
        <div style={{ ...card, padding: 44, display: "flex", flexDirection: "column", alignItems: "center", gap: 10, color: PALETTE.faint, fontSize: 13.5 }}>
          <Inbox size={28} />
          {tab === "pending" ? "No pending requests — you're all caught up." : "No users found."}
        </div>
      ) : tab === "pending" ? (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))", gap: 14 }}>
          {items.map((u) => <RequestCard key={u.id} u={u} busy={busyId === u.id} onApprove={approve} onReject={reject} />)}
        </div>
      ) : (
        <div style={{ ...card, padding: 0, overflow: "hidden" }}>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", fontSize: 13 }}>
              <thead>
                <tr style={{ background: "var(--surface-2)" }}>
                  {["User", "Role", "Status", "Joined", "Last sign-in", "Reviewed by", ""].map((h) => (
                    <th key={h} style={{ padding: "12px 14px", textAlign: "left", color: PALETTE.muted, borderBottom: "1px solid var(--border)", whiteSpace: "nowrap" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.map((u) => {
                  const self = u.username === me;
                  const busy = busyId === u.id;
                  return (
                    <tr key={u.id} style={{ borderBottom: "1px solid var(--border-soft)" }}>
                      <td style={{ padding: "11px 14px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 11 }}>
                          <Avatar u={u} size={34} />
                          <div style={{ lineHeight: 1.3 }}>
                            <div style={{ fontWeight: 600 }}>{u.name} {self && <span style={{ fontSize: 11, color: PALETTE.teal, fontWeight: 500 }}>(you)</span>}</div>
                            <div className="mono" style={{ fontSize: 11.5, color: PALETTE.faint }}>@{u.username}{u.email ? ` · ${u.email}` : ""}</div>
                          </div>
                        </div>
                      </td>
                      <td style={{ padding: "11px 14px" }}>
                        {u.status === "active" || u.status === "disabled" ? (
                          <RoleSelect value={u.role} disabled={self || busy} onChange={(r) => changeRole(u, r)} />
                        ) : (
                          <Pill map={ROLE} k={u.requested_role || u.role} />
                        )}
                      </td>
                      <td style={{ padding: "11px 14px" }}><Pill map={STATUS} k={u.status} /></td>
                      <td className="mono" style={{ padding: "11px 14px", fontSize: 12, color: PALETTE.muted, whiteSpace: "nowrap" }}>{u.created_at?.slice(0, 16)}</td>
                      <td className="mono" style={{ padding: "11px 14px", fontSize: 12, color: PALETTE.muted, whiteSpace: "nowrap" }}>{u.last_login?.slice(0, 16) || "—"}</td>
                      <td style={{ padding: "11px 14px", fontSize: 12.5, color: PALETTE.muted }}>{u.reviewed_by || "—"}</td>
                      <td style={{ padding: "11px 14px", whiteSpace: "nowrap", textAlign: "right" }}>
                        {busy ? <Loader2 size={16} className="animate-spin" color={PALETTE.muted} /> : (
                          <div style={{ display: "inline-flex", gap: 6 }}>
                            {(u.status === "pending" || u.status === "rejected") && (
                              <button style={colorBtn(PALETTE.teal)} onClick={() => approve(u, u.requested_role || "viewer")}><Check size={14} /> Approve</button>
                            )}
                            {u.status === "pending" && <button style={colorBtn(PALETTE.rose)} onClick={() => reject(u)}><X size={14} /></button>}
                            {(u.status === "active" || u.status === "disabled") && !self && (
                              <button style={colorBtn(u.status === "active" ? PALETTE.amber : PALETTE.teal)} onClick={() => toggleDisabled(u)} title={u.status === "active" ? "Disable" : "Enable"}>
                                <Power size={14} /> {u.status === "active" ? "Disable" : "Enable"}
                              </button>
                            )}
                            {!self && <button style={colorBtn(PALETTE.rose)} onClick={() => remove(u)} title="Delete account"><Trash2 size={14} /></button>}
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Confirm dialog */}
      {confirm && (
        <div style={{ position: "fixed", inset: 0, zIndex: 60, display: "grid", placeItems: "center", background: "rgba(0,0,0,0.45)" }} onClick={() => setConfirm(null)}>
          <div className="fade-up" onClick={(e) => e.stopPropagation()} style={{ ...card, background: "var(--surface-strong)", width: 420, maxWidth: "92vw", padding: 24 }}>
            <div style={{ display: "flex", gap: 12 }}>
              <div style={{ width: 40, height: 40, borderRadius: 12, display: "grid", placeItems: "center", flexShrink: 0, background: tint(confirm.color, 12) }}>
                <AlertTriangle size={20} color={confirm.color} />
              </div>
              <div>
                <h3 style={{ margin: 0, fontSize: 16 }}>{confirm.title}</h3>
                <p style={{ margin: "6px 0 0", fontSize: 13.5, color: PALETTE.muted, lineHeight: 1.6 }}>{confirm.msg}</p>
              </div>
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 22 }}>
              <button style={btn} onClick={() => setConfirm(null)}>Cancel</button>
              <button style={colorBtn(confirm.color, true)} onClick={confirm.run}>{confirm.label}</button>
            </div>
          </div>
        </div>
      )}

      {toast && (
        <div className="fade-up" style={{ position: "fixed", bottom: 24, right: 24, zIndex: 70, ...card, background: "var(--surface-strong)", padding: "12px 16px", fontSize: 13, display: "flex", alignItems: "center", gap: 8, color: toast.ok ? PALETTE.text : PALETTE.rose }}>
          {toast.ok ? <Check size={16} color={PALETTE.teal} /> : <AlertTriangle size={16} />} {toast.text}
        </div>
      )}
    </div>
  );
}
