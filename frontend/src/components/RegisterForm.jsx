import { useState } from "react";
import { User, Lock, Mail, IdCard, Eye, EyeOff, Search, ArrowLeft, Loader2, UserPlus, AlertCircle, Clock, CheckCircle2, Check } from "lucide-react";
import { api } from "../api/client";

const ROLE_OPTIONS = [
  { v: "viewer", label: "Viewer", desc: "Read-only dashboards", icon: Eye },
  { v: "analyst", label: "Analyst", desc: "Investigate & respond", icon: Search },
];

function Field({ icon: Icon, label, hint, children }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <label style={{ fontSize: 12.5, color: "var(--text-soft)", fontWeight: 500 }}>{label}</label>
      <div style={{ position: "relative", marginTop: 6 }}>
        <Icon size={16} color="var(--faint)" style={{ position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)" }} />
        {children}
      </div>
      {hint && <div style={{ fontSize: 11.5, color: "var(--faint)", marginTop: 5 }}>{hint}</div>}
    </div>
  );
}

function strength(pw) {
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[A-Za-z]/.test(pw) && /\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  return Math.min(4, s);
}
const STRENGTH = [
  { t: "Too weak", c: "var(--rose)" },
  { t: "Weak", c: "var(--rose)" },
  { t: "Fair", c: "var(--amber)" },
  { t: "Good", c: "var(--teal)" },
  { t: "Strong", c: "var(--teal)" },
];

export default function RegisterForm({ formStyle, onBack }) {
  const [f, setF] = useState({ name: "", username: "", email: "", password: "", confirm: "", requested_role: "viewer", reason: "" });
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(null);

  const set = (k) => (e) => setF((s) => ({ ...s, [k]: k === "username" ? e.target.value.toLowerCase().replace(/\s/g, "") : e.target.value }));
  const st = strength(f.password);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    if (!f.name.trim() || !f.username.trim() || !f.password) return setError("Please fill in your name, username and password.");
    if (!/^[a-z0-9][a-z0-9_.-]{2,31}$/.test(f.username)) return setError("Username: 3–32 chars, lowercase letters, numbers, . _ -");
    if (f.password.length < 8 || !/[A-Za-z]/.test(f.password) || !/\d/.test(f.password)) return setError("Password needs at least 8 characters with letters and numbers.");
    if (f.password !== f.confirm) return setError("Passwords do not match.");
    setLoading(true);
    try {
      const { confirm, ...payload } = f;
      await api.register({ ...payload, email: payload.email.trim() || null });
      setDone(f.username);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (done) {
    return (
      <div className="fade-up" style={{ ...formStyle, textAlign: "center" }}>
        <div
          style={{
            width: 64, height: 64, borderRadius: 20, margin: "4px auto 18px", display: "grid", placeItems: "center",
            background: "color-mix(in srgb, var(--amber) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--amber) 30%, transparent)",
          }}
        >
          <Clock size={30} color="var(--amber)" />
        </div>
        <h2 style={{ fontSize: 22, fontWeight: 700, margin: "0 0 8px" }}>Request submitted</h2>
        <p style={{ color: "var(--muted)", fontSize: 14, lineHeight: 1.7, margin: "0 0 22px" }}>
          Your account <b className="mono" style={{ color: "var(--text)" }}>{done}</b> was created and is now
          <b style={{ color: "var(--amber)" }}> awaiting administrator approval</b>. You'll be able to sign in as soon as it's activated.
        </p>
        <div style={{ textAlign: "left", padding: 14, borderRadius: 12, background: "var(--surface-2)", border: "1px solid var(--border)", marginBottom: 22, fontSize: 13 }}>
          {[
            [CheckCircle2, "var(--teal)", "Account created"],
            [Clock, "var(--amber)", "Administrator review"],
            [Check, "var(--faint)", "Access granted"],
          ].map(([I, c, t], i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "5px 0", color: i === 2 ? "var(--faint)" : "var(--text-soft)" }}>
              <I size={16} color={c} /> {t}
            </div>
          ))}
        </div>
        <button type="button" className="btn-primary" onClick={() => onBack(done)}>
          <ArrowLeft size={17} /> Back to sign in
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="fade-up" style={formStyle}>
      <button
        type="button"
        onClick={() => onBack()}
        style={{ display: "inline-flex", alignItems: "center", gap: 6, background: "none", border: "none", color: "var(--muted)", cursor: "pointer", fontSize: 13, padding: 0, marginBottom: 14 }}
      >
        <ArrowLeft size={15} /> Back to sign in
      </button>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
        <UserPlus size={18} color="var(--teal)" />
        <span className="mono" style={{ fontSize: 11, letterSpacing: "0.16em", color: "var(--teal)" }}>REQUEST ACCESS</span>
      </div>
      <h2 style={{ fontSize: 22, fontWeight: 700, margin: "0 0 4px", letterSpacing: "-0.02em" }}>Create an account</h2>
      <p style={{ color: "var(--muted)", fontSize: 13, margin: "0 0 20px" }}>An administrator reviews every new account before it's activated.</p>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <Field icon={IdCard} label="Full name">
          <input className="login-input" placeholder="Sara Ahmed" value={f.name} onChange={set("name")} maxLength={64} autoComplete="name" />
        </Field>
        <Field icon={User} label="Username">
          <input className="login-input" placeholder="sara.ahmed" value={f.username} onChange={set("username")} maxLength={32} autoComplete="username" />
        </Field>
      </div>

      <Field icon={Mail} label="Email (optional)">
        <input className="login-input" type="email" placeholder="sara@company.com" value={f.email} onChange={set("email")} maxLength={190} autoComplete="email" />
      </Field>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <Field icon={Lock} label="Password">
          <input className="login-input" type={showPw ? "text" : "password"} placeholder="••••••••" value={f.password} onChange={set("password")} maxLength={128} autoComplete="new-password" style={{ paddingRight: 40 }} />
          <button type="button" onClick={() => setShowPw((s) => !s)} style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: "var(--faint)", cursor: "pointer", display: "flex", padding: 4 }}>
            {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        </Field>
        <Field icon={Lock} label="Confirm password">
          <input className="login-input" type={showPw ? "text" : "password"} placeholder="••••••••" value={f.confirm} onChange={set("confirm")} maxLength={128} autoComplete="new-password" />
        </Field>
      </div>

      {f.password && (
        <div style={{ margin: "-4px 0 14px" }}>
          <div style={{ display: "flex", gap: 4 }}>
            {[0, 1, 2, 3].map((i) => (
              <div key={i} style={{ flex: 1, height: 4, borderRadius: 4, background: i < st ? STRENGTH[st].c : "color-mix(in srgb, var(--ink) 12%, transparent)", transition: "background .3s" }} />
            ))}
          </div>
          <div style={{ fontSize: 11.5, color: STRENGTH[st].c, marginTop: 5 }}>{STRENGTH[st].t}</div>
        </div>
      )}

      <label style={{ fontSize: 12.5, color: "var(--text-soft)", fontWeight: 500 }}>Requested role</label>
      <div style={{ display: "flex", gap: 8, margin: "6px 0 14px" }}>
        {ROLE_OPTIONS.map(({ v, label, desc, icon: Icon }) => (
          <button key={v} type="button" className={"chip-btn" + (f.requested_role === v ? " selected" : "")} onClick={() => setF((s) => ({ ...s, requested_role: v }))} style={{ flexDirection: "row", justifyContent: "flex-start", gap: 10, padding: "10px 12px", textAlign: "left" }}>
            <Icon size={17} />
            <span>
              <span style={{ display: "block", fontWeight: 600, fontSize: 13 }}>{label}</span>
              <span style={{ display: "block", fontSize: 11, color: "var(--faint)" }}>{desc}</span>
            </span>
          </button>
        ))}
      </div>

      <label style={{ fontSize: 12.5, color: "var(--text-soft)", fontWeight: 500 }}>Reason for access (optional)</label>
      <textarea
        className="login-input"
        value={f.reason}
        onChange={set("reason")}
        maxLength={300}
        rows={2}
        placeholder="e.g. SOC team member, network monitoring"
        style={{ padding: "10px 14px", marginTop: 6, marginBottom: 16, resize: "none" }}
      />

      {error && (
        <div className="fade-up" style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--rose)", background: "color-mix(in srgb, var(--rose) 8%, transparent)", border: "1px solid color-mix(in srgb, var(--rose) 25%, transparent)", borderRadius: 10, padding: "10px 12px", fontSize: 13, marginBottom: 14 }}>
          <AlertCircle size={16} style={{ flexShrink: 0 }} /> {error}
        </div>
      )}

      <button type="submit" className="btn-primary" disabled={loading}>
        {loading ? <><Loader2 className="animate-spin" size={18} /> Submitting…</> : <><UserPlus size={17} /> Submit request</>}
      </button>
    </form>
  );
}
