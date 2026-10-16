import { useState, useEffect } from "react";
import { ShieldHalf, Loader2, User, Lock, Eye, EyeOff, ShieldCheck, Search, Crown, ArrowRight, AlertCircle, Clock } from "lucide-react";
import { api } from "../api/client";
import CyberBackground from "../components/CyberBackground";
import ThemeToggle from "../components/ThemeToggle";
import RegisterForm from "../components/RegisterForm";

const TERMINAL = [
  { t: "$ sentinel --listen udp/53 --iface eth0", c: "#c0caf5" },
  { t: "[*] loading XGBoost model · 16 features", c: "#8b93b0" },
  { t: "[+] query  www.google.com           risk 03%", c: "#73daca" },
  { t: "[+] query  cdn.office365.com        risk 06%", c: "#73daca" },
  { t: "[!] query  mzxw6ytb.k3q.tunnel.io   entropy 4.71", c: "#e0af68" },
  { t: "[x] TXT    a9f3e1c07b.exfil.io      risk 97%", c: "#f7768e" },
  { t: "[✓] alert raised · host 192.168.1.52 isolated", c: "#7dcfff" },
];

const DEMO = [
  { u: "admin", p: "admin123", label: "Admin", icon: Crown },
  { u: "analyst", p: "analyst123", label: "Analyst", icon: Search },
  { u: "viewer", p: "viewer123", label: "Viewer", icon: Eye },
];

function Terminal() {
  const [lines, setLines] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setLines((n) => (n >= TERMINAL.length + 4 ? 0 : n + 1)), 900);
    return () => clearInterval(id);
  }, []);

  return (
    <div
      style={{
        borderRadius: 14,
        border: "1px solid var(--border-strong)",
        background: "var(--terminal-bg)",
        overflow: "hidden",
        boxShadow: "var(--pop-shadow)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "10px 14px", borderBottom: "1px solid var(--border)" }}>
        <span style={{ width: 10, height: 10, borderRadius: 99, background: "var(--rose)", opacity: 0.8 }} />
        <span style={{ width: 10, height: 10, borderRadius: 99, background: "var(--amber)", opacity: 0.8 }} />
        <span style={{ width: 10, height: 10, borderRadius: 99, background: "var(--teal)", opacity: 0.8 }} />
        <span className="mono" style={{ marginLeft: 10, fontSize: 11, color: "var(--faint)" }}>sentinel@soc: ~/dns-monitor</span>
      </div>
      <div className="mono" style={{ padding: "14px 16px", fontSize: 12, lineHeight: 1.85, minHeight: 236 }}>
        {TERMINAL.slice(0, Math.min(lines, TERMINAL.length)).map((l, i) => (
          <div key={i} className="fade-up" style={{ color: l.c, whiteSpace: "pre" }}>
            {l.t}
          </div>
        ))}
        <span className="caret" style={{ color: "var(--faint)" }} />
      </div>
    </div>
  );
}

const FORM_STYLE = {
  background: "var(--surface-strong)",
  border: "1px solid var(--border-strong)",
  borderRadius: 20,
  padding: "34px 32px",
  boxShadow: "var(--pop-shadow)",
  maxWidth: 460,
  width: "100%",
  justifySelf: "center",
};

export default function Login({ onLogin }) {
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError("Please enter both username and password");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const user = await api.login(username.trim(), password);
      if (!user) {
        setError("Invalid username or password");
        return;
      }
      localStorage.setItem("soc_user", JSON.stringify(user));
      onLogin(user);
    } catch (err) {
      setError(err.message || "Failed to connect to authentication server");
    } finally {
      setLoading(false);
    }
  };

  const setDemoUser = (u, p) => {
    setUsername(u);
    setPassword(p);
    setError("");
  };

  const isPending = /approval/i.test(error);

  return (
    <div style={{ minHeight: "100vh", position: "relative", display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
      <CyberBackground density={1.1} />

      <div style={{ position: "absolute", top: 20, right: 24, zIndex: 2 }}>
        <ThemeToggle />
      </div>

      <div
        className="fade-up"
        style={{
          position: "relative",
          zIndex: 1,
          width: "100%",
          maxWidth: 1080,
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))",
          gap: 48,
          alignItems: "center",
        }}
      >
        {/* Left: brand + terminal */}
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 28 }}>
            <div
              style={{
                width: 46,
                height: 46,
                borderRadius: 13,
                display: "grid",
                placeItems: "center",
                background: "linear-gradient(135deg, color-mix(in srgb, var(--teal) 18%, transparent), color-mix(in srgb, var(--blue) 18%, transparent))",
                border: "1px solid color-mix(in srgb, var(--teal) 30%, transparent)",
                boxShadow: "0 0 30px -6px color-mix(in srgb, var(--teal) 50%, transparent)",
              }}
            >
              <ShieldHalf size={24} color="var(--teal)" />
            </div>
            <div style={{ lineHeight: 1.15 }}>
              <div style={{ fontWeight: 700, fontSize: 18 }}>DNSLeak</div>
              <div className="mono" style={{ fontSize: 11, color: "var(--accent)", letterSpacing: "0.2em" }}>SENTINEL</div>
            </div>
          </div>

          <h1 style={{ fontSize: 38, lineHeight: 1.15, fontWeight: 700, margin: "0 0 14px", letterSpacing: "-0.03em" }}>
            Catch data leaving
            <br />
            through <span className="shimmer-text">DNS</span>.
          </h1>
          <p style={{ color: "var(--muted)", fontSize: 15, lineHeight: 1.7, margin: "0 0 28px", maxWidth: 440 }}>
            AI-driven detection of DNS tunneling and exfiltration — real-time traffic inspection, risk scoring and SOC alerting in one console.
          </p>

          <Terminal />

          <div className="mono" style={{ display: "flex", gap: 22, marginTop: 20, fontSize: 11.5, color: "var(--faint)" }}>
            <span><span style={{ color: "var(--accent)" }}>94.9%</span> accuracy</span>
            <span><span style={{ color: "var(--cyan)" }}>16</span> features</span>
            <span><span style={{ color: "var(--violet)" }}>MITRE</span> T1071.004</span>
          </div>
        </div>

        {/* Right: form */}
        {mode === "register" ? (
          <RegisterForm
            formStyle={FORM_STYLE}
            onBack={(newUsername) => {
              setMode("login");
              setError("");
              if (newUsername) {
                setUsername(newUsername);
                setPassword("");
              }
            }}
          />
        ) : (
        <form
          onSubmit={submit}
          className="fade-up"
          style={FORM_STYLE}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <ShieldCheck size={18} color="var(--teal)" />
            <span className="mono" style={{ fontSize: 11, letterSpacing: "0.16em", color: "var(--accent)" }}>SECURE ACCESS</span>
          </div>
          <h2 style={{ fontSize: 24, fontWeight: 700, margin: "0 0 6px", letterSpacing: "-0.02em" }}>Sign in to the console</h2>
          <p style={{ color: "var(--muted)", fontSize: 13.5, margin: "0 0 26px" }}>Role-based access for SOC operators.</p>

          <label style={{ fontSize: 12.5, color: "var(--text-soft)", fontWeight: 500 }}>Username</label>
          <div style={{ position: "relative", margin: "7px 0 16px" }}>
            <User size={17} color="var(--faint)" style={{ position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)" }} />
            <input
              className="login-input"
              placeholder="e.g. analyst"
              value={username}
              autoComplete="username"
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>

          <label style={{ fontSize: 12.5, color: "var(--text-soft)", fontWeight: 500 }}>Password</label>
          <div style={{ position: "relative", margin: "7px 0 18px" }}>
            <Lock size={17} color="var(--faint)" style={{ position: "absolute", left: 14, top: "50%", transform: "translateY(-50%)" }} />
            <input
              className="login-input"
              type={showPw ? "text" : "password"}
              placeholder="••••••••"
              value={password}
              autoComplete="current-password"
              onChange={(e) => setPassword(e.target.value)}
              style={{ paddingRight: 44 }}
            />
            <button
              type="button"
              onClick={() => setShowPw((s) => !s)}
              title={showPw ? "Hide password" : "Show password"}
              style={{ position: "absolute", right: 10, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: "var(--faint)", cursor: "pointer", padding: 4, display: "flex" }}
            >
              {showPw ? <EyeOff size={17} /> : <Eye size={17} />}
            </button>
          </div>

          {error && (
            <div
              className="fade-up"
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                color: isPending ? "var(--amber)" : "var(--rose)",
                background: isPending ? "color-mix(in srgb, var(--amber) 9%, transparent)" : "color-mix(in srgb, var(--rose) 8%, transparent)",
                border: isPending ? "1px solid color-mix(in srgb, var(--amber) 28%, transparent)" : "1px solid color-mix(in srgb, var(--rose) 25%, transparent)",
                borderRadius: 10,
                padding: "10px 12px",
                fontSize: 13,
                marginBottom: 16,
              }}
            >
              {isPending ? <Clock size={16} style={{ flexShrink: 0 }} /> : <AlertCircle size={16} style={{ flexShrink: 0 }} />} {error}
            </div>
          )}

          <button type="submit" className="btn-primary" disabled={loading}>
            {loading ? (
              <>
                <Loader2 className="animate-spin" size={18} /> Authenticating…
              </>
            ) : (
              <>
                Sign in <ArrowRight size={17} />
              </>
            )}
          </button>

          <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "26px 0 12px" }}>
            <div style={{ flex: 1, height: 1, background: "var(--border)" }} />
            <span className="mono" style={{ fontSize: 10.5, color: "var(--faint)", letterSpacing: "0.12em" }}>DEMO ACCOUNTS</span>
            <div style={{ flex: 1, height: 1, background: "var(--border)" }} />
          </div>

          <div style={{ display: "flex", gap: 8 }}>
            {DEMO.map(({ u, p, label, icon: Icon }) => (
              <button
                key={u}
                type="button"
                className={"chip-btn" + (username === u ? " selected" : "")}
                onClick={() => setDemoUser(u, p)}
              >
                <Icon size={16} />
                {label}
              </button>
            ))}
          </div>

          <p style={{ textAlign: "center", fontSize: 13, color: "var(--muted)", margin: "22px 0 0" }}>
            Don't have an account?{" "}
            <button
              type="button"
              onClick={() => { setMode("register"); setError(""); }}
              style={{ background: "none", border: "none", padding: 0, color: "var(--teal)", fontWeight: 600, cursor: "pointer", fontSize: 13 }}
            >
              Request access
            </button>
          </p>
        </form>
        )}
      </div>
    </div>
  );
}
