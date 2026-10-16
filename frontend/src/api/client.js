// In production set VITE_API_URL (e.g. https://dnsleak-api.onrender.com) at build time.
const API_ROOT = (import.meta.env.VITE_API_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");
const API_BASE = `${API_ROOT}/api/v1`;

// ------------------------------------------------------------------ session helpers
function getToken() {
  try {
    return JSON.parse(localStorage.getItem("soc_user") || "null")?.token || null;
  } catch {
    return null;
  }
}

function authHeaders(extra = {}) {
  const t = getToken();
  return t ? { ...extra, Authorization: `Bearer ${t}` } : extra;
}

/** Fires when the backend says the session is no longer valid → App logs out. */
function handleAuthFailure(res) {
  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent("soc-auth-expired"));
  }
}

async function errorText(res, fallback) {
  const err = await res.json().catch(() => ({}));
  return err.detail || fallback;
}

async function authed(path, { method = "GET", body, json = true } = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: authHeaders(json && body !== undefined ? { "Content-Type": "application/json" } : {}),
    body: body === undefined ? undefined : json ? JSON.stringify(body) : body,
  });
  if (!res.ok) {
    handleAuthFailure(res);
    throw new Error(await errorText(res, `Request failed (${res.status})`));
  }
  return res.json();
}

export const api = {
  // 1. Auth
  async login(username, password) {
    let timedOut = false;
    const ctrl = new AbortController();
    const timer = setTimeout(() => { timedOut = true; ctrl.abort(); }, 15000);
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
      signal: ctrl.signal,
    }).catch(() => null);
    clearTimeout(timer);
    if (!res && timedOut) throw new Error("The server took too long to respond. Check the backend terminal and try again.");
    if (!res) throw new Error("Cannot reach the authentication server. Is the backend running?");
    if (res.ok) {
      const data = await res.json();
      return { ...data.user, token: data.token };
    }
    if (res.status === 401) return null;
    // 403 pending / rejected / disabled, 429 rate-limited
    throw new Error(await errorText(res, "Sign-in failed"));
  },

  async register(payload) {
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).catch(() => null);
    if (!res) throw new Error("Cannot reach the server. Is the backend running?");
    if (!res.ok) throw new Error(await errorText(res, "Registration failed"));
    return res.json();
  },

  async logout() {
    try {
      await fetch(`${API_BASE}/auth/logout`, { method: "POST", headers: authHeaders() });
    } catch {
      /* ignore */
    }
  },

  // 2. Dashboard KPIs
  async getKpi() {
    try {
      const res = await fetch(`${API_BASE}/kpi`);
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn("Error fetching KPI:", e);
    }
    return null;
  },

  // 3. Traffic Trend
  async getTrafficTrend() {
    try {
      const res = await fetch(`${API_BASE}/traffic-trend`);
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn("Error fetching traffic trend:", e);
    }
    return [];
  },

  // 4. Live DNS Events
  async getDnsEvents(limit = 100) {
    try {
      const res = await fetch(`${API_BASE}/dns-events?limit=${limit}`);
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn("Error fetching dns events:", e);
    }
    return [];
  },

  // 5. Alerts
  async getAlerts(limit = 50) {
    try {
      const res = await fetch(`${API_BASE}/alerts?limit=${limit}`);
      if (res.ok) {
        const rows = await res.json();
        return rows.map((a) => ({
          id: `ALT-${String(a.id).padStart(3, "0")}`,
          timestamp: a.timestamp,
          device: a.src_ip,
          domain: a.domain,
          riskScore: a.probability,
          severity: (a.level || "low").toLowerCase(),
          reasons: a.reasons || [],
        }));
      }
    } catch (e) {
      console.warn("Error fetching alerts:", e);
    }
    return [];
  },

  // 6. Devices
  async getDevices() {
    try {
      const res = await fetch(`${API_BASE}/devices`);
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn("Error fetching devices:", e);
    }
    return [];
  },

  // 7. AI Performance
  async getAiPerformance() {
    try {
      const res = await fetch(`${API_BASE}/ai-performance`);
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn("Error fetching AI performance:", e);
    }
    return null;
  },

  // 8. Upload PCAP (authenticated → recorded in audit log)
  async uploadPcap(file) {
    const formData = new FormData();
    formData.append("file", file);
    return authed("/analyze/pcap", { method: "POST", body: formData, json: false });
  },

  // 9. Clear Alerts (admin / analyst)
  async clearAlerts() {
    try {
      await authed("/alerts/clear", { method: "DELETE" });
      return true;
    } catch (e) {
      console.warn("Clear alerts failed:", e);
      return false;
    }
  },

  // 10. Simulate Query
  async simulateQuery(isAttack = false) {
    try {
      return await authed(`/simulate/query?is_attack=${isAttack}`, { method: "POST" });
    } catch (e) {
      console.warn("Simulation failed:", e);
      return null;
    }
  },

  // 11. Health
  async checkHealth() {
    try {
      const res = await fetch(`${API_ROOT}/health`);
      return res.ok;
    } catch {
      return false;
    }
  },

  // ------------------------------------------------------------ Audit log
  /** Fire-and-forget client event (page views, exports). */
  logEvent(action, target = "", details = {}) {
    if (!getToken()) return;
    fetch(`${API_BASE}/audit/event`, {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ action, target, details }),
      keepalive: true,
    })
      .then(handleAuthFailure)
      .catch(() => {});
  },

  async getAudit(filters = {}, limit = 50, offset = 0) {
    const params = new URLSearchParams({ limit, offset });
    Object.entries(filters).forEach(([k, v]) => v && params.set(k, v));
    return authed(`/audit?${params}`);
  },

  async getAuditEntry(id) {
    return authed(`/audit/${id}`);
  },

  async deleteAudit(ids, cascade = false) {
    return authed("/audit/delete", { method: "POST", body: { ids, cascade } });
  },

  async purgeAudit(filters = {}, cascade = false) {
    return authed("/audit/purge", { method: "POST", body: { ...filters, cascade, confirm: true } });
  },

  // ------------------------------------------------------------ User management (admin)
  async getUsers(status = "") {
    return authed(`/users${status ? `?status=${status}` : ""}`);
  },
  async getPendingCount() {
    try {
      return (await authed("/users/pending-count")).pending;
    } catch {
      return 0;
    }
  },
  async approveUser(id, role, note = "") {
    return authed(`/users/${id}/approve`, { method: "POST", body: { role, note } });
  },
  async rejectUser(id, note = "") {
    return authed(`/users/${id}/reject`, { method: "POST", body: { note } });
  },
  async updateUser(id, changes) {
    return authed(`/users/${id}`, { method: "PATCH", body: changes });
  },
  async deleteUser(id) {
    return authed(`/users/${id}`, { method: "DELETE" });
  },
};
