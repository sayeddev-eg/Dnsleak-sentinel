const IPS_BAD = ["192.168.1.20", "192.168.1.52"];
const IPS_OK = ["192.168.1.31", "192.168.1.45", "192.168.1.77"];
const OK_DOMAINS = ["google.com", "github.com", "youtube.com", "microsoft.com", "wikipedia.org", "stackoverflow.com"];
const TYPES = ["A", "AAAA", "CNAME", "TXT", "MX"];
const CHARS = "abcdefghijklmnopqrstuvwxyz0123456789";

// رقم عشوائي ثابت (مش بيتغير مع كل Refresh)
const rand = (seed) => {
  const x = Math.sin(seed) * 10000;
  return x - Math.floor(x);
};
const randStr = (seed, len) =>
  Array.from({ length: len }, (_, k) => CHARS[Math.floor(rand(seed * 31 + k) * CHARS.length)]).join("");

const severityOf = (r) => (r >= 90 ? "critical" : r >= 70 ? "high" : r >= 40 ? "medium" : "low");
const BASE = new Date("2026-11-23T10:32:15").getTime();

export const dnsEvents = Array.from({ length: 100 }, (_, i) => {
  const id = i + 1;
  const bad = rand(id * 3) > 0.65;
  const riskScore = bad ? 70 + Math.floor(rand(id * 7) * 30) : 2 + Math.floor(rand(id * 5) * 30);
  const t = new Date(BASE - i * 15000);
  const timestamp = new Date(t.getTime() - t.getTimezoneOffset() * 60000).toISOString().slice(0, 19);

  return {
    id,
    timestamp,
    sourceIp: bad ? IPS_BAD[id % 2] : IPS_OK[id % 3],
    domain: bad ? `${randStr(id, 12)}.attacker.com` : OK_DOMAINS[id % OK_DOMAINS.length],
    queryType: bad ? (id % 3 === 0 ? "TXT" : "A") : TYPES[id % TYPES.length],
    prediction: bad ? "suspicious" : "normal",
    confidence: bad ? +(0.85 + rand(id) * 0.14).toFixed(2) : +(0.9 + rand(id) * 0.09).toFixed(2),
    riskScore,
    severity: severityOf(riskScore),
    reasons: bad ? ["High entropy", "Long subdomain", "High query frequency"] : [],
  };
});
