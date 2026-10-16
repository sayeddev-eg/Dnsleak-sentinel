import { dnsEvents } from "./dnsEvents";

const map = {};
dnsEvents.forEach((e) => {
  const d = (map[e.sourceIp] ||= { ip: e.sourceIp, totalQueries: 0, suspiciousQueries: 0, maxRisk: 0 });
  d.totalQueries++;
  if (e.prediction === "suspicious") d.suspiciousQueries++;
  d.maxRisk = Math.max(d.maxRisk, e.riskScore);
});

export const devices = Object.values(map)
  .map((d) => ({ ...d, status: d.suspiciousQueries > 0 ? "suspicious" : "normal" }))
  .sort((a, b) => b.maxRisk - a.maxRisk);
  