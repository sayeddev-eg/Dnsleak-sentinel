import { dnsEvents } from "./dnsEvents";

export const alerts = dnsEvents
  .filter((e) => e.prediction === "suspicious")
  .map((e) => ({
    id: `ALT-${String(e.id).padStart(3, "0")}`,
    timestamp: e.timestamp,
    device: e.sourceIp,
    domain: e.domain,
    riskScore: e.riskScore,
    severity: e.severity,
    reasons: e.reasons,
  }));
  