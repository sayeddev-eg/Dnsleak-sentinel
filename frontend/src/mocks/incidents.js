import { devices } from "./devices";
import { alerts } from "./alerts";

const STATUSES = ["open", "investigating", "contained", "resolved", "false_positive"];

export const incidents = devices
  .filter((d) => d.suspiciousQueries > 0)
  .map((d, i) => {
    const last = alerts.find((a) => a.device === d.ip);
    return {
      id: `INC-${String(i + 1).padStart(3, "0")}`,
      threat: "Possible DNS Data Exfiltration",
      device: d.ip,
      domain: last?.domain,
      riskScore: d.maxRisk,
      severity: last?.severity,
      status: STATUSES[i % STATUSES.length],
      detectedAt: last?.timestamp,
      reasons: last?.reasons ?? [],
    };
  });
  