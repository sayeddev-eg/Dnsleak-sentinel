export const analytics = {
  total: 5000,
  normal: 4800,
  suspicious: 150,
  critical: 50,
  traffic_over_time: [
    { time: "09:00", normal: 380, suspicious: 4 },
    { time: "09:30", normal: 420, suspicious: 6 },
    { time: "10:00", normal: 400, suspicious: 12 },
    { time: "10:30", normal: 450, suspicious: 48 },
    { time: "11:00", normal: 410, suspicious: 70 },
  ],
  risk_distribution: [
    { level: "Low", count: 4800 },
    { level: "Medium", count: 90 },
    { level: "High", count: 60 },
    { level: "Critical", count: 50 },
  ],
  top_suspicious_devices: [
    { ip: "192.168.1.20", count: 73 },
    { ip: "192.168.1.35", count: 28 },
    { ip: "192.168.1.12", count: 6 },
  ],
  top_suspicious_domains: [
    { domain: "a82k91x7q2.example.com", count: 40 },
    { domain: "91kx82m7q9.example.com", count: 33 },
    { domain: "x72k91m82.example.com", count: 28 },
  ],
}
