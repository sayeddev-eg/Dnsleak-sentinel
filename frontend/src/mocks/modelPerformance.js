export const modelPerformance = {
  accuracy: 0.97,
  precision: 0.96,
  recall: 0.95,
  f1: 0.955,
  rocAuc: 0.99,
  confusionMatrix: { tn: 940, fp: 20, fn: 25, tp: 515 },
  featureImportance: [
    { feature: "Entropy", value: 0.31 },
    { feature: "Query Frequency", value: 0.24 },
    { feature: "Subdomain Length", value: 0.18 },
    { feature: "Unique Subdomains", value: 0.15 },
  ],
};
