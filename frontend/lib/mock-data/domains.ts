export interface MockDomain {
  id: string;
  domain: string;
  status: "verified" | "pending" | "unverified";
  score: number;
  severity: "CRITICAL" | "RED" | "AMBER" | "GREEN";
  monitoring: "daily" | "weekly" | "monthly" | "manual";
  lastScanDate: string;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  addedAt: string;
}

export const domains: MockDomain[] = [
  { id: "dom_01", domain: "nanz.ai", status: "verified", score: 87, severity: "GREEN", monitoring: "daily", lastScanDate: "2026-04-27T14:30:00Z", criticalCount: 0, highCount: 1, mediumCount: 3, addedAt: "2025-12-01T10:00:00Z" },
  { id: "dom_02", domain: "api.nanz.ai", status: "verified", score: 72, severity: "AMBER", monitoring: "weekly", lastScanDate: "2026-04-26T09:15:00Z", criticalCount: 0, highCount: 3, mediumCount: 5, addedAt: "2026-01-15T10:00:00Z" },
  { id: "dom_03", domain: "clientapp.com", status: "verified", score: 45, severity: "RED", monitoring: "daily", lastScanDate: "2026-04-28T02:00:00Z", criticalCount: 2, highCount: 4, mediumCount: 6, addedAt: "2026-02-20T10:00:00Z" },
  { id: "dom_04", domain: "staging.clientapp.com", status: "pending", score: 63, severity: "AMBER", monitoring: "monthly", lastScanDate: "2026-04-20T11:45:00Z", criticalCount: 1, highCount: 2, mediumCount: 4, addedAt: "2026-03-10T10:00:00Z" },
  { id: "dom_05", domain: "newproject.dev", status: "unverified", score: 0, severity: "GREEN", monitoring: "manual", lastScanDate: "", criticalCount: 0, highCount: 0, mediumCount: 0, addedAt: "2026-04-25T10:00:00Z" },
];

export const scoreHistory = [
  { date: "Jan", nanz: 62, clientapp: 38, api: 55 },
  { date: "Feb", nanz: 68, clientapp: 42, api: 60 },
  { date: "Mar", nanz: 75, clientapp: 48, api: 65 },
  { date: "Apr", nanz: 82, clientapp: 45, api: 72 },
  { date: "May", nanz: 87, clientapp: 45, api: 72 },
];
