export interface MockAlert {
  id: string;
  type: "critical_found" | "score_drop" | "ssl_expiring" | "scan_complete" | "team_invite" | "billing";
  title: string;
  description: string;
  domain?: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  read: boolean;
  createdAt: string;
}

export const alerts: MockAlert[] = [
  { id: "alt_01", type: "critical_found", title: "Critical vulnerability detected", description: "SQL injection risk found on clientapp.com login endpoint", domain: "clientapp.com", severity: "critical", read: false, createdAt: "2026-04-28T08:30:00Z" },
  { id: "alt_02", type: "ssl_expiring", title: "SSL certificate expiring", description: "Certificate for api.nanz.ai expires in 14 days", domain: "api.nanz.ai", severity: "high", read: false, createdAt: "2026-04-28T06:00:00Z" },
  { id: "alt_03", type: "score_drop", title: "Security score dropped", description: "clientapp.com score dropped from 52 to 45 (-7 points)", domain: "clientapp.com", severity: "medium", read: false, createdAt: "2026-04-27T14:30:00Z" },
  { id: "alt_04", type: "scan_complete", title: "Scan completed", description: "Scheduled scan for nanz.ai completed successfully. Score: 87", domain: "nanz.ai", severity: "info", read: true, createdAt: "2026-04-27T14:30:00Z" },
  { id: "alt_05", type: "team_invite", title: "New team member joined", description: "Neha Kapoor accepted the workspace invitation", severity: "info", read: true, createdAt: "2026-04-26T11:00:00Z" },
  { id: "alt_06", type: "scan_complete", title: "Scan completed", description: "Scheduled scan for api.nanz.ai completed. Score: 72", domain: "api.nanz.ai", severity: "info", read: true, createdAt: "2026-04-26T09:15:00Z" },
];

export const activityFeed = [
  { id: "act_01", action: "Vulnerability detected", detail: "Critical: Exposed database port on clientapp.com", icon: "alert", time: "2h ago" },
  { id: "act_02", action: "Scan completed", detail: "nanz.ai — Score: 87 (+5)", icon: "check", time: "4h ago" },
  { id: "act_03", action: "Score improved", detail: "api.nanz.ai score improved from 65 to 72", icon: "trending-up", time: "1d ago" },
  { id: "act_04", action: "Domain verified", detail: "staging.clientapp.com ownership verified via DNS", icon: "shield", time: "2d ago" },
  { id: "act_05", action: "Member invited", detail: "neha@client.com added as Viewer", icon: "user-plus", time: "3d ago" },
  { id: "act_06", action: "Report shared", detail: "clientapp.com report shared with external team", icon: "share", time: "4d ago" },
];
