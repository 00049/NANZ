export interface MockInvoice {
  id: string;
  date: string;
  amount: number;
  currency: string;
  status: "paid" | "pending" | "failed" | "refunded";
  plan: string;
  downloadUrl: string;
}

export const invoices: MockInvoice[] = [
  { id: "inv_01", date: "2026-04-01", amount: 49, currency: "USD", status: "paid", plan: "Pro", downloadUrl: "#" },
  { id: "inv_02", date: "2026-03-01", amount: 49, currency: "USD", status: "paid", plan: "Pro", downloadUrl: "#" },
  { id: "inv_03", date: "2026-02-01", amount: 49, currency: "USD", status: "paid", plan: "Pro", downloadUrl: "#" },
  { id: "inv_04", date: "2026-01-01", amount: 0, currency: "USD", status: "paid", plan: "Free", downloadUrl: "#" },
];

export interface MockPlan {
  id: string;
  name: string;
  monthlyPrice: number;
  yearlyPrice: number;
  features: string[];
  scansPerMonth: number;
  domainsLimit: number;
  teamSeats: number;
  popular?: boolean;
}

export const plans: MockPlan[] = [
  { id: "free", name: "Free", monthlyPrice: 0, yearlyPrice: 0, scansPerMonth: 3, domainsLimit: 1, teamSeats: 1, features: ["3 scans per month", "1 domain", "Basic report", "Email support"] },
  { id: "pro", name: "Pro", monthlyPrice: 49, yearlyPrice: 39, scansPerMonth: 50, domainsLimit: 10, teamSeats: 3, popular: true, features: ["50 scans per month", "10 domains", "Continuous monitoring", "PDF exports", "Priority support", "API access"] },
  { id: "business", name: "Business", monthlyPrice: 149, yearlyPrice: 119, scansPerMonth: 200, domainsLimit: 50, teamSeats: 10, features: ["200 scans per month", "50 domains", "Multi-user workspaces", "Slack / Discord alerts", "Custom webhooks", "Compliance reports", "Dedicated support"] },
  { id: "agency", name: "Agency", monthlyPrice: 399, yearlyPrice: 319, scansPerMonth: -1, domainsLimit: -1, teamSeats: -1, features: ["Unlimited scans", "Unlimited domains", "Unlimited team seats", "White-label reports", "Client management", "API priority access", "Custom integrations", "Account manager"] },
];

export const currentSubscription = {
  planId: "pro",
  status: "active" as const,
  currentPeriodEnd: "2026-05-01T00:00:00Z",
  scansUsed: 28,
  scansLimit: 50,
  domainsUsed: 4,
  domainsLimit: 10,
  seatsUsed: 5,
  seatsLimit: 3,
};

export const auditLogs = [
  { id: "log_01", action: "user.login", user: "Admin User", detail: "Logged in from Chrome on macOS", ip: "103.45.xx.xx", createdAt: "2026-04-28T10:30:00Z" },
  { id: "log_02", action: "domain.add", user: "Admin User", detail: "Added domain newproject.dev", ip: "103.45.xx.xx", createdAt: "2026-04-25T10:00:00Z" },
  { id: "log_03", action: "report.share", user: "Priya Sharma", detail: "Shared clientapp.com report (public link)", ip: "182.73.xx.xx", createdAt: "2026-04-24T15:20:00Z" },
  { id: "log_04", action: "billing.upgrade", user: "Ravi Kumar", detail: "Upgraded plan from Free to Pro", ip: "103.45.xx.xx", createdAt: "2026-04-20T09:45:00Z" },
  { id: "log_05", action: "team.invite", user: "Admin User", detail: "Invited neha@client.com as Viewer", ip: "103.45.xx.xx", createdAt: "2026-04-18T11:00:00Z" },
  { id: "log_06", action: "monitoring.update", user: "Arjun Mehta", detail: "Changed clientapp.com monitoring to Daily", ip: "49.36.xx.xx", createdAt: "2026-04-15T14:30:00Z" },
];
