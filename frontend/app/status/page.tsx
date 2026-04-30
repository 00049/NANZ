import { NanzLogo } from "@/components/ui/NanzLogo";
import { CheckCircle2, AlertTriangle, Clock } from "lucide-react";

const services = [
  { name: "Security Scanner", status: "operational", uptime: "99.98%" },
  { name: "API Gateway", status: "operational", uptime: "99.99%" },
  { name: "Report Generation", status: "operational", uptime: "99.95%" },
  { name: "Monitoring Engine", status: "operational", uptime: "99.97%" },
  { name: "Notification Service", status: "operational", uptime: "99.99%" },
];

const incidents = [
  { date: "2026-04-15", title: "Elevated scan queue times", status: "resolved", description: "Scan processing times were elevated for ~30 minutes due to increased load. Auto-scaling resolved the issue." },
  { date: "2026-03-22", title: "Scheduled maintenance", status: "completed", description: "Database migration completed successfully. No downtime experienced." },
];

export default function StatusPage() {
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-surface-border">
        <div className="max-w-4xl mx-auto flex items-center justify-between px-6 h-16">
          <NanzLogo size="sm" />
          <span className="flex items-center gap-2 text-sm text-success font-medium">
            <CheckCircle2 className="w-4 h-4" /> All Systems Operational
          </span>
        </div>
      </header>

      <div className="max-w-4xl mx-auto px-6 py-12 space-y-10">
        <div>
          <h1 className="text-headline text-text-primary">System Status</h1>
          <p className="text-text-secondary mt-2">Real-time status of NANZ infrastructure and services</p>
        </div>

        {/* Services */}
        <div className="rounded-card border border-card-border bg-card overflow-hidden">
          {services.map((service, idx) => (
            <div key={service.name} className={`flex items-center justify-between px-5 py-4 ${idx < services.length - 1 ? "border-b border-surface-border" : ""}`}>
              <div className="flex items-center gap-3">
                <CheckCircle2 className="w-4 h-4 text-success" />
                <span className="text-sm font-medium text-text-primary">{service.name}</span>
              </div>
              <div className="flex items-center gap-4">
                <span className="text-xs text-text-muted">{service.uptime} uptime</span>
                <span className="text-xs font-medium text-success capitalize">{service.status}</span>
              </div>
            </div>
          ))}
        </div>

        {/* Uptime bars */}
        <div className="rounded-card border border-card-border bg-card p-5">
          <h3 className="text-sm font-semibold text-text-primary mb-4">90-Day Uptime</h3>
          <div className="flex gap-0.5">
            {[...Array(90)].map((_, i) => (
              <div key={i} className={`flex-1 h-8 rounded-sm ${i === 45 ? "bg-medium" : "bg-success/70"}`} title={i === 45 ? "Partial outage" : "Operational"} />
            ))}
          </div>
          <div className="flex justify-between mt-2 text-xs text-text-muted">
            <span>90 days ago</span><span>Today</span>
          </div>
        </div>

        {/* Incidents */}
        <div>
          <h3 className="text-sm font-semibold text-text-primary mb-4">Recent Incidents</h3>
          <div className="space-y-4">
            {incidents.map((inc) => (
              <div key={inc.date} className="rounded-card border border-card-border bg-card p-5">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-medium text-text-primary">{inc.title}</h4>
                  <span className="text-xs text-success capitalize">{inc.status}</span>
                </div>
                <p className="text-xs text-text-muted">{inc.description}</p>
                <div className="text-xs text-text-muted mt-2">{inc.date}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
