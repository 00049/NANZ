"use client";

import { domains } from "@/lib/mock-data";
import { cn } from "@/lib/utils";
import { Globe, Bell, AlertTriangle, Lock, RefreshCw, Shield } from "lucide-react";
import { useState } from "react";

const scheduleOptions = ["daily", "weekly", "monthly", "manual"] as const;

const alertTriggers = [
  { id: "score_drop", label: "Score drops by 10+ points", icon: AlertTriangle, enabled: true },
  { id: "critical_issue", label: "New critical vulnerability found", icon: Shield, enabled: true },
  { id: "ssl_expiry", label: "SSL certificate expiring within 30 days", icon: Lock, enabled: true },
  { id: "dns_misconfig", label: "DNS misconfiguration detected", icon: RefreshCw, enabled: false },
];

export default function MonitoringPage() {
  const [triggers, setTriggers] = useState(alertTriggers);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-title text-text-primary">Continuous Monitoring</h1>
        <p className="text-sm text-text-secondary mt-1">Configure automated scanning schedules and alert triggers</p>
      </div>

      {/* Domain Monitoring Config */}
      <div className="rounded-card border border-card-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-surface-border">
          <h3 className="text-sm font-semibold text-text-primary">Scan Schedule per Domain</h3>
          <p className="text-xs text-text-muted mt-1">Set how often each domain is automatically scanned</p>
        </div>
        <div className="divide-y divide-surface-border">
          {domains.filter(d => d.status === "verified").map((domain) => (
            <div key={domain.id} className="flex items-center justify-between px-5 py-4">
              <div className="flex items-center gap-3">
                <Globe className="w-4 h-4 text-text-muted" />
                <span className="text-sm font-medium text-text-primary">{domain.domain}</span>
              </div>
              <div className="flex items-center gap-1.5 bg-surface rounded-btn p-1">
                {scheduleOptions.map((opt) => (
                  <button
                    key={opt}
                    className={cn(
                      "px-3 py-1.5 rounded text-xs font-medium capitalize transition-colors",
                      domain.monitoring === opt
                        ? "bg-nanz-600/20 text-nanz-400"
                        : "text-text-muted hover:text-text-secondary"
                    )}
                  >
                    {opt}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Alert Triggers */}
      <div className="rounded-card border border-card-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-surface-border">
          <h3 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <Bell className="w-4 h-4 text-nanz-400" /> Alert Triggers
          </h3>
          <p className="text-xs text-text-muted mt-1">Get notified when these conditions are met</p>
        </div>
        <div className="divide-y divide-surface-border">
          {triggers.map((trigger, idx) => (
            <div key={trigger.id} className="flex items-center justify-between px-5 py-4">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-surface flex items-center justify-center">
                  <trigger.icon className="w-4 h-4 text-text-muted" />
                </div>
                <span className="text-sm text-text-primary">{trigger.label}</span>
              </div>
              <button
                onClick={() => {
                  const next = [...triggers];
                  next[idx] = { ...next[idx], enabled: !next[idx].enabled };
                  setTriggers(next);
                }}
                className={cn(
                  "relative w-10 h-6 rounded-full transition-colors",
                  trigger.enabled ? "bg-nanz-500" : "bg-surface-border"
                )}
              >
                <div className={cn(
                  "absolute top-1 w-4 h-4 rounded-full bg-white transition-transform",
                  trigger.enabled ? "left-5" : "left-1"
                )} />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
