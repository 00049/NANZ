"use client";

import { auditLogs } from "@/lib/mock-data";
import { cn } from "@/lib/utils";
import { ScrollText, LogIn, Globe, Share2, CreditCard, UserPlus, Activity } from "lucide-react";

const iconMap: Record<string, any> = {
  "user.login": LogIn,
  "domain.add": Globe,
  "report.share": Share2,
  "billing.upgrade": CreditCard,
  "team.invite": UserPlus,
  "monitoring.update": Activity,
};

export default function AuditLogPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-title text-text-primary flex items-center gap-2">
          <ScrollText className="w-5 h-5 text-nanz-400" /> Audit Log
        </h1>
        <p className="text-sm text-text-secondary mt-1">Enterprise security audit trail for your workspace</p>
      </div>

      <div className="rounded-card border border-card-border bg-card overflow-hidden">
        <div className="divide-y divide-surface-border">
          {auditLogs.map((log) => {
            const Icon = iconMap[log.action] || Activity;
            return (
              <div key={log.id} className="flex items-start gap-4 px-5 py-4">
                <div className="w-8 h-8 rounded-lg bg-surface flex items-center justify-center flex-shrink-0 mt-0.5">
                  <Icon className="w-3.5 h-3.5 text-text-muted" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-text-primary">{log.detail}</div>
                  <div className="flex items-center gap-3 mt-1">
                    <span className="text-xs text-text-muted">{log.user}</span>
                    <span className="text-xs text-text-muted">·</span>
                    <span className="text-xs text-text-muted font-mono">{log.ip}</span>
                  </div>
                </div>
                <span className="text-xs text-text-muted flex-shrink-0">{new Date(log.createdAt).toLocaleDateString("en-US", { month: "short", day: "numeric" })}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
