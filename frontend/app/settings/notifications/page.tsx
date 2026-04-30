"use client";

import { useState } from "react";
import { cn } from "@/lib/utils";
import { Mail, MessageSquare, Bell as BellIcon, Hash, Smartphone } from "lucide-react";

const channels = [
  { id: "email", label: "Email", description: "Receive alerts to your inbox", icon: Mail, enabled: true },
  { id: "slack", label: "Slack", description: "Send alerts to a Slack channel", icon: Hash, enabled: true, webhook: "https://hooks.slack.com/services/T.../B..." },
  { id: "discord", label: "Discord", description: "Post to a Discord webhook", icon: MessageSquare, enabled: false },
  { id: "telegram", label: "Telegram", description: "Push notifications via Telegram bot", icon: BellIcon, enabled: false },
  { id: "sms", label: "SMS", description: "Critical alerts via text message", icon: Smartphone, enabled: false, badge: "Pro" },
];

const preferences = [
  { id: "critical_only", label: "Critical findings only", active: false },
  { id: "all_findings", label: "All findings", active: true },
  { id: "weekly_digest", label: "Weekly digest email", active: true },
  { id: "monthly_summary", label: "Monthly summary report", active: false },
];

export default function NotificationsPage() {
  const [chs, setChs] = useState(channels);
  const [prefs, setPrefs] = useState(preferences);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-title text-text-primary">Notifications</h1>
        <p className="text-sm text-text-secondary mt-1">Configure how and when you receive alerts</p>
      </div>

      {/* Channels */}
      <div className="rounded-card border border-card-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-surface-border">
          <h3 className="text-sm font-semibold text-text-primary">Notification Channels</h3>
        </div>
        <div className="divide-y divide-surface-border">
          {chs.map((ch, idx) => (
            <div key={ch.id} className="flex items-center justify-between px-5 py-4">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-surface flex items-center justify-center"><ch.icon className="w-4 h-4 text-text-muted" /></div>
                <div>
                  <div className="text-sm text-text-primary font-medium flex items-center gap-2">{ch.label} {ch.badge && <span className="text-[10px] px-1.5 py-0.5 rounded bg-nanz-600/20 text-nanz-400">{ch.badge}</span>}</div>
                  <div className="text-xs text-text-muted">{ch.description}</div>
                </div>
              </div>
              <button onClick={() => { const next = [...chs]; next[idx] = { ...next[idx], enabled: !next[idx].enabled }; setChs(next); }}
                className={cn("relative w-10 h-6 rounded-full transition-colors", ch.enabled ? "bg-nanz-500" : "bg-surface-border")}>
                <div className={cn("absolute top-1 w-4 h-4 rounded-full bg-white transition-transform", ch.enabled ? "left-5" : "left-1")} />
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Preferences */}
      <div className="rounded-card border border-card-border bg-card overflow-hidden">
        <div className="px-5 py-4 border-b border-surface-border">
          <h3 className="text-sm font-semibold text-text-primary">Alert Preferences</h3>
        </div>
        <div className="divide-y divide-surface-border">
          {prefs.map((pref, idx) => (
            <div key={pref.id} className="flex items-center justify-between px-5 py-4">
              <span className="text-sm text-text-primary">{pref.label}</span>
              <button onClick={() => { const next = [...prefs]; next[idx] = { ...next[idx], active: !next[idx].active }; setPrefs(next); }}
                className={cn("relative w-10 h-6 rounded-full transition-colors", pref.active ? "bg-nanz-500" : "bg-surface-border")}>
                <div className={cn("absolute top-1 w-4 h-4 rounded-full bg-white transition-transform", pref.active ? "left-5" : "left-1")} />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
