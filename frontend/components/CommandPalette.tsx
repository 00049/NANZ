"use client";

import { useEffect, useState, useCallback } from "react";
import { Command } from "cmdk";
import { useRouter } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard, Globe, History, Activity, Settings, CreditCard,
  Users, Search, Shield, FileText, Plus, ExternalLink, Bell,
  Code, ScrollText, HelpCircle, Zap,
} from "lucide-react";

const groups = [
  {
    heading: "Navigation",
    items: [
      { label: "Command Center", icon: LayoutDashboard, href: "/dashboard" },
      { label: "Assets", icon: Globe, href: "/dashboard/assets" },
      { label: "Scan History", icon: History, href: "/dashboard/history" },
      { label: "Monitoring", icon: Activity, href: "/dashboard/monitoring" },
      { label: "Workspace", icon: Users, href: "/workspace" },
    ],
  },
  {
    heading: "Actions",
    items: [
      { label: "New Scan", icon: Plus, href: "/" },
      { label: "Add Domain", icon: Globe, href: "/dashboard/assets" },
      { label: "Invite Team Member", icon: Users, href: "/workspace" },
      { label: "Upgrade Plan", icon: Zap, href: "/settings/billing" },
    ],
  },
  {
    heading: "Settings",
    items: [
      { label: "Profile", icon: Settings, href: "/settings/profile" },
      { label: "Security", icon: Shield, href: "/settings/security" },
      { label: "Billing", icon: CreditCard, href: "/settings/billing" },
      { label: "Notifications", icon: Bell, href: "/settings/notifications" },
      { label: "API Keys", icon: Code, href: "/settings/api" },
      { label: "Audit Log", icon: ScrollText, href: "/settings/audit-log" },
    ],
  },
  {
    heading: "Resources",
    items: [
      { label: "Documentation", icon: FileText, href: "/docs" },
      { label: "Help Center", icon: HelpCircle, href: "/help" },
      { label: "System Status", icon: Activity, href: "/status" },
    ],
  },
];

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, []);

  const runCommand = useCallback((href: string) => {
    setOpen(false);
    router.push(href);
  }, [router]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[100]">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setOpen(false)} />

      {/* Command dialog */}
      <div className="absolute top-[20%] left-1/2 -translate-x-1/2 w-full max-w-[560px] px-4">
        <Command className="rounded-panel border border-surface-border bg-card shadow-2xl overflow-hidden">
          {/* Input */}
          <div className="flex items-center gap-3 px-4 border-b border-surface-border">
            <Search className="w-4 h-4 text-text-muted flex-shrink-0" />
            <Command.Input
              placeholder="Type a command or search..."
              className="flex-1 py-4 bg-transparent text-sm text-text-primary placeholder:text-text-muted outline-none"
              autoFocus
            />
            <kbd className="text-[10px] text-text-muted bg-surface px-1.5 py-0.5 rounded border border-surface-border">ESC</kbd>
          </div>

          {/* Results */}
          <Command.List className="max-h-[340px] overflow-y-auto p-2">
            <Command.Empty className="py-8 text-center text-sm text-text-muted">No results found.</Command.Empty>
            {groups.map((group) => (
              <Command.Group key={group.heading} heading={group.heading}
                className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-2 [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:text-text-muted [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider">
                {group.items.map((item) => (
                  <Command.Item
                    key={item.label}
                    value={item.label}
                    onSelect={() => runCommand(item.href)}
                    className="flex items-center gap-3 px-3 py-2.5 rounded-btn text-sm text-text-secondary cursor-pointer data-[selected=true]:bg-surface-hover data-[selected=true]:text-text-primary transition-colors"
                  >
                    <item.icon className="w-4 h-4 text-text-muted flex-shrink-0" />
                    <span>{item.label}</span>
                  </Command.Item>
                ))}
              </Command.Group>
            ))}
          </Command.List>

          {/* Footer */}
          <div className="flex items-center justify-between px-4 py-2.5 border-t border-surface-border text-[10px] text-text-muted">
            <span>Navigate with ↑↓ · Select with ↵</span>
            <span>NANZ Command Palette</span>
          </div>
        </Command>
      </div>
    </div>
  );
}
