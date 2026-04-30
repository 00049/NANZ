"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { NanzLogo } from "@/components/ui/NanzLogo";
import { User, Shield, Sliders, Bell, CreditCard, ScrollText, Code, ArrowLeft } from "lucide-react";

const settingsNav = [
  { label: "Profile", href: "/settings/profile", icon: User },
  { label: "Security", href: "/settings/security", icon: Shield },
  { label: "Notifications", href: "/settings/notifications", icon: Bell },
  { label: "Billing", href: "/settings/billing", icon: CreditCard },
  { label: "API Keys", href: "/settings/api", icon: Code },
  { label: "Audit Log", href: "/settings/audit-log", icon: ScrollText },
];

export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="min-h-screen flex bg-background">
      {/* Settings Sidebar */}
      <aside className="hidden lg:flex w-[260px] flex-col fixed inset-y-0 left-0 border-r border-surface-border bg-surface/50">
        <div className="flex items-center h-16 px-5 border-b border-surface-border gap-3">
          <Link href="/dashboard" className="text-text-muted hover:text-text-secondary transition-colors"><ArrowLeft className="w-4 h-4" /></Link>
          <NanzLogo size="sm" />
        </div>
        <div className="px-3 pt-4 pb-2">
          <span className="px-3 text-xs font-medium text-text-muted uppercase tracking-wider">Settings</span>
        </div>
        <nav className="flex-1 px-3 py-1 space-y-0.5">
          {settingsNav.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link key={item.href} href={item.href} className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-btn text-sm font-medium transition-colors",
                isActive ? "bg-surface-active text-text-primary" : "text-text-secondary hover:text-text-primary hover:bg-surface-hover"
              )}>
                <item.icon className={cn("w-4 h-4", isActive && "text-nanz-400")} />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>
      </aside>

      {/* Mobile Header */}
      <div className="lg:hidden fixed top-0 inset-x-0 z-50 h-14 border-b border-surface-border bg-background/80 backdrop-blur-lg flex items-center px-4 gap-3">
        <Link href="/dashboard" className="text-text-muted"><ArrowLeft className="w-5 h-5" /></Link>
        <span className="text-sm font-semibold text-text-primary">Settings</span>
      </div>

      {/* Mobile nav */}
      <div className="lg:hidden fixed top-14 inset-x-0 z-40 overflow-x-auto border-b border-surface-border bg-background/80 backdrop-blur-lg">
        <div className="flex px-4 py-2 gap-1 min-w-max">
          {settingsNav.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link key={item.href} href={item.href} className={cn(
                "px-3 py-1.5 rounded-btn text-xs font-medium whitespace-nowrap transition-colors",
                isActive ? "bg-surface-active text-text-primary" : "text-text-muted"
              )}>
                {item.label}
              </Link>
            );
          })}
        </div>
      </div>

      <main className="flex-1 lg:ml-[260px] pt-28 lg:pt-0">
        <div className="max-w-3xl mx-auto p-6 lg:p-10">
          {children}
        </div>
      </main>
    </div>
  );
}
