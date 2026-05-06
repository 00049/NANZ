"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { cn } from "@/lib/utils";
import { NanzLogo } from "@/components/ui/NanzLogo";
import {
  LayoutDashboard, Globe, History, Activity, Settings, Bell,
  CreditCard, Users, Search, ChevronDown, LogOut, Shield,
  Menu, X, PanelLeftClose, PanelLeft, Plus, Command, Loader2
} from "lucide-react";
import ProtectedRoute from "@/components/ProtectedRoute";
import { getCurrentUser } from "@/lib/api";
import { useAuthStore } from "@/store/authStore";

const navItems = [
  { label: "Command Center", href: "/dashboard", icon: LayoutDashboard },
  { label: "Assets", href: "/dashboard/assets", icon: Globe },
  { label: "Scan History", href: "/dashboard/history", icon: History },
  { label: "Monitoring", href: "/dashboard/monitoring", icon: Activity },
];

const bottomItems = [
  { label: "Workspace", href: "/workspace", icon: Users },
  { label: "Settings", href: "/settings/profile", icon: Settings },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  
  const token = useAuthStore((state) => state.token);
  const logout = useAuthStore((state) => state.logout);
  const [user, setUser] = useState<{name: string, email: string} | null>(null);
  
  // Example alerts count
  const unreadAlerts = 2;

  useEffect(() => {
    if (token) {
      getCurrentUser(token)
        .then(data => setUser(data))
        .catch(err => {
          console.error("Failed to fetch user", err);
          logout();
          router.push("/auth/login");
        });
    }
  }, [token, logout, router]);

  const handleLogout = () => {
    logout();
    router.push("/auth/login");
  };

  if (!user) {
    return (
      <ProtectedRoute>
        <div className="min-h-screen flex items-center justify-center bg-background">
          <Loader2 className="w-8 h-8 text-primary animate-spin" />
        </div>
      </ProtectedRoute>
    );
  }

  return (
    <ProtectedRoute>
    <div className="min-h-screen flex bg-background">
      {/* Sidebar */}
      <aside className={cn(
        "hidden lg:flex flex-col fixed inset-y-0 left-0 z-40 border-r border-sidebar-border bg-sidebar transition-all duration-300",
        collapsed ? "w-[68px]" : "w-[260px]"
      )}>
        {/* Logo */}
        <div className={cn("flex items-center h-16 px-4 border-b border-sidebar-border", collapsed ? "justify-center" : "justify-between")}>
          <NanzLogo size="sm" showText={!collapsed} />
          <button onClick={() => setCollapsed(!collapsed)} className="text-text-muted hover:text-text-secondary transition-colors hidden lg:block">
            {collapsed ? <PanelLeft className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
          </button>
        </div>

        {/* Scan CTA */}
        <div className="px-3 pt-4 pb-2">
          <Link href="/" className={cn(
            "flex items-center gap-2 px-3 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity",
            collapsed ? "justify-center" : ""
          )}>
            <Plus className="w-4 h-4 flex-shrink-0" />
            {!collapsed && <span>New Scan</span>}
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-2 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const isActive = pathname === item.href || (item.href !== "/dashboard" && pathname.startsWith(item.href));
            return (
              <Link key={item.href} href={item.href} className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-btn text-sm font-medium transition-colors",
                isActive ? "bg-sidebar-active text-text-primary" : "text-text-secondary hover:text-text-primary hover:bg-sidebar-hover",
                collapsed ? "justify-center" : ""
              )}>
                <item.icon className={cn("w-4 h-4 flex-shrink-0", isActive && "text-nanz-400")} />
                {!collapsed && <span>{item.label}</span>}
              </Link>
            );
          })}
        </nav>

        {/* Bottom */}
        <div className="px-3 py-3 space-y-1 border-t border-sidebar-border">
          {bottomItems.map((item) => {
            const isActive = pathname.startsWith(item.href);
            return (
              <Link key={item.href} href={item.href} className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-btn text-sm font-medium transition-colors",
                isActive ? "bg-sidebar-active text-text-primary" : "text-text-secondary hover:text-text-primary hover:bg-sidebar-hover",
                collapsed ? "justify-center" : ""
              )}>
                <item.icon className={cn("w-4 h-4 flex-shrink-0", isActive && "text-nanz-400")} />
                {!collapsed && <span>{item.label}</span>}
              </Link>
            );
          })}
        </div>

        <div className={cn("px-3 py-3 border-t border-sidebar-border", collapsed ? "flex justify-center" : "")}>
          <div className={cn("flex items-center justify-between w-full", collapsed ? "" : "px-3")}>
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-nanz-gradient flex items-center justify-center text-xs font-bold text-white flex-shrink-0">
                {user.name.split(" ").map(n => n[0]).join("")}
              </div>
              {!collapsed && (
                <div className="min-w-0 max-w-[120px]">
                  <div className="text-sm font-medium text-text-primary truncate">{user.name}</div>
                  <div className="text-xs text-text-muted truncate">{user.email}</div>
                </div>
              )}
            </div>
            {!collapsed && (
              <button onClick={handleLogout} className="text-text-muted hover:text-critical transition-colors p-1" title="Logout">
                <LogOut className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      </aside>

      {/* Mobile header */}
      <div className="lg:hidden fixed top-0 inset-x-0 z-50 h-14 border-b border-surface-border bg-background/80 backdrop-blur-lg flex items-center justify-between px-4">
        <button onClick={() => setMobileOpen(true)} className="text-text-secondary"><Menu className="w-5 h-5" /></button>
        <NanzLogo size="sm" />
        <Link href="/dashboard" className="relative">
          <Bell className="w-5 h-5 text-text-secondary" />
          {unreadAlerts > 0 && <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-critical text-[10px] font-bold text-white flex items-center justify-center">{unreadAlerts}</span>}
        </Link>
      </div>

      {/* Mobile sidebar overlay */}
      {mobileOpen && (
        <div className="lg:hidden fixed inset-0 z-50">
          <div className="absolute inset-0 bg-black/60" onClick={() => setMobileOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-[280px] bg-sidebar border-r border-sidebar-border flex flex-col">
            <div className="flex items-center justify-between h-14 px-4 border-b border-sidebar-border">
              <NanzLogo size="sm" />
              <button onClick={() => setMobileOpen(false)} className="text-text-muted"><X className="w-5 h-5" /></button>
            </div>
            <div className="px-3 pt-4 pb-2">
              <Link href="/" className="flex items-center gap-2 px-3 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium" onClick={() => setMobileOpen(false)}>
                <Plus className="w-4 h-4" /> New Scan
              </Link>
            </div>
            <nav className="flex-1 px-3 py-2 space-y-1">
              {navItems.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <Link key={item.href} href={item.href} onClick={() => setMobileOpen(false)} className={cn(
                    "flex items-center gap-3 px-3 py-2.5 rounded-btn text-sm font-medium transition-colors",
                    isActive ? "bg-sidebar-active text-text-primary" : "text-text-secondary hover:text-text-primary hover:bg-sidebar-hover"
                  )}>
                    <item.icon className="w-4 h-4" />
                    <span>{item.label}</span>
                  </Link>
                );
              })}
            </nav>
            <div className="px-3 py-3 space-y-1 border-t border-sidebar-border">
              {bottomItems.map((item) => (
                <Link key={item.href} href={item.href} onClick={() => setMobileOpen(false)} className="flex items-center gap-3 px-3 py-2.5 rounded-btn text-sm text-text-secondary hover:text-text-primary hover:bg-sidebar-hover transition-colors">
                  <item.icon className="w-4 h-4" /> <span>{item.label}</span>
                </Link>
              ))}
            </div>
          </aside>
        </div>
      )}

      {/* Main content */}
      <main className={cn(
        "flex-1 min-h-screen transition-all duration-300 pt-14 lg:pt-0",
        collapsed ? "lg:ml-[68px]" : "lg:ml-[260px]"
      )}>
        {/* Top bar */}
        <header className="hidden lg:flex items-center justify-between h-16 px-8 border-b border-surface-border bg-background/50 backdrop-blur-sm sticky top-0 z-30">
          <div className="flex items-center gap-3">
            <button className="flex items-center gap-2 px-3 py-1.5 rounded-btn bg-surface border border-surface-border text-sm text-text-muted hover:text-text-secondary hover:border-surface-border-light transition-colors">
              <Command className="w-3.5 h-3.5" />
              <span>Search</span>
              <kbd className="ml-4 text-xs text-text-muted bg-surface-hover px-1.5 py-0.5 rounded">⌘K</kbd>
            </button>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/settings/notifications" className="relative p-2 rounded-btn text-text-muted hover:text-text-secondary hover:bg-surface transition-colors">
              <Bell className="w-4.5 h-4.5" />
              {unreadAlerts > 0 && <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-critical" />}
            </Link>
            <div className="w-px h-6 bg-surface-border" />
            <div className="flex items-center gap-2.5 cursor-pointer">
              <div className="w-8 h-8 rounded-full bg-nanz-gradient flex items-center justify-center text-xs font-bold text-white">
                {user.name.split(" ").map(n => n[0]).join("")}
              </div>
              <span className="text-sm text-text-primary font-medium">{user.name.split(" ")[0]}</span>
              <ChevronDown className="w-3.5 h-3.5 text-text-muted" />
            </div>
          </div>
        </header>

        <div className="p-4 lg:p-8">
          {children}
        </div>
      </main>
    </div>
    </ProtectedRoute>
  );
}
