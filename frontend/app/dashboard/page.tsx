"use client";

import { useEffect, useState } from "react";
import { scoreHistory, activityFeed, severityData as mockSeverity } from "@/lib/mock-data";
import { cn } from "@/lib/utils";
import { Shield, Globe, AlertTriangle, TrendingUp, ArrowUpRight, ArrowDownRight, Activity, CheckCircle2, UserPlus, Share2, ExternalLink, Loader2 } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from "recharts";
import Link from "next/link";
import { useAuthStore } from "@/store/authStore";
import { getCurrentUser, getDomains } from "@/lib/api";

const metricCards = [
  { label: "Domains Monitored", value: domains.filter(d => d.status === "verified").length.toString(), change: "+1 this month", trend: "up", icon: Globe, color: "text-nanz-400" },
  { label: "Avg Security Score", value: Math.round(domains.filter(d => d.score > 0).reduce((a, b) => a + b.score, 0) / domains.filter(d => d.score > 0).length).toString(), change: "+8 pts", trend: "up", icon: Shield, color: "text-success" },
  { label: "Critical Risks Open", value: domains.reduce((a, b) => a + b.criticalCount, 0).toString(), change: "Needs attention", trend: "down", icon: AlertTriangle, color: "text-critical" },
  { label: "30-Day Trend", value: "+12%", change: "Improving", trend: "up", icon: TrendingUp, color: "text-nanz-400" },
];


const activityIcons: Record<string, any> = {
  alert: AlertTriangle,
  check: CheckCircle2,
  "trending-up": TrendingUp,
  shield: Shield,
  "user-plus": UserPlus,
  share: Share2,
};

export default function DashboardPage() {
  const token = useAuthStore((state) => state.token);
  const [user, setUser] = useState<{name: string, email: string} | null>(null);
  const [domains, setDomains] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      Promise.all([
        getCurrentUser(token),
        getDomains(token).catch(() => []) // fallback to empty if domains fail
      ]).then(([userData, domainsData]) => {
        setUser(userData);
        setDomains(Array.isArray(domainsData) ? domainsData : []);
      }).finally(() => {
        setLoading(false);
      });
    }
  }, [token]);

  if (loading || !user) {
    return <div className="h-64 flex items-center justify-center"><Loader2 className="w-8 h-8 text-text-muted animate-spin" /></div>;
  }

  const metricCards = [
    { label: "Domains Monitored", value: domains.length.toString(), change: "Active", trend: "up", icon: Globe, color: "text-nanz-400" },
    { label: "Avg Security Score", value: "85", change: "+8 pts", trend: "up", icon: Shield, color: "text-success" },
    { label: "Critical Risks Open", value: "2", change: "Needs attention", trend: "down", icon: AlertTriangle, color: "text-critical" },
    { label: "30-Day Trend", value: "+12%", change: "Improving", trend: "up", icon: TrendingUp, color: "text-nanz-400" },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-headline text-text-primary">
            Welcome back, {user.name.split(" ")[0]}
          </h1>
          <p className="text-text-secondary mt-1">NANZ Security Command Center</p>
        </div>
        <Link href="/" className="px-4 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity flex items-center gap-2">
          Scan Domain <ExternalLink className="w-3.5 h-3.5" />
        </Link>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {metricCards.map((card) => (
          <div key={card.label} className="rounded-card border border-card-border bg-card p-5 hover:bg-card-hover hover:border-surface-border-light transition-all group">
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-medium text-text-muted uppercase tracking-wider">{card.label}</span>
              <card.icon className={cn("w-4 h-4", card.color)} />
            </div>
            <div className="text-3xl font-bold text-text-primary">{card.value}</div>
            <div className="flex items-center gap-1 mt-2">
              {card.trend === "up" ? (
                <ArrowUpRight className="w-3.5 h-3.5 text-success" />
              ) : (
                <ArrowDownRight className="w-3.5 h-3.5 text-critical" />
              )}
              <span className={cn("text-xs", card.trend === "up" ? "text-success" : "text-critical")}>{card.change}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Score Trend */}
        <div className="lg:col-span-2 rounded-card border border-card-border bg-card p-6">
          <h3 className="text-sm font-semibold text-text-primary mb-1">Security Score Trend</h3>
          <p className="text-xs text-text-muted mb-6">NANZ Risk Score over time</p>
          <div className="h-[240px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={scoreHistory}>
                <defs>
                  <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0A8CFF" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#0A8CFF" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="clientGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FF6B6B" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#FF6B6B" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" axisLine={false} tickLine={false} tick={{ fill: "#5C5C6F", fontSize: 12 }} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: "#5C5C6F", fontSize: 12 }} domain={[0, 100]} />
                <Tooltip
                  contentStyle={{ background: "#0A0A0C", border: "1px solid #1E1E24", borderRadius: "8px", fontSize: "12px", color: "#F0F0F5" }}
                  labelStyle={{ color: "#8B8B9E" }}
                />
                <Area type="monotone" dataKey="nanz" stroke="#0A8CFF" fill="url(#scoreGrad)" strokeWidth={2} name="nanz.ai" />
                <Area type="monotone" dataKey="clientapp" stroke="#FF6B6B" fill="url(#clientGrad)" strokeWidth={2} name="clientapp.com" />
                <Area type="monotone" dataKey="api" stroke="#38BDF8" fill="none" strokeWidth={1.5} strokeDasharray="4 4" name="api.nanz.ai" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Findings by Severity */}
        <div className="rounded-card border border-card-border bg-card p-6">
          <h3 className="text-sm font-semibold text-text-primary mb-1">Findings by Severity</h3>
          <p className="text-xs text-text-muted mb-6">Current open findings</p>
          <div className="h-[200px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={mockSeverity} layout="vertical" barSize={18}>
                <XAxis type="number" axisLine={false} tickLine={false} tick={{ fill: "#5C5C6F", fontSize: 12 }} />
                <YAxis type="category" dataKey="name" axisLine={false} tickLine={false} tick={{ fill: "#8B8B9E", fontSize: 12 }} width={60} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {mockSeverity.map((entry, index) => (
                    <Cell key={index} fill={entry.color} fillOpacity={0.8} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-4 grid grid-cols-2 gap-3">
            {mockSeverity.map((s) => (
              <div key={s.name} className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: s.color }} />
                <span className="text-xs text-text-secondary">{s.name}: {s.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Activity Feed */}
        <div className="rounded-card border border-card-border bg-card p-6">
          <h3 className="text-sm font-semibold text-text-primary mb-5">Recent Activity</h3>
          <div className="space-y-4">
            {activityFeed.map((item) => {
              const Icon = activityIcons[item.icon] || Activity;
              return (
                <div key={item.id} className="flex items-start gap-3 group">
                  <div className="w-8 h-8 rounded-lg bg-surface flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Icon className="w-3.5 h-3.5 text-text-muted" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-text-primary font-medium">{item.action}</div>
                    <div className="text-xs text-text-muted mt-0.5 truncate">{item.detail}</div>
                  </div>
                  <span className="text-xs text-text-muted flex-shrink-0">{item.time}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Domain Health */}
        <div className="rounded-card border border-card-border bg-card p-6">
          <div className="flex items-center justify-between mb-5">
            <h3 className="text-sm font-semibold text-text-primary">Domain Health</h3>
            <Link href="/dashboard/assets" className="text-xs text-nanz-400 hover:text-nanz-300 transition-colors">View all →</Link>
          </div>
          <div className="space-y-3">
            {domains.length === 0 ? (
              <div className="text-sm text-text-muted text-center py-6">No domains added yet.</div>
            ) : domains.slice(0, 5).map((domain) => (
              <div key={domain.id} className="flex items-center gap-4 p-3 rounded-btn bg-surface hover:bg-surface-hover transition-colors group">
                <div className="w-10 h-10 rounded-lg flex items-center justify-center text-sm font-bold bg-nanz-600/10 text-nanz-400">
                  <Globe className="w-5 h-5" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-text-primary truncate">{domain.domain_name}</div>
                  <div className="text-xs text-text-muted">
                    Status: {domain.status}
                  </div>
                </div>
                <div className="px-2 py-1 rounded text-xs font-medium bg-nanz-600/10 text-nanz-400">
                  {domain.monitoring_frequency || "weekly"}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
