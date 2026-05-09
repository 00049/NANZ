"use client";

import { useEffect, useState, useMemo } from "react";
import { cn } from "@/lib/utils";
import { Shield, Globe, AlertTriangle, TrendingUp, TrendingDown, Minus, Activity, CheckCircle2, ExternalLink, Loader2, ArrowRight, Clock, Plus } from "lucide-react";
import Link from "next/link";
import { useAuthStore } from "@/store/authStore";
import { getCurrentUser, getDomains, listScans } from "@/lib/api";

type ScanItem = {
  id: string;
  domain: string;
  url: string;
  status: string;
  scan_type: string;
  created_at: string | null;
  completed_at: string | null;
  scan_duration_ms: number | null;
  overall_score?: number;
};

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return 'Never';
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return `${Math.floor(days / 7)}w ago`;
}

function getScoreInfo(score: number | null | undefined) {
  if (score == null) return { label: 'NOT SCANNED', color: '#6B7280' };
  if (score > 70) return { label: 'SECURE', color: '#22C55E' };
  if (score >= 50) return { label: 'AT RISK', color: '#F59E0B' };
  return { label: 'HIGH RISK', color: '#EF4444' };
}

function getStatusDotInfo(lastScan: string | null, score: number | null | undefined) {
  if (!lastScan) return { color: '#6B7280', pulse: false };
  const hoursSince = (Date.now() - new Date(lastScan).getTime()) / 3_600_000;
  if (hoursSince > 168) return { color: '#6B7280', pulse: false };
  if (score == null) return { color: '#6B7280', pulse: false };
  if (score > 70) return { color: '#22C55E', pulse: hoursSince < 24 };
  if (score >= 50) return { color: '#F59E0B', pulse: false };
  return { color: '#EF4444', pulse: false };
}

function scoreBarColor(score: number): string {
  if (score > 70) return '#22C55E';
  if (score >= 50) return '#F59E0B';
  return '#EF4444';
}

function statusDotColor(status: string): string {
  if (status === 'complete') return '#22C55E';
  if (status === 'failed') return '#EF4444';
  if (status === 'running') return '#00A8FF';
  return '#6B7280';
}

export default function DashboardPage() {
  const token = useAuthStore((state) => state.token);
  const [user, setUser] = useState<{name: string, email: string} | null>(null);
  const [domains, setDomains] = useState<any[]>([]);
  const [scans, setScans] = useState<ScanItem[]>([]);
  const [totalScans, setTotalScans] = useState(0);
  const [loading, setLoading] = useState(true);
  const [showAllDomains, setShowAllDomains] = useState(false);

  const INITIAL_DOMAIN_LIMIT = 5;

  useEffect(() => {
    if (token) {
      Promise.all([
        getCurrentUser(token),
        getDomains(token).catch(() => []),
        listScans(50, 0).catch(() => ({ scans: [], total: 0 }))
      ]).then(([userData, domainsData, scansData]) => {
        setUser(userData);
        setDomains(Array.isArray(domainsData) ? domainsData : []);
        setScans(scansData.scans || []);
        setTotalScans(scansData.total || 0);
      }).finally(() => {
        setLoading(false);
      });
    }
  }, [token]);

  // Compute latest scan + score per domain
  const domainScores = useMemo(() => {
    const map: Record<string, { score: number | null; lastScan: string | null }> = {};
    for (const domain of domains) {
      const domainName = domain.domain_name;
      const latestScan = scans
        .filter(s => s.domain === domainName && s.status === 'complete')
        .sort((a, b) =>
          new Date(b.created_at || 0).getTime() -
          new Date(a.created_at || 0).getTime()
        )[0];
      map[domainName] = {
        score: latestScan?.overall_score ?? null,
        lastScan: latestScan?.completed_at || latestScan?.created_at || null,
      };
    }
    return map;
  }, [domains, scans]);

  // Average score for header
  const avgScore = useMemo(() => {
    const scores = Object.values(domainScores)
      .map(d => d.score)
      .filter((s): s is number => s != null);
    if (scores.length === 0) return null;
    return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  }, [domainScores]);

  // Latest scan + previous scan for delta calculation
  const latestScan = scans.length > 0 ? scans[0] : null;
  const previousScan = useMemo(() => {
    if (!latestScan) return null;
    return scans
      .filter(s => s.domain === latestScan.domain && s.id !== latestScan.id && s.status === 'complete')
      .sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime())[0] || null;
  }, [scans, latestScan]);

  const scoreDelta = useMemo(() => {
    if (!latestScan?.overall_score) return null;
    if (!previousScan?.overall_score) return null;
    return latestScan.overall_score - previousScan.overall_score;
  }, [latestScan, previousScan]);

  // This week's scans
  const scansThisWeek = useMemo(() => {
    const weekAgo = Date.now() - 7 * 86_400_000;
    return scans.filter(s => s.created_at && new Date(s.created_at).getTime() >= weekAgo).length;
  }, [scans]);

  // Domains added this month
  const domainsThisMonth = useMemo(() => {
    const monthAgo = Date.now() - 30 * 86_400_000;
    return domains.filter((d: any) => d.created_at && new Date(d.created_at).getTime() >= monthAgo).length;
  }, [domains]);

  if (loading || !user) {
    return <div className="h-64 flex items-center justify-center"><Loader2 className="w-8 h-8 text-text-muted animate-spin" /></div>;
  }

  const visibleDomains = showAllDomains ? domains : domains.slice(0, INITIAL_DOMAIN_LIMIT);

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
        <Link href="/dashboard/new-scan" className="px-4 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity flex items-center gap-2">
          New Scan <ExternalLink className="w-3.5 h-3.5" />
        </Link>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Card 1: Domains Monitored */}
        <div className="rounded-card border border-card-border bg-card p-5 hover:bg-card-hover hover:border-surface-border-light transition-all">
          <div className="flex items-center justify-between mb-4">
            <span className="text-xs font-medium text-text-muted uppercase tracking-wider">Domains Monitored</span>
            <Globe className="w-4 h-4 text-nanz-400" />
          </div>
          <div className="text-3xl font-bold text-text-primary">{domains.length}</div>
          <div className="flex items-center gap-1 mt-2 text-xs text-text-secondary">
            {domains.length === 0 ? (
              <Link href="/dashboard/assets" className="text-nanz-400 hover:text-nanz-300 transition-colors">Add domain →</Link>
            ) : domainsThisMonth > 0 ? (
              <span style={{ color: '#22C55E' }}>+{domainsThisMonth} added this month</span>
            ) : (
              <span>Active</span>
            )}
          </div>
        </div>

        {/* Card 2: Total Scans Run */}
        <div className="rounded-card border border-card-border bg-card p-5 hover:bg-card-hover hover:border-surface-border-light transition-all">
          <div className="flex items-center justify-between mb-4">
            <span className="text-xs font-medium text-text-muted uppercase tracking-wider">Total Scans Run</span>
            <Activity className="w-4 h-4 text-success" />
          </div>
          <div className="text-3xl font-bold text-text-primary">{totalScans}</div>
          <div className="flex items-center gap-1 mt-2 text-xs text-text-secondary">
            <span>{scansThisWeek} this week</span>
          </div>
        </div>

        {/* Card 3: Latest Scan — with delta */}
        <div className="rounded-card border border-card-border bg-card p-5 hover:bg-card-hover hover:border-surface-border-light transition-all">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium text-text-muted uppercase tracking-wider">Latest Scan</span>
            <Shield className={cn("w-4 h-4", latestScan?.status === 'complete' ? "text-success" : "text-amber-500")} />
          </div>

          {!latestScan ? (
            <div>
              <p className="text-sm font-semibold text-text-primary mb-1">No scans yet</p>
              <p className="text-xs text-text-muted mb-3">Run your first scan to see results</p>
              <Link href="/dashboard/new-scan" className="text-xs font-semibold text-nanz-400 hover:text-nanz-300">New Scan →</Link>
            </div>
          ) : (
            <>
              <div className="text-sm font-semibold text-text-primary truncate">{latestScan.domain}</div>
              <div className="flex items-center gap-1.5 mt-1">
                <span className="relative flex w-2 h-2">
                  {latestScan.status === 'running' && <span className="absolute inset-0 rounded-full animate-ping" style={{ backgroundColor: statusDotColor(latestScan.status), opacity: 0.75 }} />}
                  <span className="relative w-2 h-2 rounded-full inline-flex" style={{ backgroundColor: statusDotColor(latestScan.status) }} />
                </span>
                <span className="text-xs capitalize" style={{ color: statusDotColor(latestScan.status) }}>{latestScan.status}</span>
              </div>

              <div className="my-2.5" style={{ borderTop: '1px solid #1E1E1E' }} />

              {/* Score + delta */}
              <div className="flex items-center justify-between">
                <span className="text-lg font-bold text-text-primary">
                  Score: {latestScan.overall_score ?? '—'}
                </span>
                {latestScan.overall_score != null && (
                  <span className="flex items-center gap-1 text-xs font-medium">
                    {scoreDelta != null ? (
                      scoreDelta > 0 ? (
                        <><TrendingUp className="w-3.5 h-3.5" style={{ color: '#22C55E' }} /><span style={{ color: '#22C55E' }}>+{scoreDelta} from last scan</span></>
                      ) : scoreDelta < 0 ? (
                        <><TrendingDown className="w-3.5 h-3.5" style={{ color: '#EF4444' }} /><span style={{ color: '#EF4444' }}>{scoreDelta} from last scan</span></>
                      ) : (
                        <><Minus className="w-3.5 h-3.5" style={{ color: '#6B7280' }} /><span style={{ color: '#6B7280' }}>No change</span></>
                      )
                    ) : (
                      <span style={{ color: '#6B7280' }}>First scan</span>
                    )}
                  </span>
                )}
              </div>

              {/* Mini progress bar */}
              {latestScan.overall_score != null && (
                <div className="w-full h-1 rounded-sm mt-2" style={{ backgroundColor: '#1E1E1E' }}>
                  <div className="h-full rounded-sm transition-all duration-500" style={{ width: `${Math.min(latestScan.overall_score, 100)}%`, backgroundColor: scoreBarColor(latestScan.overall_score) }} />
                </div>
              )}

              {/* Timestamp + previous */}
              <div className="flex items-center gap-1 mt-2.5 text-[11px]" style={{ color: '#6B7280' }}>
                <span>{timeAgo(latestScan.completed_at || latestScan.created_at)}</span>
                {previousScan && (
                  <>
                    <span>·</span>
                    <span>Previous: {previousScan.status === 'complete' ? '✓' : '✗'} <span className="capitalize">{previousScan.status}</span></span>
                  </>
                )}
              </div>
            </>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent Scans Feed */}
        <div className="rounded-card border border-card-border bg-card p-6 flex flex-col min-h-[400px]">
          <div className="flex items-center justify-between mb-5">
            <h3 className="text-sm font-semibold text-text-primary">Recent Scans</h3>
            <Link href="/dashboard/history" className="text-xs text-nanz-400 hover:text-nanz-300 transition-colors">View history →</Link>
          </div>
          <div className="space-y-3 flex-1 overflow-y-auto pr-2 custom-scrollbar">
            {scans.length === 0 ? (
              <div className="text-sm text-text-muted text-center py-6 border border-dashed border-surface-border rounded-lg">No scans run yet.</div>
            ) : scans.slice(0, 10).map((scan) => {
              return (
                <Link key={scan.id} href={`/report/${scan.id}`} className="block">
                  <div className="flex items-center justify-between p-3 rounded-btn bg-surface hover:bg-surface-hover transition-colors group border border-transparent hover:border-surface-border">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0", scan.status === 'complete' ? 'bg-success/10 text-success' : scan.status === 'failed' ? 'bg-critical/10 text-critical' : 'bg-amber-500/10 text-amber-500')}>
                        {scan.status === 'complete' ? <CheckCircle2 className="w-4 h-4" /> : scan.status === 'failed' ? <AlertTriangle className="w-4 h-4" /> : <Activity className="w-4 h-4" />}
                      </div>
                      <div className="min-w-0">
                        <div className="text-sm font-medium text-text-primary truncate flex items-center gap-1">
                          {scan.domain}
                          <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity text-nanz-400" />
                        </div>
                        <div className="text-xs text-text-muted capitalize">
                          {scan.status} • {scan.created_at ? new Date(scan.created_at).toLocaleDateString() : 'Unknown'}
                        </div>
                      </div>
                    </div>
                  </div>
                </Link>
              );
            })}
          </div>
        </div>

        {/* Domain Health */}
        <div className="rounded-card border border-card-border bg-card p-6 flex flex-col min-h-[400px]">
          <div className="flex items-center justify-between mb-5">
            <h3 className="text-sm font-semibold text-text-primary">Domain Health</h3>
            <div className="flex items-center gap-3">
              {avgScore != null && (
                <span className="text-xs font-semibold" style={{ color: getScoreInfo(avgScore).color }}>
                  Avg score: {avgScore}
                </span>
              )}
              <Link href="/dashboard/assets" className="text-xs text-nanz-400 hover:text-nanz-300 transition-colors">Manage →</Link>
            </div>
          </div>
          <div className="space-y-2 flex-1 overflow-y-auto pr-2 custom-scrollbar">
            {domains.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <Globe className="w-8 h-8 mb-3" style={{ color: '#2A2A2A' }} />
                <p className="text-sm font-semibold text-text-primary mb-1">No domains monitored yet</p>
                <p className="text-xs text-text-muted mb-4">Add a domain to track security over time</p>
                <Link href="/dashboard/assets" className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold border transition-colors" style={{ color: '#00A8FF', borderColor: '#00A8FF' }}>
                  <Plus className="w-3.5 h-3.5" /> Add Domain
                </Link>
              </div>
            ) : visibleDomains.map((domain) => {
              const info = domainScores[domain.domain_name] || { score: null, lastScan: null };
              const scoreInfo = getScoreInfo(info.score);
              const dotInfo = getStatusDotInfo(info.lastScan, info.score);
              return (
                <Link key={domain.id} href={`/dashboard/assets`} className="block">
                  <div className="flex items-center gap-4 p-3 rounded-btn bg-surface group border border-transparent hover:border-surface-border transition-colors cursor-pointer" onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = '#161616')} onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = '')}>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span style={{ position: 'relative', display: 'inline-flex', width: '8px', height: '8px', flexShrink: 0 }}>
                          {dotInfo.pulse && <span style={{ position: 'absolute', inset: 0, borderRadius: '50%', backgroundColor: dotInfo.color, opacity: 0.75, animation: 'domainPulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite' }} />}
                          <span style={{ position: 'relative', width: '8px', height: '8px', borderRadius: '50%', backgroundColor: dotInfo.color, display: 'inline-flex' }} />
                        </span>
                        <span className="text-[13px] font-semibold text-text-primary truncate">{domain.domain_name}</span>
                      </div>
                      <div className="flex items-center gap-1 ml-4">
                        <Clock className="w-2.5 h-2.5 text-text-muted" />
                        <span className="text-[11px] text-text-muted">Last scan: {timeAgo(info.lastScan)}</span>
                      </div>
                    </div>
                    <div className="flex flex-col items-end gap-1" style={{ width: '100px' }}>
                      {info.score != null ? (
                        <>
                          <span className="text-lg font-bold" style={{ color: scoreInfo.color }}>{info.score}</span>
                          <div className="w-full h-1.5 rounded-sm" style={{ backgroundColor: '#1E1E1E' }}>
                            <div className="h-full rounded-sm transition-all duration-500" style={{ width: `${Math.min(info.score, 100)}%`, backgroundColor: scoreInfo.color }} />
                          </div>
                          <span className="text-[10px] font-bold uppercase" style={{ color: scoreInfo.color }}>{scoreInfo.label}</span>
                        </>
                      ) : (
                        <>
                          <span className="text-lg font-bold" style={{ color: '#6B7280' }}>—</span>
                          <div className="w-full h-1.5 rounded-sm" style={{ backgroundColor: '#1E1E1E' }} />
                          <Link href={`/dashboard/new-scan?url=${encodeURIComponent(domain.domain_name)}`} className="text-[11px] font-semibold transition-opacity hover:opacity-80" style={{ color: '#00A8FF' }} onClick={(e) => e.stopPropagation()}>Scan Now →</Link>
                        </>
                      )}
                    </div>
                  </div>
                </Link>
              );
            })}
          </div>

          {domains.length > INITIAL_DOMAIN_LIMIT && (
            <Link href="/dashboard/assets" className="block w-full text-center py-2 mt-2 text-xs font-medium transition-colors" style={{ color: '#00A8FF' }}>
              View all {domains.length} domains →
            </Link>
          )}

          <style jsx>{`
            @keyframes domainPulse {
              0%, 100% { transform: scale(1); opacity: 0.75; }
              50% { transform: scale(2.5); opacity: 0; }
            }
          `}</style>
        </div>
      </div>
    </div>
  );
}
