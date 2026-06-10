"use client";

import { cn } from "@/lib/utils";
import { Globe, Plus, Search, MoreHorizontal, Play, History, Settings, Trash2, CheckCircle2, Clock, AlertCircle, Loader2, X, TrendingUp, TrendingDown, Minus } from "lucide-react";
import { EmptyState } from "@/components/ui/EmptyState";
import { useState, useEffect, useMemo } from "react";
import { getDomains, createDomain, listScans } from "@/lib/api";
import { useAuthStore } from "@/store/authStore";

const statusConfig = {
  verified: { label: "Verified", icon: CheckCircle2, cls: "bg-success/10 text-success border-success/20" },
  pending: { label: "Pending", icon: Clock, cls: "bg-medium/10 text-medium border-medium/20" },
  unverified: { label: "Unverified", icon: AlertCircle, cls: "bg-gray-600/10 text-gray-400 border-gray-600/20" },
};

export default function AssetsPage() {
  const [search, setSearch] = useState("");
  const token = useAuthStore((state) => state.token);
  const [domains, setDomains] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  
  const [showAddModal, setShowAddModal] = useState(false);
  const [newDomain, setNewDomain] = useState("");
  const [adding, setAdding] = useState(false);

  useEffect(() => {
    if (token) {
      Promise.all([
        getDomains(token).catch(() => []),
        listScans(500, 0).catch(() => ({ scans: [] }))
      ]).then(([domainsData, scansData]) => {
        setDomains(Array.isArray(domainsData) ? domainsData : []);
        setScans(scansData.scans || []);
      }).finally(() => {
        setLoading(false);
      });
    }
  }, [token]);

  const domainScores = useMemo(() => {
    const map: Record<string, { latestScore: number | null, trend: number | null }> = {};
    for (const d of domains) {
      const dName = d.domain_name;
      const domainScans = scans
        .filter(s => s.domain === dName && s.status === 'complete')
        .sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime());
      
      const latest = domainScans[0];
      const previous = domainScans[1];

      map[dName] = {
        latestScore: latest?.overall_score ?? null,
        trend: (latest?.overall_score != null && previous?.overall_score != null) 
          ? (latest.overall_score - previous.overall_score) 
          : null,
      };
    }
    return map;
  }, [domains, scans]);

  function scoreBarColor(score: number): string {
    if (score > 70) return '#22C55E';
    if (score >= 50) return '#F59E0B';
    return '#EF4444';
  }

  const handleAddDomain = async () => {
    if (!newDomain.trim() || !token) return;
    setAdding(true);
    try {
      await createDomain(token, newDomain.trim());
      const data = await getDomains(token);
      setDomains(Array.isArray(data) ? data : []);
      setShowAddModal(false);
      setNewDomain("");
    } catch (err) {
      console.error("Failed to add domain", err);
      alert("Failed to add domain. Please try again.");
    } finally {
      setAdding(false);
    }
  };

  const filtered = domains.filter(d => (d.domain_name || "").toLowerCase().includes(search.toLowerCase()));

  if (loading) {
    return <div className="h-64 flex items-center justify-center"><Loader2 className="w-8 h-8 text-text-muted animate-spin" /></div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-title text-text-primary">Assets</h1>
          <p className="text-sm text-text-secondary mt-1">{domains.length} domains in your workspace</p>
        </div>
        <button 
          onClick={() => setShowAddModal(true)}
          className="px-4 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity flex items-center gap-2"
        >
          <Plus className="w-4 h-4" /> Add Domain
        </button>
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search domains..."
          className="w-full pl-11 pr-4 py-2.5 rounded-btn bg-surface border border-surface-border text-sm text-text-primary placeholder:text-text-muted focus:border-nanz-500 focus:ring-1 focus:ring-nanz-500/30 outline-none transition-all"
        />
      </div>

      {/* Table */}
      <div className="rounded-card border border-card-border bg-card overflow-hidden">
        <div className="grid grid-cols-[1fr_120px_80px_100px_140px_48px] gap-4 px-5 py-3 border-b border-surface-border text-xs font-medium text-text-muted uppercase tracking-wider">
          <span>Domain</span><span>Status</span><span>Score</span><span>Monitoring</span><span>Last Scan</span><span />
        </div>
        {filtered.length === 0 ? (
          <div className="p-8 text-center text-text-muted">No domains found. Add a domain to get started.</div>
        ) : filtered.map((domain) => {
          const status = statusConfig[domain.status as keyof typeof statusConfig] || statusConfig.unverified;
          const info = domainScores[domain.domain_name] || { latestScore: null, trend: null };
          return (
            <div key={domain.id} className="grid grid-cols-[1fr_120px_80px_100px_140px_48px] gap-4 px-5 py-4 border-b border-surface-border last:border-b-0 hover:bg-surface-hover/50 transition-colors items-center">
              <div className="flex items-center gap-3 min-w-0">
                <Globe className="w-4 h-4 text-text-muted flex-shrink-0" />
                <span className="text-sm font-medium text-text-primary truncate">{domain.domain_name}</span>
              </div>
              <div>
                <span className={cn("inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium border", status.cls)}>
                  <status.icon className="w-3 h-3" /> {status.label}
                </span>
              </div>
              <div className={cn("text-sm font-bold", info.latestScore != null ? "" : "text-text-muted")} style={info.latestScore != null ? { color: scoreBarColor(info.latestScore) } : {}}>
                {info.latestScore != null ? (
                  <div className="flex items-center gap-1.5">
                    <span>{info.latestScore}</span>
                    {info.trend != null ? (
                      info.trend > 0 ? <span title={`+${info.trend} from last scan`}><TrendingUp className="w-3.5 h-3.5 text-success" /></span> : 
                      info.trend < 0 ? <span title={`${info.trend} from last scan`}><TrendingDown className="w-3.5 h-3.5 text-critical" /></span> : 
                      <span title="No change from last scan"><Minus className="w-3.5 h-3.5 text-text-muted" /></span>
                    ) : null}
                  </div>
                ) : "—"}
              </div>
              <div className="text-xs text-text-secondary capitalize">{domain.monitoring_frequency || "weekly"}</div>
              <div className="text-xs text-text-muted">{domain.created_at ? new Date(domain.created_at).toLocaleDateString() : "Never"}</div>
              <button className="p-1.5 rounded hover:bg-surface transition-colors text-text-muted hover:text-text-secondary">
                <MoreHorizontal className="w-4 h-4" />
              </button>
            </div>
          );
        })}
      </div>

      {/* Add Domain Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm">
          <div className="bg-card border border-card-border rounded-xl shadow-2xl max-w-md w-full overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between p-5 border-b border-surface-border">
              <h2 className="text-lg font-semibold text-text-primary">Add New Domain</h2>
              <button 
                onClick={() => setShowAddModal(false)}
                className="text-text-muted hover:text-text-primary transition-colors p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="p-5 space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium text-text-secondary">Domain Name</label>
                <input
                  type="text"
                  placeholder="e.g., example.com"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  className="w-full px-4 py-2.5 rounded-btn bg-surface border border-surface-border text-sm text-text-primary placeholder:text-text-muted focus:border-nanz-500 focus:ring-1 focus:ring-nanz-500/30 outline-none transition-all"
                  autoFocus
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleAddDomain();
                  }}
                />
              </div>
              <p className="text-xs text-text-muted leading-relaxed">
                Enter the root domain you want to monitor. We will automatically verify ownership and begin asset discovery.
              </p>
            </div>

            <div className="p-5 border-t border-surface-border bg-surface/50 flex justify-end gap-3">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2.5 text-sm font-medium text-text-secondary hover:text-text-primary transition-colors"
                disabled={adding}
              >
                Cancel
              </button>
              <button
                onClick={handleAddDomain}
                disabled={!newDomain.trim() || adding}
                className="px-5 py-2.5 rounded-btn bg-nanz-gradient text-white text-sm font-medium hover:opacity-90 transition-opacity flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {adding && <Loader2 className="w-4 h-4 animate-spin" />}
                {adding ? 'Adding...' : 'Add Domain'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
