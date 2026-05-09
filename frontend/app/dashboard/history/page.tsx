"use client";

import { useState, useEffect, useMemo, useCallback } from "react";
import { cn } from "@/lib/utils";
import {
  Search, Download, Loader2, RefreshCw, ExternalLink, History,
  SearchX, X, ChevronLeft, ChevronRight, CheckCircle2, AlertTriangle,
  Activity, Clock, Plus, Filter,
} from "lucide-react";
import Link from "next/link";
import { listScans } from "@/lib/api";

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
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  info_count?: number;
  total_findings?: number;
};

const PAGE_SIZES = [10, 25, 50, 100];
const STATUSES = ["complete", "running", "failed", "pending"];
const DATE_PRESETS = [
  { label: "Today", days: 1 },
  { label: "Last 7 days", days: 7 },
  { label: "Last 30 days", days: 30 },
  { label: "Last 3 months", days: 90 },
  { label: "All time", days: 0 },
];

function statusBadge(status: string) {
  if (status === "complete") return "text-[#22C55E] bg-[#22C55E]/10 border-[#22C55E]/20";
  if (status === "running") return "text-[#00A8FF] bg-[#00A8FF]/10 border-[#00A8FF]/20";
  if (status === "failed") return "text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/20";
  return "text-[#6B7280] bg-[#6B7280]/10 border-[#6B7280]/20";
}

function statusIcon(status: string) {
  if (status === "complete") return <CheckCircle2 className="w-3 h-3" />;
  if (status === "running") return <Activity className="w-3 h-3 animate-pulse" />;
  if (status === "failed") return <AlertTriangle className="w-3 h-3" />;
  return <Clock className="w-3 h-3" />;
}

function formatDuration(ms: number | null): string {
  if (!ms) return "—";
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return "—";
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return `${Math.floor(days / 7)}w ago`;
}

function scoreColor(score: number | null | undefined): string {
  if (score == null) return "#6B7280";
  if (score > 70) return "#22C55E";
  if (score >= 50) return "#F59E0B";
  return "#EF4444";
}

function exportToCSV(scans: ScanItem[]) {
  const headers = [
    "Domain", "URL", "Status", "Score", "Critical", "High", "Medium",
    "Low", "Info", "Total Findings", "Duration (s)", "Scanned At",
  ];
  const rows = scans.map((s) => [
    s.domain, s.url, s.status, s.overall_score ?? "",
    s.critical_count ?? 0, s.high_count ?? 0, s.medium_count ?? 0,
    s.low_count ?? 0, s.info_count ?? 0, s.total_findings ?? 0,
    s.scan_duration_ms ? Math.round(s.scan_duration_ms / 1000) : "",
    s.created_at,
  ]);
  const csv = [headers, ...rows]
    .map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(","))
    .join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `shieldcheck-scans-${new Date().toISOString().split("T")[0]}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function HistoryPage() {
  const [allScans, setAllScans] = useState<ScanItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState("");

  // Filters
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string[]>([]);
  const [scoreRange, setScoreRange] = useState<string>("any");
  const [datePreset, setDatePreset] = useState<number>(30);
  const [statusDropdownOpen, setStatusDropdownOpen] = useState(false);
  const [scoreDropdownOpen, setScoreDropdownOpen] = useState(false);

  // Pagination
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  // Debounced search
  const [debouncedSearch, setDebouncedSearch] = useState("");
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 300);
    return () => clearTimeout(t);
  }, [search]);

  const fetchScans = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await listScans(500, 0);
      setAllScans(data.scans || []);
      setTotal(data.total || 0);
    } catch (e: any) {
      setError(e.message || "Failed to load scan history.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchScans(); }, [fetchScans]);

  // Apply filters
  const filtered = useMemo(() => {
    let list = [...allScans];

    // Search
    if (debouncedSearch) {
      const q = debouncedSearch.toLowerCase();
      list = list.filter((s) => s.domain.toLowerCase().includes(q) || s.url.toLowerCase().includes(q));
    }

    // Status
    if (statusFilter.length > 0) {
      list = list.filter((s) => statusFilter.includes(s.status));
    }

    // Score range
    if (scoreRange === "critical") list = list.filter((s) => s.overall_score != null && s.overall_score < 50);
    else if (scoreRange === "medium") list = list.filter((s) => s.overall_score != null && s.overall_score >= 50 && s.overall_score < 70);
    else if (scoreRange === "low") list = list.filter((s) => s.overall_score != null && s.overall_score >= 70);

    // Date range
    if (datePreset > 0) {
      const cutoff = Date.now() - datePreset * 86_400_000;
      list = list.filter((s) => s.created_at && new Date(s.created_at).getTime() >= cutoff);
    }

    return list;
  }, [allScans, debouncedSearch, statusFilter, scoreRange, datePreset]);

  // Pagination
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safeP = Math.min(page, totalPages);
  const pageData = filtered.slice((safeP - 1) * pageSize, safeP * pageSize);
  const showStart = filtered.length > 0 ? (safeP - 1) * pageSize + 1 : 0;
  const showEnd = Math.min(safeP * pageSize, filtered.length);

  useEffect(() => { setPage(1); }, [debouncedSearch, statusFilter, scoreRange, datePreset, pageSize]);

  // Stats
  const completeCount = filtered.filter((s) => s.status === "complete").length;
  const failedCount = filtered.filter((s) => s.status === "failed").length;
  const scoresArr = filtered.map((s) => s.overall_score).filter((s): s is number => s != null);
  const avgScore = scoresArr.length > 0 ? Math.round(scoresArr.reduce((a, b) => a + b, 0) / scoresArr.length) : null;

  // Active filter count
  const activeFilterCount = [
    statusFilter.length > 0, scoreRange !== "any", datePreset !== 0, debouncedSearch !== "",
  ].filter(Boolean).length;

  const clearFilters = () => {
    setSearch(""); setStatusFilter([]); setScoreRange("any"); setDatePreset(0);
  };

  const handleExport = () => {
    setExporting(true);
    setTimeout(() => { exportToCSV(filtered); setExporting(false); }, 300);
  };

  // Pagination buttons
  const pageButtons = () => {
    const btns: (number | "...")[] = [];
    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i++) btns.push(i);
    } else {
      btns.push(1);
      if (safeP > 3) btns.push("...");
      for (let i = Math.max(2, safeP - 1); i <= Math.min(totalPages - 1, safeP + 1); i++) btns.push(i);
      if (safeP < totalPages - 2) btns.push("...");
      btns.push(totalPages);
    }
    return btns;
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-title text-text-primary">Scan History</h1>
          <p className="text-sm text-text-secondary mt-1">{loading ? "Loading…" : `${total} scans total`}</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={fetchScans} disabled={loading} className="px-3 py-2 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors" style={{ backgroundColor: '#111111', border: '1px solid #1E1E1E', color: '#FFFFFF' }}>
            <RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} /> Refresh
          </button>
          <Link href="/dashboard/new-scan" className="px-3 py-2 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors" style={{ background: 'linear-gradient(135deg, #00A8FF, #0070CC)', color: '#FFFFFF' }}>
            <Plus className="w-3.5 h-3.5" /> New Scan
          </Link>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="rounded-xl p-3 flex flex-wrap items-center gap-2" style={{ backgroundColor: '#111111', border: '1px solid #1E1E1E' }}>
        {/* Date preset */}
        <div className="flex items-center gap-1">
          {DATE_PRESETS.map((p) => (
            <button key={p.label} onClick={() => setDatePreset(p.days)} className="px-2.5 py-1.5 rounded-md text-[11px] font-medium transition-colors" style={{ backgroundColor: datePreset === p.days ? '#00A8FF' : 'transparent', color: datePreset === p.days ? '#FFFFFF' : '#6B7280', border: datePreset === p.days ? 'none' : '1px solid transparent' }}>
              {p.label}
            </button>
          ))}
        </div>

        <div className="w-px h-6" style={{ backgroundColor: '#1E1E1E' }} />

        {/* Status filter */}
        <div className="relative">
          <button onClick={() => { setStatusDropdownOpen(!statusDropdownOpen); setScoreDropdownOpen(false); }} className="px-2.5 py-1.5 rounded-md text-[11px] font-medium flex items-center gap-1 transition-colors" style={{ border: '1px solid #1E1E1E', color: statusFilter.length > 0 ? '#00A8FF' : '#6B7280' }}>
            Status: {statusFilter.length === 0 ? "All" : statusFilter.join(", ")} ▾
          </button>
          {statusDropdownOpen && (
            <div className="absolute top-full left-0 mt-1 w-40 rounded-lg p-2 z-50 shadow-xl" style={{ backgroundColor: '#111111', border: '1px solid #1E1E1E' }}>
              {STATUSES.map((s) => (
                <label key={s} className="flex items-center gap-2 px-2 py-1.5 rounded cursor-pointer hover:bg-white/5 text-[11px] capitalize" style={{ color: '#FFFFFF' }}>
                  <input type="checkbox" checked={statusFilter.includes(s)} onChange={(e) => setStatusFilter(e.target.checked ? [...statusFilter, s] : statusFilter.filter((x) => x !== s))} className="rounded" />
                  {s}
                </label>
              ))}
            </div>
          )}
        </div>

        {/* Score filter */}
        <div className="relative">
          <button onClick={() => { setScoreDropdownOpen(!scoreDropdownOpen); setStatusDropdownOpen(false); }} className="px-2.5 py-1.5 rounded-md text-[11px] font-medium flex items-center gap-1 transition-colors" style={{ border: '1px solid #1E1E1E', color: scoreRange !== "any" ? '#00A8FF' : '#6B7280' }}>
            Score: {scoreRange === "any" ? "Any" : scoreRange === "critical" ? "0–49" : scoreRange === "medium" ? "50–69" : "70–100"} ▾
          </button>
          {scoreDropdownOpen && (
            <div className="absolute top-full left-0 mt-1 w-48 rounded-lg p-2 z-50 shadow-xl" style={{ backgroundColor: '#111111', border: '1px solid #1E1E1E' }}>
              {[{ v: "any", l: "Any score" }, { v: "critical", l: "Critical risk (0–49)" }, { v: "medium", l: "Medium risk (50–69)" }, { v: "low", l: "Low risk (70–100)" }].map((o) => (
                <button key={o.v} onClick={() => { setScoreRange(o.v); setScoreDropdownOpen(false); }} className="block w-full text-left px-2 py-1.5 rounded text-[11px] hover:bg-white/5 transition-colors" style={{ color: scoreRange === o.v ? '#00A8FF' : '#FFFFFF' }}>
                  {scoreRange === o.v ? "● " : "○ "}{o.l}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Search */}
        <div className="relative flex-1 min-w-[160px] max-w-[260px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: '#6B7280' }} />
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search domains..." className="w-full pl-8 pr-7 py-1.5 rounded-md text-[11px] outline-none transition-colors" style={{ backgroundColor: '#0A0A0A', border: '1px solid #1E1E1E', color: '#FFFFFF' }} />
          {search && <button onClick={() => setSearch("")} className="absolute right-2 top-1/2 -translate-y-1/2" style={{ color: '#6B7280' }}><X className="w-3 h-3" /></button>}
        </div>

        <div className="flex-1" />

        {/* Filter count + clear */}
        {activeFilterCount > 0 && (
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold" style={{ backgroundColor: '#00A8FF', color: '#FFFFFF' }}>{activeFilterCount} filter{activeFilterCount > 1 ? "s" : ""}</span>
            <button onClick={clearFilters} className="text-[11px] font-medium underline" style={{ color: '#00A8FF' }}>Clear all</button>
          </div>
        )}

        {/* Export */}
        <button onClick={handleExport} disabled={loading || filtered.length === 0 || exporting} className="px-3 py-1.5 rounded-md text-[11px] font-medium flex items-center gap-1.5 transition-colors disabled:opacity-40" style={{ border: '1px solid #2A2A2A', color: '#FFFFFF' }}>
          <Download className="w-3.5 h-3.5" /> {exporting ? "Exporting..." : "Export CSV"}
        </button>
      </div>

      {/* Summary row */}
      <div className="flex items-center justify-between px-1">
        <span className="text-[11px] font-medium" style={{ color: '#6B7280' }}>{filtered.length} scans found</span>
        <div className="flex items-center gap-4 text-[11px] font-medium">
          <span style={{ color: '#22C55E' }}>✓ {completeCount} complete</span>
          <span style={{ color: '#EF4444' }}>✗ {failedCount} failed</span>
          {avgScore != null && <span style={{ color: '#00A8FF' }}>⏱ Avg score: {avgScore}</span>}
        </div>
      </div>

      {error && <div className="rounded-lg px-4 py-3 text-sm" style={{ border: '1px solid rgba(239,68,68,0.3)', backgroundColor: 'rgba(239,68,68,0.1)', color: '#EF4444' }}>{error}</div>}

      {/* Table */}
      <div className="rounded-xl overflow-hidden" style={{ border: '1px solid #1E1E1E', backgroundColor: '#111111' }}>
        {/* Header */}
        <div className="grid grid-cols-[1fr_100px_70px_120px_70px_120px_90px] gap-2 px-4 py-2.5 text-[10px] font-bold uppercase tracking-widest" style={{ borderBottom: '1px solid #1E1E1E', color: '#6B7280' }}>
          <span>Domain</span><span>Status</span><span>Score</span><span>Findings</span><span>Duration</span><span>Scanned</span><span>Actions</span>
        </div>

        {loading ? (
          <div className="space-y-0">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="grid grid-cols-[1fr_100px_70px_120px_70px_120px_90px] gap-2 px-4 py-3.5" style={{ borderBottom: '1px solid #1E1E1E' }}>
                {Array.from({ length: 7 }).map((_, j) => (
                  <div key={j} className="h-4 rounded animate-pulse" style={{ backgroundColor: '#1E1E1E' }} />
                ))}
              </div>
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3">
            {allScans.length === 0 ? (
              <>
                <History className="w-10 h-10" style={{ color: '#2A2A2A' }} />
                <p className="text-sm font-semibold" style={{ color: '#FFFFFF' }}>No scans yet</p>
                <p className="text-xs" style={{ color: '#6B7280' }}>Run your first scan to see history here</p>
                <Link href="/dashboard/new-scan" className="px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 mt-2" style={{ background: 'linear-gradient(135deg, #00A8FF, #0070CC)', color: '#FFFFFF' }}>New Scan →</Link>
              </>
            ) : (
              <>
                <SearchX className="w-10 h-10" style={{ color: '#2A2A2A' }} />
                <p className="text-sm font-semibold" style={{ color: '#FFFFFF' }}>No scans match your filters</p>
                <button onClick={clearFilters} className="text-xs font-medium underline" style={{ color: '#00A8FF' }}>Clear all filters</button>
              </>
            )}
          </div>
        ) : (
          pageData.map((scan) => (
            <Link key={scan.id} href={`/report/${scan.id}`} className="grid grid-cols-[1fr_100px_70px_120px_70px_120px_90px] gap-2 px-4 py-3 items-center transition-colors cursor-pointer group" style={{ borderBottom: '1px solid #1E1E1E' }} onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = '#161616')} onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = '')}>
              <div className="min-w-0">
                <div className="text-[13px] font-medium truncate flex items-center gap-1" style={{ color: '#FFFFFF' }}>
                  {scan.domain}
                  <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" style={{ color: '#00A8FF' }} />
                </div>
                <div className="text-[11px] truncate" style={{ color: '#6B7280' }}>{scan.url}</div>
              </div>
              <div>
                <span className={cn("inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded border capitalize", statusBadge(scan.status))}>
                  {statusIcon(scan.status)} {scan.status}
                </span>
              </div>
              <div className="text-sm font-bold" style={{ color: scoreColor(scan.overall_score) }}>{scan.overall_score ?? "—"}</div>
              <div className="text-[11px]" style={{ color: '#9CA3AF' }}>
                {scan.total_findings != null ? `${scan.total_findings} total` : "—"}
              </div>
              <div className="text-[11px]" style={{ color: '#6B7280' }}>{formatDuration(scan.scan_duration_ms)}</div>
              <div className="text-[11px]" style={{ color: '#6B7280' }} title={scan.created_at || ""}>{timeAgo(scan.created_at)}</div>
              <div className="flex items-center gap-1">
                <span className="text-[10px] font-medium opacity-0 group-hover:opacity-100 transition-opacity" style={{ color: '#00A8FF' }}>View Report →</span>
              </div>
            </Link>
          ))
        )}
      </div>

      {/* Pagination */}
      {filtered.length > 0 && (
        <div className="flex items-center justify-between px-1 pt-1">
          <span className="text-[11px]" style={{ color: '#6B7280' }}>Showing {showStart}–{showEnd} of {filtered.length} scans</span>
          <div className="flex items-center gap-2">
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={safeP <= 1} className="p-1.5 rounded transition-colors disabled:opacity-30" style={{ color: '#FFFFFF' }}><ChevronLeft className="w-4 h-4" /></button>
            {pageButtons().map((b, i) => b === "..." ? <span key={`e${i}`} className="px-1 text-xs" style={{ color: '#6B7280' }}>…</span> : (
              <button key={b} onClick={() => setPage(b as number)} className="w-7 h-7 rounded text-xs font-medium transition-colors" style={{ backgroundColor: safeP === b ? '#00A8FF' : 'transparent', color: safeP === b ? '#FFFFFF' : '#6B7280' }}>{b}</button>
            ))}
            <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={safeP >= totalPages} className="p-1.5 rounded transition-colors disabled:opacity-30" style={{ color: '#FFFFFF' }}><ChevronRight className="w-4 h-4" /></button>
            <div className="w-px h-5 mx-1" style={{ backgroundColor: '#1E1E1E' }} />
            <span className="text-[11px]" style={{ color: '#6B7280' }}>Rows:</span>
            <select value={pageSize} onChange={(e) => setPageSize(Number(e.target.value))} className="rounded px-1.5 py-1 text-[11px] outline-none" style={{ backgroundColor: '#0A0A0A', border: '1px solid #1E1E1E', color: '#FFFFFF' }}>
              {PAGE_SIZES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        </div>
      )}
    </div>
  );
}
