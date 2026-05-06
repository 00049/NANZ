"use client";

import { cn } from "@/lib/utils";
import { Search, Download, Loader2, RefreshCw, ExternalLink } from "lucide-react";
import { useState, useEffect } from "react";
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
};

function statusBadge(status: string) {
  if (status === "complete") return "text-success bg-success/10 border-success/20";
  if (status === "running" || status === "pending") return "text-yellow-400 bg-yellow-400/10 border-yellow-400/20";
  return "text-critical bg-critical/10 border-critical/20";
}

export default function HistoryPage() {
  const [search, setSearch] = useState("");
  const [scans, setScans] = useState<ScanItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchScans = async () => {
    setLoading(true);
    setError("");
    try {
      const data = await listScans(100, 0);
      setScans(data.scans);
      setTotal(data.total);
    } catch (e: any) {
      setError(e.message || "Failed to load scan history.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const filtered = scans.filter(
    (s) =>
      s.domain.toLowerCase().includes(search.toLowerCase()) ||
      s.url.toLowerCase().includes(search.toLowerCase())
  );

  const handleExport = () => {
    if (filtered.length === 0) return;
    const header = "ID,Domain,URL,Status,Type,Created At,Completed At,Duration (ms)\n";
    const rows = filtered
      .map((s) =>
        [
          s.id,
          s.domain,
          s.url,
          s.status,
          s.scan_type,
          s.created_at ?? "",
          s.completed_at ?? "",
          s.scan_duration_ms ?? "",
        ].join(",")
      )
      .join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `shieldcheck_scans_${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-title text-text-primary">Scan History</h1>
          <p className="text-sm text-text-secondary mt-1">
            {loading ? "Loading…" : `${total} scans total`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchScans}
            disabled={loading}
            className="px-3 py-2.5 rounded-btn bg-surface border border-surface-border text-sm font-medium text-text-secondary hover:text-text-primary hover:bg-surface-hover transition-colors flex items-center gap-2 disabled:opacity-50"
          >
            <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
            Refresh
          </button>
          <button
            onClick={handleExport}
            disabled={loading || filtered.length === 0}
            className="px-4 py-2.5 rounded-btn bg-surface border border-surface-border text-sm font-medium text-text-secondary hover:text-text-primary hover:bg-surface-hover transition-colors flex items-center gap-2 disabled:opacity-50"
          >
            <Download className="w-4 h-4" /> Export CSV
          </button>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by domain or URL…"
            className="w-full pl-11 pr-4 py-2.5 rounded-btn bg-surface border border-surface-border text-sm text-text-primary placeholder:text-text-muted focus:border-nanz-500 outline-none transition-all"
          />
        </div>
        {search && (
          <span className="text-xs text-text-muted">{filtered.length} result{filtered.length !== 1 ? "s" : ""}</span>
        )}
      </div>

      {error && (
        <div className="rounded-btn border border-critical/30 bg-critical/10 px-4 py-3 text-sm text-critical">
          {error}
        </div>
      )}

      <div className="rounded-card border border-card-border bg-card overflow-hidden">
        {/* Header */}
        <div className="grid grid-cols-[1fr_140px_90px_80px_80px] gap-4 px-5 py-3 border-b border-surface-border text-xs font-medium text-text-muted uppercase tracking-wider">
          <span>Domain / URL</span>
          <span>Date</span>
          <span>Status</span>
          <span>Type</span>
          <span>Duration</span>
        </div>

        {loading ? (
          <div className="flex items-center justify-center h-48">
            <Loader2 className="w-6 h-6 text-text-muted animate-spin" />
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 gap-2 text-text-muted">
            <p className="text-sm">{search ? "No scans match your filter." : "No scans found in the database."}</p>
            {!search && (
              <Link href="/" className="text-xs text-nanz-400 hover:text-nanz-300 transition-colors">
                Run your first scan →
              </Link>
            )}
          </div>
        ) : (
          filtered.map((scan) => (
            <Link
              key={scan.id}
              href={`/report/${scan.id}`}
              className="grid grid-cols-[1fr_140px_90px_80px_80px] gap-4 px-5 py-4 border-b border-surface-border last:border-b-0 hover:bg-surface-hover/50 transition-colors items-center group"
            >
              <div className="min-w-0">
                <div className="text-sm font-medium text-text-primary truncate group-hover:text-nanz-400 transition-colors flex items-center gap-1.5">
                  {scan.domain}
                  <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
                </div>
                <div className="text-xs text-text-muted truncate">{scan.url}</div>
              </div>
              <div className="text-xs text-text-muted">
                {scan.created_at
                  ? new Date(scan.created_at).toLocaleDateString("en-IN", {
                      day: "numeric",
                      month: "short",
                      year: "numeric",
                    })
                  : "—"}
              </div>
              <div>
                <span
                  className={cn(
                    "text-xs font-medium px-2 py-0.5 rounded border capitalize",
                    statusBadge(scan.status)
                  )}
                >
                  {scan.status}
                </span>
              </div>
              <div className="text-xs text-text-secondary capitalize">{scan.scan_type}</div>
              <div className="text-xs text-text-muted">
                {scan.scan_duration_ms ? `${(scan.scan_duration_ms / 1000).toFixed(1)}s` : "—"}
              </div>
            </Link>
          ))
        )}
      </div>
    </div>
  );
}
