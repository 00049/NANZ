"use client";

import { domains } from "@/lib/mock-data";
import { cn } from "@/lib/utils";
import { Search, Download, Filter } from "lucide-react";
import { useState } from "react";

const mockHistory = [
  { id: "scan_01", date: "2026-04-28T02:00:00Z", domain: "clientapp.com", score: 45, prev: 52, critical: 2, high: 4, medium: 6, status: "complete" },
  { id: "scan_02", date: "2026-04-27T14:30:00Z", domain: "nanz.ai", score: 87, prev: 82, critical: 0, high: 1, medium: 3, status: "complete" },
  { id: "scan_03", date: "2026-04-26T09:15:00Z", domain: "api.nanz.ai", score: 72, prev: 65, critical: 0, high: 3, medium: 5, status: "complete" },
  { id: "scan_04", date: "2026-04-20T11:45:00Z", domain: "staging.clientapp.com", score: 63, prev: 63, critical: 1, high: 2, medium: 4, status: "complete" },
  { id: "scan_05", date: "2026-04-15T08:00:00Z", domain: "nanz.ai", score: 82, prev: 75, critical: 0, high: 2, medium: 4, status: "complete" },
  { id: "scan_06", date: "2026-04-10T16:00:00Z", domain: "clientapp.com", score: 52, prev: 48, critical: 1, high: 5, medium: 7, status: "complete" },
  { id: "scan_07", date: "2026-04-05T12:30:00Z", domain: "api.nanz.ai", score: 65, prev: 60, critical: 1, high: 4, medium: 6, status: "complete" },
];

export default function HistoryPage() {
  const [search, setSearch] = useState("");
  const filtered = mockHistory.filter(h => h.domain.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-title text-text-primary">Scan History</h1>
          <p className="text-sm text-text-secondary mt-1">{mockHistory.length} scans completed</p>
        </div>
        <button className="px-4 py-2.5 rounded-btn bg-surface border border-surface-border text-sm font-medium text-text-secondary hover:text-text-primary hover:bg-surface-hover transition-colors flex items-center gap-2">
          <Download className="w-4 h-4" /> Export CSV
        </button>
      </div>

      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Filter by domain..." className="w-full pl-11 pr-4 py-2.5 rounded-btn bg-surface border border-surface-border text-sm text-text-primary placeholder:text-text-muted focus:border-nanz-500 outline-none transition-all" />
        </div>
      </div>

      <div className="rounded-card border border-card-border bg-card overflow-hidden">
        <div className="grid grid-cols-[140px_1fr_80px_80px_60px_60px_60px] gap-4 px-5 py-3 border-b border-surface-border text-xs font-medium text-text-muted uppercase tracking-wider">
          <span>Date</span><span>Domain</span><span>Score</span><span>Change</span><span>Crit</span><span>High</span><span>Med</span>
        </div>
        {filtered.map((scan) => {
          const change = scan.score - scan.prev;
          return (
            <div key={scan.id} className="grid grid-cols-[140px_1fr_80px_80px_60px_60px_60px] gap-4 px-5 py-4 border-b border-surface-border last:border-b-0 hover:bg-surface-hover/50 transition-colors items-center cursor-pointer">
              <div className="text-xs text-text-muted">{new Date(scan.date).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}</div>
              <div className="text-sm font-medium text-text-primary truncate">{scan.domain}</div>
              <div className={cn("text-sm font-bold", scan.score >= 80 ? "text-success" : scan.score >= 60 ? "text-medium" : "text-critical")}>{scan.score}</div>
              <div className={cn("text-xs font-medium", change > 0 ? "text-success" : change < 0 ? "text-critical" : "text-text-muted")}>
                {change > 0 ? `+${change}` : change === 0 ? "—" : change}
              </div>
              <div className={cn("text-xs font-medium", scan.critical > 0 ? "text-critical" : "text-text-muted")}>{scan.critical}</div>
              <div className={cn("text-xs font-medium", scan.high > 0 ? "text-high" : "text-text-muted")}>{scan.high}</div>
              <div className={cn("text-xs font-medium", scan.medium > 0 ? "text-medium" : "text-text-muted")}>{scan.medium}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
