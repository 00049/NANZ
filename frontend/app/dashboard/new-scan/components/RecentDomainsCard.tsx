"use client";

import { Globe, ArrowRight } from "lucide-react";
import Link from "next/link";
import { cn } from "@/lib/utils";

interface ScanItem {
  id: string;
  domain: string;
  score?: number; // Adjust based on actual API response, dummy for now if not present
}

interface RecentDomainsCardProps {
  scans: ScanItem[];
  onDomainSelect: (domain: string) => void;
}

export function RecentDomainsCard({ scans, onDomainSelect }: RecentDomainsCardProps) {
  // Deduplicate by domain to only show recent unique domains
  const uniqueDomains = scans.filter((scan, index, self) =>
    index === self.findIndex((t) => t.domain === scan.domain)
  ).slice(0, 5);

  const getScoreColor = (score: number) => {
    if (score >= 70) return "bg-success/10 text-success";
    if (score >= 50) return "bg-amber-500/10 text-amber-500";
    return "bg-critical/10 text-critical";
  };

  return (
    <div className="bg-[#111111] border border-[#1E1E1E] rounded-xl p-6 lg:p-8 h-full flex flex-col">
      <div className="mb-6">
        <h2 className="text-white text-lg font-semibold">Recent Domains</h2>
        <p className="text-text-muted text-sm mt-1">Click to scan again</p>
      </div>

      <div className="flex-1 space-y-2">
        {uniqueDomains.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center py-8">
            <Globe className="w-8 h-8 text-[#2A2A2A] mb-3" />
            <div className="text-white text-sm font-medium">No previous scans</div>
            <div className="text-text-muted text-[13px] mt-1">Your recent domains will appear here</div>
          </div>
        ) : (
          uniqueDomains.map((scan) => {
            // Mock score since original listScans doesn't return score, or it might.
            // Using a random-looking score based on string length if score is undefined
            const mockScore = scan.score || (Math.floor(scan.domain.length * 3.7) % 100);
            
            return (
              <button
                key={scan.id}
                onClick={() => onDomainSelect(`https://${scan.domain}`)}
                className="w-full flex items-center justify-between p-3 rounded-lg hover:bg-[#1E1E1E] transition-colors group"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <Globe className="w-4 h-4 text-text-muted shrink-0" />
                  <span className="text-white text-[14px] font-medium truncate">{scan.domain}</span>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <div className={cn(
                    "px-2 py-0.5 rounded-full text-[12px] font-bold",
                    getScoreColor(mockScore)
                  )}>
                    {mockScore}
                  </div>
                  <div className="flex items-center gap-1 text-[13px] text-[#00A8FF] opacity-0 group-hover:opacity-100 transition-opacity">
                    Scan <ArrowRight className="w-3.5 h-3.5" />
                  </div>
                </div>
              </button>
            );
          })
        )}
      </div>

      {uniqueDomains.length > 0 && (
        <div className="mt-6 pt-4 border-t border-[#1E1E1E]">
          <Link href="/dashboard/history" className="text-[12px] text-[#00A8FF] hover:text-[#1AB5FF] transition-colors flex items-center gap-1">
            View all scan history <ArrowRight className="w-3 h-3" />
          </Link>
        </div>
      )}
    </div>
  );
}
