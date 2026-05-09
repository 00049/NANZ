// WHAT THIS FILE DOES: Fixed bar below the navbar for the report page. Contains scan metadata,
// role selector, and action buttons.
// KEY DEPENDENCIES: react, lucide-react, ./RoleSelector, ../types
// MOCKED DATA: None.

'use client';

import { Download, Share2, RefreshCw } from 'lucide-react';
import RoleSelector, { useRole } from '@/components/RoleSelector';
import ScoreRing from '@/components/ScoreRing';
import { useRouter } from 'next/navigation';
import { useAuthStore } from '@/store/authStore';
import { toast } from 'sonner';
import { normalizeSeverity } from '@/lib/severity';

interface ReportTopBarProps {
  domain: string;
  score: number;
  severity: string;
  scanId: string;
  scannedAt?: string;
  onMobileMenuClick: () => void;
}

export default function ReportTopBar({ domain, score, severity, scanId, scannedAt, onMobileMenuClick }: ReportTopBarProps) {
  const [role, setRole] = useRole();
  const router = useRouter();
  const { setPendingScanUrl } = useAuthStore();

  const handleRescan = () => {
    // Assuming user is authenticated if they are viewing the full report
    setPendingScanUrl(domain);
    // Actually, we can just push to home and it will trigger the flow, 
    // or just push to home and let them type it.
    // Better: We just push to home with a query param or let the auth flow handle it.
    router.push(`/?scan=${encodeURIComponent(domain)}`);
  };

  const handleShare = () => {
    navigator.clipboard.writeText(window.location.href);
    toast.success('Report link copied to clipboard');
  };

  return (
    <div className="fixed top-16 left-0 right-0 h-12 bg-[#0A0A0C] border-b border-[#1E1E24] z-40 flex items-center justify-between px-4 lg:px-6">

      {/* Mobile hamburger & Left Side */}
      <div className="flex items-center gap-4">
        <button
          onClick={onMobileMenuClick}
          className="lg:hidden p-1.5 -ml-1.5 text-slate-400 hover:text-slate-100 transition-colors"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="3" y1="12" x2="21" y2="12"></line>
            <line x1="3" y1="6" x2="21" y2="6"></line>
            <line x1="3" y1="18" x2="21" y2="18"></line>
          </svg>
        </button>

        <div className="flex flex-col justify-center">
          <span className="text-sm font-bold text-slate-100 truncate max-w-[150px] sm:max-w-[300px]">
            {domain.replace(/^https?:\/\//, '')}
          </span>
          <span className="text-[10px] text-slate-500 uppercase tracking-wider">
            {scannedAt || 'Just now'}
          </span>
        </div>

        <div className={`hidden sm:flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ml-2 border ${normalizeSeverity(severity) === 'CRITICAL' ? 'bg-red-950/50 border-red-900/50 text-red-400' :
            normalizeSeverity(severity) === 'HIGH' ? 'bg-orange-950/30 border-orange-900/30 text-orange-400' :
              normalizeSeverity(severity) === 'MEDIUM' ? 'bg-amber-950/20 border-amber-800/30 text-amber-400' :
                'bg-green-950/20 border-green-800/30 text-green-400'
          }`}>
          {normalizeSeverity(severity)}
        </div>
      </div>

      {/* Center: Score */}
      <div className="hidden md:flex items-center gap-3">
        <div className="w-8 h-8">
          <ScoreRing score={score} severity={severity} hideText />
        </div>
        <span className="text-lg font-black text-slate-100">{score}</span>
      </div>

      {/* Right Side */}
      <div className="flex items-center gap-3 sm:gap-4">
        <div className="hidden sm:block">
          <RoleSelector value={role} onChange={setRole} />
        </div>

        <div className="h-6 w-px bg-[#1E1E24] hidden sm:block"></div>

        <div className="flex items-center gap-1 sm:gap-2">
          <button onClick={handleShare} className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800/50 rounded-md transition-colors" title="Share Report">
            <Share2 className="w-4 h-4" />
          </button>
          <button onClick={() => window.print()} className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800/50 rounded-md transition-colors" title="Download PDF">
            <Download className="w-4 h-4" />
          </button>
          <button onClick={handleRescan} className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-md transition-colors border border-slate-700">
            <RefreshCw className="w-3 h-3" />
            Re-scan
          </button>
        </div>
      </div>
    </div>
  );
}
