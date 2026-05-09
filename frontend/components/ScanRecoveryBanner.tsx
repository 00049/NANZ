// WHAT THIS FILE DOES: A persistent banner shown globally (below navbar) when a user has
// an active or recently completed scan in localStorage.
// KEY DEPENDENCIES: react, next/navigation, next/link, lucide-react, ../store/authStore, ../hooks/useScanPoll (implicitly through store)
// MOCKED DATA: Uses localStorage for 'shieldcheck_active_scan'.

'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { X, RefreshCw, CheckCircle2, ArrowRight } from 'lucide-react';
import { useAuthStore } from '@/store/authStore';
import { useScanStore } from '@/store/scanStore';
import { getScanProgress } from '@/lib/api';

export default function ScanRecoveryBanner() {
  const [show, setShow] = useState(false);
  const [scanData, setScanData] = useState<{ scanId: string; url: string; status: 'running' | 'complete' } | null>(null);
  const { user } = useAuthStore();
  const { scanStatus, scanId } = useScanStore();
  const pathname = usePathname();

  useEffect(() => {
    // Hide on the actual scan or report pages
    if (pathname.startsWith('/scan/') || pathname.startsWith('/report/')) {
      setShow(false);
      return;
    }

    if (!user) {
      setShow(false);
      return;
    }

    const checkActiveScan = async () => {
      try {
        const dismissed = localStorage.getItem('shieldcheck_scan_banner_dismissed');
        const stored = localStorage.getItem('shieldcheck_active_scan');

        if (!stored) {
          setShow(false);
          return;
        }

        const data = JSON.parse(stored);

        // Ensure this scan belongs to the current user
        if (data.userId !== user.id) {
          setShow(false);
          return;
        }

        // If dismissed AND it's the exact same scan, don't show
        if (dismissed === data.scanId) {
          setShow(false);
          return;
        }

        // We have a stored scan. What's its status?
        // If it's the currently active scan in Zustand, just use that status
        if (data.scanId === scanId) {
          setScanData({
            scanId: data.scanId,
            url: data.url,
            status: scanStatus === 'complete' || scanStatus === 'failed' ? 'complete' : 'running',
          });
          setShow(true);
          return;
        }

        // Otherwise we need to ping the backend to see if it's done
        const prog = await getScanProgress(data.scanId);
        const isDone = prog.status === 'completed' || prog.status === 'complete' || prog.status === 'failed';

        setScanData({
          scanId: data.scanId,
          url: data.url,
          status: isDone ? 'complete' : 'running',
        });
        setShow(true);

      } catch (err) {
        console.error('Failed to parse or fetch active scan for banner', err);
        setShow(false);
      }
    };

    checkActiveScan();
    // Poll every 10s if we're showing a running scan
    const interval = setInterval(checkActiveScan, 10000);
    return () => clearInterval(interval);

  }, [pathname, user, scanId, scanStatus]);

  const handleDismiss = () => {
    if (scanData?.scanId) {
      localStorage.setItem('shieldcheck_scan_banner_dismissed', scanData.scanId);
    }
    setShow(false);
  };

  if (!show || !scanData) return null;

  const isComplete = scanData.status === 'complete';
  const displayUrl = scanData.url.replace(/^https?:\/\//, '');

  return (
    <div className={`fixed top-16 left-0 right-0 z-40 px-4 py-2 flex items-center justify-center border-b shadow-md transition-colors ${isComplete
        ? 'bg-green-950/90 border-green-900/50 text-green-300'
        : 'bg-blue-950/90 border-blue-900/50 text-blue-300'
      }`}>
      <div className="flex items-center gap-3 max-w-7xl mx-auto w-full">
        {isComplete ? (
          <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />
        ) : (
          <RefreshCw className="w-4 h-4 text-blue-400 shrink-0 animate-spin-slow" />
        )}

        <p className="text-sm font-medium flex-1 truncate">
          {isComplete ? (
            <>Scan complete for <strong>{displayUrl}</strong></>
          ) : (
            <>Scan in progress for <strong>{displayUrl}</strong></>
          )}
        </p>

        <Link
          href={isComplete ? `/report/${scanData.scanId}` : `/scan/${scanData.scanId}`}
          className={`shrink-0 flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold rounded-md transition-colors ${isComplete
              ? 'bg-green-900 hover:bg-green-800 text-white'
              : 'bg-blue-900 hover:bg-blue-800 text-white'
            }`}
        >
          {isComplete ? 'View Results' : 'View Progress'} <ArrowRight className="w-3.5 h-3.5" />
        </Link>

        <button
          onClick={handleDismiss}
          className="shrink-0 p-1.5 hover:bg-black/20 rounded-lg transition-colors ml-2"
          aria-label="Dismiss banner"
        >
          <X className="w-4 h-4 opacity-70 hover:opacity-100" />
        </button>
      </div>
    </div>
  );
}
