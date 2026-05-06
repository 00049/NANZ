'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useScanPoll } from '@/hooks/useScanPoll';
import { useScanStore } from '@/store/scanStore';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import ScanProgress from '@/components/ScanProgress';

const TIPS = [
  "Did you know? 60% of hacked small businesses close within 6 months.",
  "DPDP Act requires Indian businesses to report data breaches.",
  "Most attacks target small businesses, not large corporations.",
  "Unpatched software causes 1 in 3 data breaches.",
  "Missing security headers make you vulnerable to XSS and clickjacking."
];

export default function ScanPage({ params }: { params: { scanId: string } }) {
  const router = useRouter();
  const { scanStatus, scanUrl, scanId: storeScanId, initScan } = useScanStore();
  const { isLoading } = useScanPoll();
  const [elapsed, setElapsed] = useState(0);
  const [tipIndex, setTipIndex] = useState(0);

  // Ensure store has the correct scanId from the URL (handles page refreshes)
  useEffect(() => {
    if (storeScanId !== params.scanId) {
      // Re-initialize the store with the URL scanId so polling can start
      initScan(params.scanId, scanUrl || params.scanId);
    }
  }, [params.scanId, storeScanId, scanUrl, initScan]);

  // Navigate to report when scan completes
  useEffect(() => {
    if (scanStatus === 'complete') {
      const t = setTimeout(() => {
        router.push(`/results/${params.scanId}`);
      }, 1500);
      return () => clearTimeout(t);
    }
  }, [scanStatus, params.scanId, router]);

  // Elapsed timer
  useEffect(() => {
    if (scanStatus === 'complete' || scanStatus === 'failed') return;
    const interval = setInterval(() => setElapsed(e => e + 1), 1000);
    return () => clearInterval(interval);
  }, [scanStatus]);

  // Rotating tips
  useEffect(() => {
    const interval = setInterval(() => setTipIndex(i => (i + 1) % TIPS.length), 8000);
    return () => clearInterval(interval);
  }, []);

  const formatDomain = (url: string | null) => {
    if (!url) return 'your domain';
    try {
      return new URL(url).hostname;
    } catch {
      return url;
    }
  };

  return (
    <>
      <Navbar />
      <main className="flex-1 flex flex-col items-center py-16 px-6 bg-background">
        <div className="text-center mb-12">
          <h1 className="text-3xl md:text-4xl font-bold text-text-primary mb-4">
            Auditing <span className="text-primary">{formatDomain(scanUrl)}</span>
          </h1>
          <p className="text-text-muted text-lg font-medium">
            Time elapsed: <span className="text-text-primary font-mono">{elapsed}s</span>
          </p>
        </div>

        <ScanProgress />

        {scanStatus === 'complete' && (
          <div className="mt-8 text-center">
            <div className="flex items-center justify-center gap-2 text-low font-bold mb-2">
              <span className="w-2 h-2 rounded-full bg-low animate-pulse" />
              Scan complete — loading results…
            </div>
          </div>
        )}

        {scanStatus === 'failed' && (
          <div className="mt-8 text-center bg-high/10 border border-high/30 rounded-lg p-6 max-w-lg">
            <h3 className="text-high font-bold mb-2">Scan Degraded</h3>
            <p className="text-text-muted text-sm mb-4">Some modules failed to complete, but partial results are available.</p>
            <button onClick={() => router.push(`/results/${params.scanId}`)} className="bg-surface hover:bg-card-border border border-card-border text-text-primary px-6 py-2 rounded-btn font-medium transition-colors">
              View Partial Results
            </button>
          </div>
        )}

        <div className="mt-16 text-center max-w-xl animate-fade-in">
          <p className="text-sm font-bold text-primary uppercase tracking-widest mb-2">Security Tip</p>
          <p className="text-lg text-text-muted italic">&ldquo;{TIPS[tipIndex]}&rdquo;</p>
        </div>
      </main>
      <Footer />
    </>
  );
}
