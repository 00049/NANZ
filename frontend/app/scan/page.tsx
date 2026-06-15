'use client';

import { useEffect, useState, useRef, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { startScan } from '@/lib/api';
import { useScanStore } from '@/store/scanStore';
import Navbar from '@/components/Navbar';
import { ShieldCheck } from 'lucide-react';

let globalScanPromise: Promise<any> | null = null;
let globalScanUrl: string | null = null;

function ScanInitContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const url = searchParams.get('url');
  const { initScan } = useScanStore();
  const [error, setError] = useState('');

  useEffect(() => {
    if (!url) {
      router.replace('/');
      return;
    }
    
    let isMounted = true;

    async function init() {
      try {
        if (globalScanUrl !== url || !globalScanPromise) {
          globalScanUrl = url as string;
          globalScanPromise = startScan(url as string);
        }
        
        const res = await globalScanPromise;
        if (!isMounted) return;
        
        initScan(res.scan_id, url as string);
        router.replace(`/scan/${res.scan_id}`);
      } catch (err: any) {
        if (!isMounted) return;
        
        globalScanPromise = null;
        console.error('Failed to start scan:', err);
        setError(err.message || 'Failed to start scan. Please try again.');
      }
    }
    
    init();
    
    return () => {
      isMounted = false;
    };
  }, [url, router, initScan]);

  if (error) {
    return (
      <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6 max-w-md w-full">
        <h2 className="text-xl font-bold text-red-400 mb-2">Scan Failed</h2>
        <p className="text-slate-300 mb-6">{error}</p>
        <button
          onClick={() => router.push('/')}
          className="px-6 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors"
        >
          Go Back
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center">
      <div className="relative mb-8">
        <div className="absolute inset-0 bg-blue-500/20 blur-xl rounded-full" />
        <ShieldCheck className="w-20 h-20 text-blue-500 relative z-10 animate-pulse" />
      </div>
      <h1 className="text-2xl font-bold mb-4">Initializing Security Audit...</h1>
      <p className="text-slate-400">Target: {url}</p>
      <div className="mt-8 flex gap-2">
        <span className="w-2 h-2 rounded-full bg-blue-500 animate-bounce" style={{ animationDelay: '0ms' }} />
        <span className="w-2 h-2 rounded-full bg-blue-500 animate-bounce" style={{ animationDelay: '150ms' }} />
        <span className="w-2 h-2 rounded-full bg-blue-500 animate-bounce" style={{ animationDelay: '300ms' }} />
      </div>
    </div>
  );
}

export default function ScanInitPage() {
  return (
    <div className="min-h-screen bg-[#030303] flex flex-col text-slate-200">
      <Navbar />
      <main className="flex-1 max-w-7xl mx-auto w-full px-6 py-20 flex flex-col items-center justify-center text-center">
        <Suspense fallback={
          <div className="flex flex-col items-center">
            <div className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin mb-4" />
            <p className="text-slate-400">Loading...</p>
          </div>
        }>
          <ScanInitContent />
        </Suspense>
      </main>
    </div>
  );
}
