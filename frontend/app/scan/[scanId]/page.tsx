// WHAT THIS FILE DOES: Scan progress page (split layout). Left side shows module progress,
// Right side shows partial module result cards as they complete.
// KEY DEPENDENCIES: react, framer-motion, lucide-react, ../hooks/useScanPoll, ../store/scanStore
// MOCKED DATA: None.

'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import {
  CheckCircle2, AlertTriangle, Circle, ShieldCheck,
  ArrowRight, CreditCard, Lock
} from 'lucide-react';
import { useScanStore } from '@/store/scanStore';
import { useScanPoll } from '@/hooks/useScanPoll';
import { useAuthStore } from '@/store/authStore';
import Navbar from '@/components/Navbar';
import ScanPartialCard from '@/components/ScanPartialCard';
import ScoreRing from '@/components/ScoreRing';

// Mock active tips
const TIPS = [
  "Analyzing SSL/TLS configuration against modern standards...",
  "Looking for exposed admin panels and sensitive endpoints...",
  "Checking email security records (SPF, DMARC, DKIM)...",
  "Evaluating Content Security Policy (CSP) headers...",
  "Checking for known vulnerable JavaScript libraries..."
];

const MODULES = [
  { key: 'waf_check', label: 'WAF & CDN Detection' },
  { key: 'ssl_check', label: 'SSL Certificate Analysis' },
  { key: 'headers_check', label: 'Security Headers Check' },
  { key: 'dns_check', label: 'DNS & Email Security' },
  { key: 'port_check', label: 'Open Port Scanning' },
  { key: 'breach_check', label: 'Data Breach History' },
  { key: 'cms_check', label: 'CMS & Plugin Security' },
  { key: 'cookie_check', label: 'Cookie Security' },
  { key: 'webapp_check', label: 'Web Application Security' },
  { key: 'reputation_check', label: 'Threat Intelligence' },
  { key: 'infra_check', label: 'Infrastructure & Server Check' },
  { key: 'javascript_check', label: 'JavaScript Source Analysis' },
  { key: 'cors_check', label: 'CORS Configuration' },
  { key: 'http_methods_check', label: 'HTTP Methods Check' },
  { key: 'cloud_exposure_check', label: 'Cloud Storage Exposure' },
  { key: 'email_security_check', label: 'Email Security Deep Scan' },
  { key: 'performance_check', label: 'Performance & Latency Profiling' },
  { key: 'tech_inventory', label: 'Tech Stack Fingerprinting' },
  { key: 'crawl_intelligence', label: 'Site Crawl & Subdomain Mapping' },
  { key: 'iast_behavioral', label: 'Behavioral Threat Analysis' },
  { key: 'oast_check', label: 'Out-of-band Vulnerability Check' },
  { key: 'api_security', label: 'API Endpoint Security' },
  { key: 'graphql', label: 'GraphQL Introspection & Security' },
  { key: 'business_logic', label: 'Business Logic Flaw Detection' },
  { key: 'container_security', label: 'Container & Docker Misconfigurations' },
  { key: 'dependency', label: 'Vulnerable Dependencies Check' },
  { key: 'llm_security', label: 'LLM & Prompt Injection Risks' }
];

export default function ScanProgressPage({ params }: { params: { scanId: string } }) {
  const router = useRouter();
  const {
    scanStatus, scanUrl, progress, partialResults,
    completedModules, preliminaryScore, preliminaryCounts
  } = useScanStore();
  const { user } = useAuthStore();

  const [tipIndex, setTipIndex] = useState(0);

  // Hook handles all the polling logic
  useScanPoll();

  // Rotate tips
  useEffect(() => {
    const i = setInterval(() => {
      setTipIndex(prev => (prev + 1) % TIPS.length);
    }, 4000);
    return () => clearInterval(i);
  }, []);

  // Completion handling
  const isDone = scanStatus === 'complete' || scanStatus === 'failed';

  // If scan is done and we have no partial results, it means we loaded an already completed scan.
  // We should redirect to the results page immediately.
  useEffect(() => {
    if (isDone && Object.keys(partialResults).length === 0) {
      router.replace(`/report/${params.scanId}`);
    }
  }, [isDone, partialResults, router, params.scanId]);

  const completedCount = isDone ? MODULES.length : completedModules.length;
  const totalCount = MODULES.length;
  const percent = Math.round((completedCount / totalCount) * 100);

  const getStatusIcon = (status: string) => {
    const s = status === 'completed' || status === 'complete' ? 'done' : status;
    if (s === 'done') return <CheckCircle2 className="w-5 h-5 text-green-500" />;
    if (s === 'failed') return <AlertTriangle className="w-5 h-5 text-orange-500" />;
    if (s === 'running') return <div className="w-5 h-5 rounded-full border-2 border-blue-500/30 border-t-blue-500 animate-spin" />;
    return <Circle className="w-5 h-5 text-slate-700" />;
  };

  const getStatusBg = (status: string) => {
    const s = status === 'completed' || status === 'complete' ? 'done' : status;
    if (s === 'done') return 'bg-green-500/10 border-green-500/20';
    if (s === 'failed') return 'bg-orange-500/10 border-orange-500/20';
    if (s === 'running') return 'bg-blue-500/10 border-blue-500/20';
    return 'bg-slate-900 border-slate-800 opacity-50';
  };

  const getModuleStatus = (mKey: string) => {
    if (isDone) return 'done';
    return progress[mKey] || 'pending';
  };

  const partialEntries = Object.entries(partialResults);

  return (
    <div className="min-h-screen bg-[#030303] flex flex-col text-slate-200">
      <Navbar />

      <main className="flex-1 max-w-7xl mx-auto w-full px-6 py-8 flex flex-col lg:flex-row gap-8">

        {/* Left Panel: Progress Outline */}
        <div className="lg:w-5/12 flex flex-col h-[calc(100vh-140px)]">
          <div className="mb-6">
            <h1 className="text-2xl font-bold mb-2">Analyzing Target</h1>
            <p className="text-blue-400 font-mono text-sm bg-blue-500/10 inline-block px-3 py-1.5 rounded-lg border border-blue-500/20 truncate max-w-full">
              {scanUrl || 'Loading target...'}
            </p>
          </div>

          <div className="bg-[#0A0A0C] border border-[#1E1E24] rounded-2xl p-6 flex-1 flex flex-col min-h-0">
            {/* Progress Header */}
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <ShieldCheck className="w-6 h-6 text-blue-500" />
                <span className="font-semibold">{isDone ? 'Scan Complete' : 'Modules Running'}</span>
              </div>
              <span className="font-mono text-lg font-bold text-slate-300">
                {completedCount} / {totalCount}
              </span>
            </div>

            {/* Progress Bar */}
            <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden mb-6">
              <motion.div
                className="h-full bg-gradient-to-r from-blue-600 to-blue-400"
                initial={{ width: 0 }}
                animate={{ width: `${percent}%` }}
                transition={{ duration: 0.5 }}
              />
            </div>

            {/* Module List (Scrollable) */}
            <div className="flex-1 overflow-y-auto pr-2 space-y-2.5 custom-scrollbar min-h-0 relative">
              {MODULES.map(m => {
                const status = getModuleStatus(m.key);
                const isRunning = status === 'running';

                return (
                  <div key={m.key} className={`flex items-center gap-3 p-3 rounded-xl border transition-colors ${getStatusBg(status)}`}>
                    {getStatusIcon(status)}
                    <span className={`text-sm font-medium ${isRunning ? 'text-blue-400' : 'text-slate-300'}`}>
                      {m.label}
                    </span>
                    {isRunning && (
                      <span className="ml-auto flex space-x-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-bounce" style={{ animationDelay: '0ms' }} />
                        <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-bounce" style={{ animationDelay: '150ms' }} />
                        <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-bounce" style={{ animationDelay: '300ms' }} />
                      </span>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Tip Footer */}
            <div className="mt-6 pt-4 border-t border-[#1E1E24]">
              <AnimatePresence mode="wait">
                <motion.p
                  key={tipIndex}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="text-sm text-slate-500 italic text-center h-5"
                >
                  {isDone ? "Finalizing report generation..." : TIPS[tipIndex]}
                </motion.p>
              </AnimatePresence>
            </div>
          </div>
        </div>

        {/* Right Panel: Partial Results / Live Output */}
        <div className="lg:w-7/12 flex flex-col h-[calc(100vh-140px)]">
          <div className="mb-6 flex items-center justify-between">
            <h2 className="text-xl font-bold">Live Intelligence Stream</h2>
            {isDone && (
              <span className="px-3 py-1 bg-green-500/20 text-green-400 text-xs font-bold uppercase rounded-full border border-green-500/30">
                Ready for Review
              </span>
            )}
          </div>

          <div className="bg-[#0A0A0C] border border-[#1E1E24] rounded-2xl p-6 flex-1 flex flex-col min-h-0 relative overflow-hidden">

            {/* Background Logo Watermark */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 opacity-[0.03] pointer-events-none">
              <ShieldCheck className="w-96 h-96" />
            </div>

            {/* Preliminary Score Header (if available) */}
            {preliminaryScore != null && (
              <div className="mb-6 p-4 rounded-xl border border-blue-900/50 bg-blue-950/10 flex items-center gap-6">
                <div className="w-16 h-16 shrink-0">
                  <ScoreRing score={preliminaryScore} severity="INFO" hideText={false} />
                </div>
                <div>
                  <h3 className="text-slate-300 text-sm font-semibold mb-1">Preliminary Score Estimated</h3>
                  <div className="flex gap-4 text-xs font-medium">
                    <span className="text-red-400">{preliminaryCounts?.critical || 0} Critical</span>
                    <span className="text-orange-400">{preliminaryCounts?.high || 0} High</span>
                    <span className="text-slate-500">Subject to change until complete</span>
                  </div>
                </div>
              </div>
            )}

            {/* Results Stream */}
            <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar relative z-10 flex flex-col gap-3">
              {partialEntries.length === 0 ? (
                <div className="flex-1 flex flex-col items-center justify-center text-slate-500">
                  <div className="w-12 h-12 mb-4 border-t-2 border-r-2 border-slate-700 rounded-full animate-spin" />
                  <p>Awaiting first module completion...</p>
                </div>
              ) : (
                <AnimatePresence>
                  {[...partialEntries].reverse().map(([key, result]) => (
                    <ScanPartialCard key={key} moduleName={key} result={result} />
                  ))}
                </AnimatePresence>
              )}
            </div>

            {/* Completion CTA */}
            <AnimatePresence>
              {isDone && (
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="absolute bottom-6 left-6 right-6 z-20"
                >
                  <div className="bg-slate-900/90 backdrop-blur-md border border-slate-700 p-5 rounded-xl shadow-2xl flex items-center justify-between">
                    <div>
                      <h3 className="text-white font-bold mb-1">Scan Complete</h3>
                      <p className="text-slate-400 text-sm">Review your results and access the full report.</p>
                    </div>
                    <button
                      onClick={() => router.push(`/report/${params.scanId}`)}
                      className="px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-lg flex items-center gap-2 transition-colors"
                    >
                      View Report <ArrowRight className="w-4 h-4" />
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

          </div>
        </div>
      </main>
    </div>
  );
}
