// WHAT THIS FILE DOES: Polls the scan status every 2 seconds and tracks partial module
// completions in real time. When a module flips to 'done', fetches partial results and
// updates the scanStore for live card rendering on the scan progress page.
// KEY DEPENDENCIES: react, ../store/scanStore, ../lib/api
// MOCKED DATA: getPartialResults falls back to a mock if backend returns 404/error.
//              Remove mock fallback when GET /api/scans/{id}/partial is implemented.

'use client';

import { useEffect, useRef } from 'react';
import { useScanStore } from '@/store/scanStore';
import { getScanProgress } from '@/lib/api';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// Module → friendly summary mock (used when partial endpoint not available)
function getMockPartialResult(moduleKey: string, status: string) {
  if (status !== 'done' && status !== 'complete' && status !== 'completed') return null;
  const mocks: Record<string, { grade?: string; summary: string; severity: 'GREEN' | 'AMBER' | 'RED' | 'CRITICAL'; key_metric?: string }> = {
    ssl_check: { grade: 'B', summary: 'SSL certificate valid', severity: 'GREEN', key_metric: 'TLS 1.3 supported' },
    headers_check: { grade: 'D', summary: '4 security headers missing', severity: 'AMBER', key_metric: '4 of 13 headers missing' },
    dns_check: { grade: 'C', summary: 'DMARC not enforced', severity: 'AMBER', key_metric: 'DMARC: p=none' },
    port_check: { grade: 'A', summary: 'No dangerous ports exposed', severity: 'GREEN', key_metric: 'All common attack ports closed' },
    reputation_check: { grade: 'A', summary: 'Clean threat reputation', severity: 'GREEN', key_metric: 'Not flagged by 70+ vendors' },
    waf_check: { summary: 'No WAF detected', severity: 'AMBER', key_metric: 'No web application firewall found' },
    breach_check: { summary: 'No known breaches', severity: 'GREEN', key_metric: 'Domain not in breach databases' },
    cms_check: { summary: 'CMS detected', severity: 'AMBER', key_metric: 'WordPress version exposed' },
    cookie_check: { summary: 'Cookie security issues', severity: 'AMBER', key_metric: 'Missing HttpOnly flag on 2 cookies' },
    webapp_check: { summary: 'Web app security analyzed', severity: 'GREEN', key_metric: 'No critical vulnerabilities found' },
    javascript_check: { summary: 'JS libraries analyzed', severity: 'AMBER', key_metric: '2 outdated libraries detected' },
    cors_check: { summary: 'CORS configuration checked', severity: 'GREEN', key_metric: 'Restrictive CORS policy in place' },
    http_methods_check: { summary: 'HTTP methods verified', severity: 'GREEN', key_metric: 'No dangerous methods enabled' },
    cloud_exposure_check: { summary: 'Cloud exposure analyzed', severity: 'GREEN', key_metric: 'No exposed storage buckets' },
    email_security_check: { summary: 'Email security analyzed', severity: 'AMBER', key_metric: 'DKIM not configured' },
  };
  return mocks[moduleKey] ?? { summary: `${moduleKey} completed`, severity: 'GREEN' as const };
}

async function fetchPartialResults(scanId: string, moduleKeys: string[]) {
  try {
    const params = moduleKeys.join(',');
    const res = await fetch(`${API_BASE}/api/scans/${scanId}/partial?modules=${params}`);
    if (!res.ok) throw new Error('Not available');
    return res.json();
  } catch {
    // Endpoint not yet implemented — return null, caller uses mock
    return null;
  }
}

export function useScanPoll() {
  const {
    scanId, scanStatus,
    setStatus, updateProgress,
    partialResults, setPartialResults,
    addCompletedModule, completedModules,
    setPreliminaryScore,
  } = useScanStore();

  // Track which modules were already done to detect new completions
  const prevDoneRef = useRef<Set<string>>(new Set(completedModules));

  useEffect(() => {
    if (!scanId || scanStatus === 'complete' || scanStatus === 'failed') return;

    const poll = async () => {
      try {
        const data = await getScanProgress(scanId);
        const progress: Record<string, string> = data.progress || {};
        updateProgress(progress);

        // Detect status change
        const rawStatus = data.status;
        if (rawStatus === 'completed' || rawStatus === 'complete') {
          setStatus('complete');
        } else if (rawStatus === 'failed') {
          setStatus('failed');
        } else {
          setStatus('running');
        }

        // Find newly completed modules
        const nowDone: string[] = [];
        for (const [key, val] of Object.entries(progress)) {
          const norm = val === 'complete' || val === 'completed' ? 'done' : val;
          if (norm === 'done' && !prevDoneRef.current.has(key)) {
            nowDone.push(key);
            prevDoneRef.current.add(key);
            addCompletedModule(key);
          }
        }

        // Fetch/mock partial results for newly completed modules
        if (nowDone.length > 0) {
          const serverData = await fetchPartialResults(scanId, nowDone);

          // Fix: Always get fresh state from the store, not the stale closure
          const currentResults = useScanStore.getState().partialResults;
          const newResults = { ...currentResults };

          if (serverData?.partial_results) {
            Object.assign(newResults, serverData.partial_results);
            if (serverData.preliminary_score != null) {
              setPreliminaryScore(serverData.preliminary_score, serverData.preliminary_counts || { critical: 0, high: 0, medium: 0, low: 0 });
            }
          } else {
            // Use mocks
            for (const key of nowDone) {
              const mock = getMockPartialResult(key, 'done');
              if (mock) newResults[key] = mock;
            }
          }

          setPartialResults(newResults);
        }
      } catch (err) {
        console.error('Poll error:', err);
      }
    };

    poll(); // Initial fetch
    const interval = setInterval(poll, 2000); // 2s for snappier UX
    return () => clearInterval(interval);
  }, [
    scanId, scanStatus,
    setStatus, updateProgress,
    addCompletedModule, setPartialResults, setPreliminaryScore,
    // partialResults intentionally excluded to avoid re-creating interval on each result
  ]);
}
