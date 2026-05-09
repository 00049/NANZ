// WHAT THIS FILE DOES: Zustand store for active scan state. Tracks scan metadata,
// polling progress per module, partial results as modules complete, and elapsed time.
// KEY DEPENDENCIES: zustand, zustand/middleware (persist), ../types
// MOCKED DATA: partialResults populated from mock /api/scans/{id}/partial endpoint

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { PreviewResponse, FullReport } from '../types';

export interface PartialModuleResult {
  grade?: string;
  summary: string;
  severity: 'GREEN' | 'AMBER' | 'RED' | 'CRITICAL';
  key_metric?: string;
  missing_count?: number;
  extra?: Record<string, unknown>;
}

interface ScanStore {
  scanId: string | null;
  scanUrl: string | null;
  scanStatus: 'idle' | 'pending' | 'running' | 'complete' | 'failed';
  progress: Record<string, string>;
  isPaid: boolean;
  reportJWT: string | null;
  previewData: PreviewResponse | null;
  fullReportData: FullReport | null;

  // NEW: Partial results for live scan progress
  partialResults: Record<string, PartialModuleResult>;
  completedModules: string[];
  scanStartedAt: number | null; // timestamp ms
  elapsedSeconds: number;
  preliminaryScore: number | null;
  preliminaryCounts: { critical: number; high: number; medium: number; low: number } | null;

  // Actions
  initScan: (id: string, url: string) => void;
  updateProgress: (progress: Record<string, string>) => void;
  setStatus: (status: 'idle' | 'pending' | 'running' | 'complete' | 'failed') => void;
  setPreviewData: (data: PreviewResponse) => void;
  setReportJWT: (token: string) => void;
  setFullReport: (data: FullReport) => void;
  setPartialResults: (results: Record<string, PartialModuleResult>) => void;
  addCompletedModule: (moduleKey: string) => void;
  setElapsedSeconds: (s: number) => void;
  setPreliminaryScore: (score: number, counts: { critical: number; high: number; medium: number; low: number }) => void;
  setIsPaid: (paid: boolean) => void;
  resetScan: () => void;
}

export const useScanStore = create<ScanStore>()(
  persist(
    (set) => ({
      scanId: null,
      scanUrl: null,
      scanStatus: 'idle',
      progress: {},
      isPaid: false,       // ← Fixed: was hardcoded true (bypassed paywall)
      reportJWT: null,     // ← Fixed: was 'premium-bypass'
      previewData: null,
      fullReportData: null,
      partialResults: {},
      completedModules: [],
      scanStartedAt: null,
      elapsedSeconds: 0,
      preliminaryScore: null,
      preliminaryCounts: null,

      initScan: (id, url) => set({
        scanId: id,
        scanUrl: url,
        scanStatus: 'pending',
        progress: {},
        previewData: null,
        fullReportData: null,
        partialResults: {},
        completedModules: [],
        scanStartedAt: Date.now(),
        elapsedSeconds: 0,
        preliminaryScore: null,
        preliminaryCounts: null,
      }),

      updateProgress: (progress) => set({ progress }),
      setStatus: (scanStatus) => set({ scanStatus }),
      setPreviewData: (previewData) => set({ previewData }),
      setReportJWT: (reportJWT) => set({ reportJWT }),
      setFullReport: (fullReportData) => set({ fullReportData }),
      setIsPaid: (isPaid) => set({ isPaid }),

      setPartialResults: (results) => set({ partialResults: results }),

      addCompletedModule: (moduleKey) => set((state) => ({
        completedModules: state.completedModules.includes(moduleKey)
          ? state.completedModules
          : [...state.completedModules, moduleKey],
      })),

      setElapsedSeconds: (elapsedSeconds) => set({ elapsedSeconds }),

      setPreliminaryScore: (score, counts) => set({
        preliminaryScore: score,
        preliminaryCounts: counts,
      }),

      resetScan: () => set({
        scanId: null,
        scanUrl: null,
        scanStatus: 'idle',
        progress: {},
        isPaid: false,
        reportJWT: null,
        previewData: null,
        fullReportData: null,
        partialResults: {},
        completedModules: [],
        scanStartedAt: null,
        elapsedSeconds: 0,
        preliminaryScore: null,
        preliminaryCounts: null,
      }),
    }),
    {
      name: 'nanz-storage',
      partialize: (state) => ({
        scanId: state.scanId,
        scanUrl: state.scanUrl,
        reportJWT: state.reportJWT,
        isPaid: state.isPaid,
      }),
    }
  )
);
