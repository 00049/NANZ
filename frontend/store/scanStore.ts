import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { PreviewResponse, FullReport } from '../types';

interface ScanStore {
  scanId: string | null;
  scanUrl: string | null;
  scanStatus: 'idle' | 'pending' | 'running' | 'complete' | 'failed';
  progress: Record<string, string>;
  isPaid: boolean;
  reportJWT: string | null;
  previewData: PreviewResponse | null;
  fullReportData: FullReport | null;

  initScan: (id: string, url: string) => void;
  updateProgress: (progress: Record<string, string>) => void;
  setStatus: (status: 'idle' | 'pending' | 'running' | 'complete' | 'failed') => void;
  setPreviewData: (data: PreviewResponse) => void;
  setReportJWT: (token: string) => void;
  setFullReport: (data: FullReport) => void;
  resetScan: () => void;
}

export const useScanStore = create<ScanStore>()(
  persist(
    (set) => ({
      scanId: null,
      scanUrl: null,
      scanStatus: 'idle',
      progress: {},
      isPaid: true,
      reportJWT: 'premium-bypass',
      previewData: null,
      fullReportData: null,

      initScan: (id, url) => set({ 
        scanId: id, 
        scanUrl: url, 
        scanStatus: 'pending',
        progress: {},
        previewData: null,
        fullReportData: null
      }),
      updateProgress: (progress) => set({ progress }),
      setStatus: (scanStatus) => set({ scanStatus }),
      setPreviewData: (previewData) => set({ previewData }),
      setReportJWT: (reportJWT) => set({ reportJWT }),
      setFullReport: (fullReportData) => set({ fullReportData }),
      resetScan: () => set({
        scanId: null,
        scanUrl: null,
        scanStatus: 'idle',
        progress: {},
        isPaid: false,
        reportJWT: null,
        previewData: null,
        fullReportData: null
      }),
    }),
    {
      name: 'nanz-storage',
      partialize: (state) => ({ scanId: state.scanId, reportJWT: state.reportJWT, isPaid: state.isPaid }),
    }
  )
);
