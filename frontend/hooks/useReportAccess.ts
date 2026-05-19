// WHAT THIS FILE DOES: Single source of truth for report access control.
// Currently: ALL reports are FREE — no payment or subscription required.
// When ready to add payments, restore the subscription/payment check logic here.
// KEY DEPENDENCIES: ../store/authStore, react

'use client';

import { useMemo } from 'react';
import { useAuthStore } from '@/store/authStore';
import { useScanStore } from '@/store/scanStore';

export type AccessLevel =
  | 'full'     // full access (currently everyone)
  | 'preview'  // reserved for future paywall use
  | 'pending'  // scan still running
  | 'no_auth'  // not logged in
  | 'loading'; // checking access

export interface ReportAccess {
  level: AccessLevel;
  reason: string;
  canViewFull: boolean;
  subscriptionActive: boolean;
  scanPaid: boolean;
  showPaywall: boolean;
}

export function useReportAccess(scanId: string): ReportAccess {
  const { user, token } = useAuthStore();
  const { scanStatus } = useScanStore();

  return useMemo(() => {
    // Scan not yet complete — only block if this is the ACTIVE scan that's still running
    const isActiveScan = scanStatus === 'pending' || scanStatus === 'running';
    // We only know the scan is pending/running if this scanId matches the stored one
    // If the user navigates directly to a report URL, we don't know the status → allow access
    const { scanId: storedScanId } = useScanStore.getState();
    if (isActiveScan && storedScanId === scanId) {
      return {
        level: 'pending',
        reason: 'Scan in progress',
        canViewFull: false,
        subscriptionActive: false,
        scanPaid: false,
        showPaywall: false,
      };
    }

    // All users get full access — free for now
    return {
      level: 'full',
      reason: 'Free access — no payment required',
      canViewFull: true,
      subscriptionActive: false,
      scanPaid: false,
      showPaywall: false,
    };
  }, [token, user, scanStatus, scanId]);
}
