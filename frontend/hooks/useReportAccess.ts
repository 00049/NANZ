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
  const { scanStatus, isPaid } = useScanStore();

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

    // Check paid status
    let isLocallyPaid = false;
    if (typeof window !== 'undefined') {
      isLocallyPaid = localStorage.getItem(`paid_scan_${scanId}`) === 'true';
    }
    const isThisScanPaidInStore = isPaid && storedScanId === scanId;

    if (isLocallyPaid || isThisScanPaidInStore) {
      return {
        level: 'full',
        reason: 'Paid access',
        canViewFull: true,
        subscriptionActive: false,
        scanPaid: true,
        showPaywall: false,
      };
    }

    return {
      level: 'preview',
      reason: 'payment_required',
      canViewFull: false,
      subscriptionActive: false,
      scanPaid: false,
      showPaywall: true,
    };
  }, [token, user, scanStatus, scanId, isPaid]);
}
