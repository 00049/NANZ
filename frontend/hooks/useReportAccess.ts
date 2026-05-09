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
    // Not authenticated — still allow access (reports are public for now)
    if (!token || !user) {
      return {
        level: 'full',
        reason: 'Free access — no payment required',
        canViewFull: true,
        subscriptionActive: false,
        scanPaid: false,
        showPaywall: false,
      };
    }

    // Scan not yet complete
    if (scanStatus === 'pending' || scanStatus === 'running') {
      return {
        level: 'pending',
        reason: 'Scan in progress',
        canViewFull: false,
        subscriptionActive: false,
        scanPaid: false,
        showPaywall: false,
      };
    }

    // All authenticated users get full access — free for now
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
