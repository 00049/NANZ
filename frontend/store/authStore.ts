// WHAT THIS FILE DOES: Zustand store for authentication state. Manages user token,
// email, loading state, and pendingScanUrl (URL awaiting auth before scan submission).
// KEY DEPENDENCIES: zustand, zustand/middleware (persist)
// MOCKED DATA: None — calls real /api/auth/* endpoints

'use client';

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export interface AuthUser {
  id: number;
  email: string;
  full_name?: string;
}

interface AuthStore {
  user: AuthUser | null;
  token: string | null;
  isLoading: boolean;
  pendingScanUrl: string | null;

  // Actions
  setUser: (user: AuthUser | null) => void;
  setToken: (token: string | null) => void;
  setLoading: (loading: boolean) => void;
  setPendingScanUrl: (url: string | null) => void;
  clearUser: () => void;
  signOut: () => void;

  // Legacy compat (used by old login page — keep during transition)
  logout: () => void;
}

export const useAuthStore = create<AuthStore>()(
  persist(
    (set) => ({
      user: null,
      token: null,
      isLoading: false,
      pendingScanUrl: null,

      setUser: (user) => set({ user }),
      setToken: (token) => set({ token }),
      setLoading: (isLoading) => set({ isLoading }),
      setPendingScanUrl: (pendingScanUrl) => set({ pendingScanUrl }),

      clearUser: () => set({ user: null, token: null }),

      signOut: () => {
        // Clear scan recovery data too
        if (typeof window !== 'undefined') {
          localStorage.removeItem('shieldcheck_active_scan');
          localStorage.removeItem('shieldcheck_scan_banner_dismissed');
        }
        set({ user: null, token: null, pendingScanUrl: null });
      },

      // Legacy alias
      logout: () => {
        if (typeof window !== 'undefined') {
          localStorage.removeItem('shieldcheck_active_scan');
        }
        set({ user: null, token: null });
      },
    }),
    {
      name: 'nanz-auth-storage',
      // Only persist token and user — not loading state or pendingScanUrl
      partialize: (state) => ({
        token: state.token,
        user: state.user,
      }),
    }
  )
);
