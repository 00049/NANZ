'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { AlertTriangle, X } from 'lucide-react';

interface AlertFatigueGuardProps {
  criticalCount: number;
}

const SESSION_KEY = 'shield_fatigue_shown';

export default function AlertFatigueGuard({ criticalCount }: AlertFatigueGuardProps) {
  const [visible, setVisible] = useState(false);
  const scrolledPastRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const firedRef = useRef(false);

  const dismiss = useCallback(() => {
    setVisible(false);
    sessionStorage.setItem(SESSION_KEY, '1');
  }, []);

  const jumpToCritical = useCallback(() => {
    dismiss();
    document.getElementById('findings-critical')?.scrollIntoView({ behavior: 'smooth' });
  }, [dismiss]);

  useEffect(() => {
    if (criticalCount === 0) return;
    if (sessionStorage.getItem(SESSION_KEY)) return;

    const criticalCards = () =>
      Array.from(document.querySelectorAll<HTMLElement>('[data-severity="CRITICAL"]'));

    const handleScroll = () => {
      if (firedRef.current) return;

      const cards = criticalCards();
      const scrollY = window.scrollY + window.innerHeight;
      let passed = 0;
      for (const card of cards) {
        if (card.offsetTop + card.offsetHeight < scrollY) passed++;
      }

      if (passed >= 2) {
        if (!timerRef.current) {
          timerRef.current = setTimeout(() => {
            if (!firedRef.current && !sessionStorage.getItem(SESSION_KEY)) {
              firedRef.current = true;
              setVisible(true);
            }
          }, 3000); // 3s delay after passing cards
        }
      } else {
        if (timerRef.current) {
          clearTimeout(timerRef.current);
          timerRef.current = null;
        }
      }
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => {
      window.removeEventListener('scroll', handleScroll);
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [criticalCount]);

  if (!visible) return null;

  return (
    <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 w-full max-w-sm mx-4">
      <div className="bg-[#1a0505] border-2 border-red-700/70 rounded-2xl shadow-2xl p-5">
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
            <h3 className="text-sm font-black text-red-300">
              You scrolled past {Math.min(criticalCount, 2)} critical security issues
            </h3>
          </div>
          <button onClick={dismiss} className="text-slate-500 hover:text-slate-300 transition-colors shrink-0">
            <X className="w-4 h-4" />
          </button>
        </div>
        <p className="text-xs text-slate-400 mb-4 leading-relaxed">
          These need attention within 24 hours and may be actively exploited right now.
        </p>
        <div className="flex gap-2">
          <button
            onClick={jumpToCritical}
            className="flex-1 py-2 rounded-xl bg-red-700 hover:bg-red-600 text-white text-xs font-bold transition-colors"
          >
            Jump to Critical Issues
          </button>
          <button
            onClick={dismiss}
            className="px-4 py-2 rounded-xl border border-slate-700 text-slate-400 text-xs font-medium hover:border-slate-600 transition-colors"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
}
