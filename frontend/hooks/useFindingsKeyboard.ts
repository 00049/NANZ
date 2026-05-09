'use client';

import { useState, useEffect, useRef, useCallback, RefObject } from 'react';

interface UseFindingsKeyboardOptions<T = any> {
  findings: T[];
  onSelect?: (index: number) => void;
  onExpand?: (index: number) => void;
  onEscalate?: (finding: T) => void;
  onAcknowledge?: (finding: T) => void;
  containerRef: RefObject<HTMLElement>;
  enabled?: boolean;
}

export function useFindingsKeyboard({
  findings,
  onSelect,
  onExpand,
  onEscalate,
  onAcknowledge,
  containerRef,
  enabled = true,
}: UseFindingsKeyboardOptions) {
  const [selectedIndex, setSelectedIndex] = useState<number>(-1);
  const [expandedIndex, setExpandedIndex] = useState<number>(-1);
  const [showHelp, setShowHelp] = useState(false);
  const lastGPress = useRef<number>(0);

  const selectIndex = useCallback(
    (index: number) => {
      setSelectedIndex(index);
      onSelect?.(index);
    },
    [onSelect],
  );

  useEffect(() => {
    if (!enabled) return;

    function handleKeyDown(e: KeyboardEvent) {
      // Ignore if user is typing in an input
      const tag = (e.target as HTMLElement).tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') {
        if (e.key === 'Escape') {
          (e.target as HTMLElement).blur();
        }
        return;
      }

      switch (e.key) {
        case 'j':
        case 'ArrowDown':
          e.preventDefault();
          setSelectedIndex((i) => {
            const next = Math.min(i + 1, findings.length - 1);
            onSelect?.(next);
            return next;
          });
          break;

        case 'k':
        case 'ArrowUp':
          e.preventDefault();
          setSelectedIndex((i) => {
            const prev = Math.max(i - 1, 0);
            onSelect?.(prev);
            return prev;
          });
          break;

        case 'Enter':
        case ' ':
          e.preventDefault();
          if (selectedIndex >= 0) {
            setExpandedIndex((i) => {
              const next = i === selectedIndex ? -1 : selectedIndex;
              onExpand?.(next);
              return next;
            });
          }
          break;

        case 'e':
          e.preventDefault();
          if (selectedIndex >= 0 && findings[selectedIndex]) {
            onEscalate?.(findings[selectedIndex]);
          }
          break;

        case 'a':
          e.preventDefault();
          if (selectedIndex >= 0 && findings[selectedIndex]) {
            onAcknowledge?.(findings[selectedIndex]);
          }
          break;

        case 'f':
        case '/': {
          e.preventDefault();
          const searchInput = document.querySelector(
            '[data-findings-search]',
          ) as HTMLInputElement;
          searchInput?.focus();
          break;
        }

        case 'g': {
          e.preventDefault();
          const now = Date.now();
          if (now - lastGPress.current < 500) {
            // double-g: go to first
            selectIndex(0);
          }
          lastGPress.current = now;
          break;
        }

        case 'G':
          e.preventDefault();
          selectIndex(findings.length - 1);
          break;

        case 'Escape':
          e.preventDefault();
          setExpandedIndex(-1);
          setSelectedIndex(-1);
          setShowHelp(false);
          break;

        case '?':
          e.preventDefault();
          setShowHelp((v) => !v);
          break;
      }
    }

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [enabled, findings, selectedIndex, onSelect, onExpand, onEscalate, onAcknowledge, selectIndex]);

  // Auto-scroll selected item into view
  useEffect(() => {
    if (selectedIndex < 0) return;
    const container = containerRef.current;
    if (!container) return;
    const rows = container.querySelectorAll('[data-finding-row]');
    const target = rows[selectedIndex] as HTMLElement;
    target?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }, [selectedIndex, containerRef]);

  return {
    selectedIndex,
    expandedIndex,
    showHelp,
    setSelectedIndex: selectIndex,
    setExpandedIndex,
    setShowHelp,
  };
}
