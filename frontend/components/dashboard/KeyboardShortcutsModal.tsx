'use client';

import { X, Keyboard } from 'lucide-react';

interface KeyboardShortcutsModalProps {
  open: boolean;
  onClose: () => void;
}

const SECTIONS = [
  {
    title: 'NAVIGATION',
    shortcuts: [
      { keys: ['j', '↓'], action: 'Next finding' },
      { keys: ['k', '↑'], action: 'Previous finding' },
      { keys: ['g g'], action: 'First finding' },
      { keys: ['G'], action: 'Last finding' },
    ],
  },
  {
    title: 'ACTIONS',
    shortcuts: [
      { keys: ['Enter', 'Space'], action: 'Expand / collapse detail' },
      { keys: ['e'], action: 'Escalate severity' },
      { keys: ['a'], action: 'Acknowledge / mark reviewed' },
    ],
  },
  {
    title: 'SEARCH',
    shortcuts: [
      { keys: ['f', '/'], action: 'Focus search box' },
      { keys: ['Escape'], action: 'Clear selection / close' },
    ],
  },
  {
    title: 'HELP',
    shortcuts: [{ keys: ['?'], action: 'Toggle this help' }],
  },
];

export default function KeyboardShortcutsModal({
  open,
  onClose,
}: KeyboardShortcutsModalProps) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div
        className="relative w-full max-w-[400px] mx-4 rounded-xl border overflow-hidden"
        style={{
          backgroundColor: '#111111',
          borderColor: '#1E1E1E',
        }}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between px-5 py-4 border-b"
          style={{ borderColor: '#1E1E1E' }}
        >
          <div className="flex items-center gap-2">
            <Keyboard className="w-4 h-4" style={{ color: '#00A8FF' }} />
            <h3
              className="text-sm font-bold"
              style={{ color: '#FFFFFF' }}
            >
              Keyboard Shortcuts
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-md transition-colors hover:bg-white/5"
            style={{ color: '#6B7280' }}
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="px-5 py-4 space-y-5">
          {SECTIONS.map((section) => (
            <div key={section.title}>
              <div
                className="text-[10px] font-bold uppercase tracking-widest mb-2.5"
                style={{ color: '#6B7280' }}
              >
                {section.title}
              </div>
              <div className="space-y-2">
                {section.shortcuts.map((sc) => (
                  <div
                    key={sc.action}
                    className="flex items-center justify-between"
                  >
                    <div className="flex items-center gap-1.5">
                      {sc.keys.map((key) => (
                        <kbd
                          key={key}
                          className="px-1.5 py-0.5 rounded text-[11px] font-mono font-medium"
                          style={{
                            backgroundColor: '#1E1E1E',
                            color: '#FFFFFF',
                            border: '1px solid #2A2A2A',
                          }}
                        >
                          {key}
                        </kbd>
                      ))}
                    </div>
                    <span
                      className="text-xs"
                      style={{ color: '#9CA3AF' }}
                    >
                      {sc.action}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div
          className="px-5 py-3 border-t text-center"
          style={{ borderColor: '#1E1E1E' }}
        >
          <span className="text-[11px]" style={{ color: '#6B7280' }}>
            Keyboard navigation is active when no input is focused
          </span>
        </div>
      </div>
    </div>
  );
}
