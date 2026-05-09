'use client';

import React from 'react';
import { ShieldAlert, AlertTriangle, ShieldCheck, Info } from 'lucide-react';
import {
  type Severity,
  getSeverityColor,
  getSeverityBg,
  getSeverityBorder,
} from '@/lib/severity';

// ─── SeverityBadge ────────────────────────────────────────────────────────────

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
  showLabel?: boolean;
}

const SIZE_CONFIG = {
  sm: { iconSize: 12, fontSize: '10px', padding: '2px 6px' },
  md: { iconSize: 14, fontSize: '11px', padding: '3px 8px' },
  lg: { iconSize: 16, fontSize: '13px', padding: '4px 10px' },
} as const;

function getIcon(severity: Severity, size: number) {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return <ShieldAlert size={size} />;
    case 'MEDIUM':
      return <AlertTriangle size={size} />;
    case 'LOW':
      return <ShieldCheck size={size} />;
    case 'INFO':
    default:
      return <Info size={size} />;
  }
}

export function SeverityBadge({
  severity,
  size = 'md',
  showIcon = true,
  showLabel = true,
}: SeverityBadgeProps) {
  const config = SIZE_CONFIG[size];
  const color = getSeverityColor(severity);
  const bg = getSeverityBg(severity);
  const border = getSeverityBorder(severity);

  return (
    <span
      className={`severity-badge severity-${severity.toLowerCase()}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        borderRadius: '4px',
        fontWeight: 600,
        fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
        letterSpacing: '0.05em',
        whiteSpace: 'nowrap',
        color,
        background: bg,
        border,
        padding: config.padding,
        fontSize: config.fontSize,
        lineHeight: 1.2,
      }}
    >
      {showIcon && getIcon(severity, config.iconSize)}
      {showLabel && <span>{severity}</span>}
    </span>
  );
}

// ─── SeverityDot ──────────────────────────────────────────────────────────────

interface SeverityDotProps {
  severity: Severity;
  pulse?: boolean;
}

export function SeverityDot({ severity, pulse = false }: SeverityDotProps) {
  const color = getSeverityColor(severity);
  const shouldPulse = pulse && severity === 'CRITICAL';

  return (
    <span
      style={{
        position: 'relative',
        display: 'inline-flex',
        width: '8px',
        height: '8px',
        flexShrink: 0,
      }}
    >
      {shouldPulse && (
        <span
          style={{
            position: 'absolute',
            inset: 0,
            borderRadius: '50%',
            backgroundColor: color,
            opacity: 0.75,
            animation: 'severityPulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
          }}
        />
      )}
      <span
        style={{
          position: 'relative',
          display: 'inline-flex',
          width: '8px',
          height: '8px',
          borderRadius: '50%',
          backgroundColor: color,
        }}
      />
      <style jsx>{`
        @keyframes severityPulse {
          0%, 100% { transform: scale(1); opacity: 0.75; }
          50% { transform: scale(2); opacity: 0; }
        }
      `}</style>
    </span>
  );
}

export default SeverityBadge;
