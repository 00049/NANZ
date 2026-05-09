// ─────────────────────────────────────────────────────────────────────────────
// Severity Normalizer & Utilities
// Canonical scale: CRITICAL → HIGH → MEDIUM → LOW → INFO
// ─────────────────────────────────────────────────────────────────────────────

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

/**
 * Map any legacy/backend severity string to canonical display value.
 * The backend may return 'RED', 'AMBER', 'GREEN', etc. —
 * this function normalizes them all to the 5-level canonical scale.
 */
export function normalizeSeverity(raw: string): Severity {
  const upper = raw?.toUpperCase()?.trim()

  switch (upper) {
    case 'CRITICAL':      return 'CRITICAL'
    case 'RED':           return 'HIGH'
    case 'HIGH':          return 'HIGH'
    case 'AMBER':         return 'MEDIUM'
    case 'ORANGE':        return 'MEDIUM'
    case 'MEDIUM':        return 'MEDIUM'
    case 'YELLOW':        return 'LOW'
    case 'GREEN':         return 'LOW'
    case 'LOW':           return 'LOW'
    case 'INFO':          return 'INFO'
    case 'INFORMATIONAL': return 'INFO'
    default:              return 'INFO'
  }
}

/** Sort order for severity (lower number = higher priority) */
export const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH:     1,
  MEDIUM:   2,
  LOW:      3,
  INFO:     4,
}

/** Sort findings by severity (highest first) */
export function sortBySeverity<T extends { severity: string }>(
  findings: T[]
): T[] {
  return [...findings].sort((a, b) => {
    const aOrder = SEVERITY_ORDER[normalizeSeverity(a.severity)] ?? 99
    const bOrder = SEVERITY_ORDER[normalizeSeverity(b.severity)] ?? 99
    return aOrder - bOrder
  })
}

/** Get the exact hex color token for a severity */
export function getSeverityColor(severity: Severity): string {
  const colors: Record<Severity, string> = {
    CRITICAL: '#DC2626',
    HIGH:     '#EF4444',
    MEDIUM:   '#F59E0B',
    LOW:      '#22C55E',
    INFO:     '#6B7280',
  }
  return colors[severity]
}

/** Get the transparent background color for severity chips */
export function getSeverityBg(severity: Severity): string {
  const bgs: Record<Severity, string> = {
    CRITICAL: 'rgba(220, 38, 38, 0.12)',
    HIGH:     'rgba(239, 68, 68, 0.10)',
    MEDIUM:   'rgba(245, 158, 11, 0.10)',
    LOW:      'rgba(34, 197, 94, 0.10)',
    INFO:     'rgba(107, 114, 128, 0.10)',
  }
  return bgs[severity]
}

/** Get the border color for severity chips */
export function getSeverityBorder(severity: Severity): string {
  const borders: Record<Severity, string> = {
    CRITICAL: '1px solid rgba(220, 38, 38, 0.25)',
    HIGH:     '1px solid rgba(239, 68, 68, 0.20)',
    MEDIUM:   '1px solid rgba(245, 158, 11, 0.20)',
    LOW:      '1px solid rgba(34, 197, 94, 0.20)',
    INFO:     '1px solid rgba(107, 114, 128, 0.20)',
  }
  return borders[severity]
}
