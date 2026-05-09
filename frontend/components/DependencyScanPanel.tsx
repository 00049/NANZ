'use client';

import React, { useState } from 'react';
import { GitBranch, Package, AlertTriangle, XCircle, ChevronDown, ChevronRight, ExternalLink, ShieldAlert } from 'lucide-react';
import { normalizeSeverity } from '@/lib/severity';

interface VulnerableLibrary {
  name: string;
  detected_version: string;
  min_safe_version: string;
  severity: string;
  cve_ref?: string;
  osv_ids?: string[];
  source?: string;
}

interface DependencyLibrary {
  name: string;
  detected_version: string;
  source: string;
  is_outdated: boolean;
}

interface OSVMatch {
  library: string;
  version: string;
  osv_id: string;
  summary: string;
  severity: string;
}

interface DependencyScanProps {
  data?: {
    detected_libraries?: DependencyLibrary[];
    vulnerable_libraries?: VulnerableLibrary[];
    package_files_exposed?: { path: string; size_bytes: number; severity: string }[];
    dependency_confusion_risk?: { package: string; file: string; severity: string; detail: string }[];
    known_vuln_patterns?: { description: string; cve: string; file: string; severity: string }[];
    osv_matches?: OSVMatch[];
    total_dependencies_found?: number;
    outdated_count?: number;
    critical_vuln_count?: number;
    error?: string;
  };
}

const SEV_BADGE: Record<string, string> = {
  CRITICAL: 'bg-red-500/10 text-red-400 border-red-500/30',
  HIGH:     'bg-orange-500/10 text-orange-400 border-orange-500/30',
  MEDIUM:   'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  LOW:      'bg-green-500/10 text-green-400 border-green-500/30',
  INFO:     'bg-slate-500/10 text-slate-400 border-slate-500/30',
};

export default function DependencyScanPanel({ data }: DependencyScanProps) {
  const [showAll, setShowAll] = useState(false);

  if (!data) return null;

  const vulnLibs = data.vulnerable_libraries || [];
  const packageFiles = data.package_files_exposed || [];
  const confusionRisks = data.dependency_confusion_risk || [];
  const knownVulns = data.known_vuln_patterns || [];
  const osvMatches = data.osv_matches || [];
  const allLibs = data.detected_libraries || [];

  const totalVulnerable = vulnLibs.length + knownVulns.length + osvMatches.length;
  const displayLibs = showAll ? allLibs : allLibs.slice(0, 12);

  if (totalVulnerable === 0 && packageFiles.length === 0 && allLibs.length === 0) return null;

  return (
    <section id="dependency-scan" className="scroll-mt-8">
      <h2 className="text-2xl font-bold text-text-primary mb-6 border-b border-card-border pb-2 flex items-center gap-3">
        <Package className="w-6 h-6 text-primary" />
        Dependency Security Analysis (SCA)
      </h2>

      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        {[
          { label: 'Libraries Found',   value: data.total_dependencies_found || 0, color: 'text-text-primary' },
          { label: 'Outdated',          value: data.outdated_count || 0,           color: 'text-yellow-400' },
          { label: 'Vulnerable',        value: totalVulnerable,                    color: 'text-red-400' },
          { label: 'Package Files Exposed', value: packageFiles.length,            color: 'text-orange-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-surface border border-card-border rounded-card p-3 text-center">
            <div className={`text-2xl font-black ${color}`}>{value}</div>
            <div className="text-xs text-text-muted mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Vulnerable libraries */}
      {vulnLibs.length > 0 && (
        <div className="mb-6">
          <h3 className="text-sm font-bold text-text-muted uppercase tracking-widest mb-3 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-orange-400" />
            Outdated / Vulnerable Libraries
          </h3>
          <div className="grid sm:grid-cols-2 gap-2">
            {vulnLibs.map((lib, i) => {
              const badgeClass = SEV_BADGE[normalizeSeverity(lib.severity)] || SEV_BADGE.MEDIUM;
              return (
                <div
                  key={`${lib.name}-${i}`}
                  className="bg-surface border border-card-border rounded-card p-3 flex items-center gap-3"
                >
                  <GitBranch className="w-4 h-4 text-orange-400 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-sm text-text-primary">{lib.name}</span>
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${badgeClass}`}>
                        {normalizeSeverity(lib.severity)}
                      </span>
                    </div>
                    <div className="text-xs text-text-muted mt-0.5">
                      Found: <span className="text-orange-400 font-mono">{lib.detected_version}</span>
                      {' → '}
                      Min safe: <span className="text-green-400 font-mono">{lib.min_safe_version}+</span>
                    </div>
                    {lib.cve_ref && (
                      <span className="text-[10px] text-red-400 font-mono mt-0.5 inline-block">{lib.cve_ref}</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* OSV matches */}
      {osvMatches.length > 0 && (
        <div className="mb-6">
          <h3 className="text-sm font-bold text-text-muted uppercase tracking-widest mb-3 flex items-center gap-2">
            <XCircle className="w-4 h-4 text-red-400" />
            OSV.dev Vulnerability Matches
          </h3>
          <div className="flex flex-col gap-2">
            {osvMatches.map((match, i) => (
              <div key={i} className="bg-red-500/5 border border-red-500/20 rounded-card p-3 flex items-start gap-3">
                <ShieldAlert className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                <div className="flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-bold text-sm text-text-primary">{match.library}</span>
                    <span className="text-xs font-mono text-orange-400">{match.version}</span>
                    <a
                      href={`https://osv.dev/vulnerability/${match.osv_id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-primary hover:underline flex items-center gap-0.5"
                      onClick={e => e.stopPropagation()}
                    >
                      {match.osv_id}
                      <ExternalLink className="w-2.5 h-2.5" />
                    </a>
                  </div>
                  <p className="text-xs text-text-muted mt-1">{match.summary}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Package files exposed */}
      {packageFiles.length > 0 && (
        <div className="mb-6">
          <h3 className="text-sm font-bold text-text-muted uppercase tracking-widest mb-3 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
            Exposed Package Manifests
          </h3>
          <div className="flex flex-col gap-2">
            {packageFiles.map((pf, i) => {
              const badgeClass = SEV_BADGE[normalizeSeverity(pf.severity)] || SEV_BADGE.MEDIUM;
              return (
                <div key={i} className="bg-surface border border-card-border rounded-card p-3 flex items-center gap-3">
                  <Package className="w-4 h-4 text-yellow-400 shrink-0" />
                  <div className="flex-1">
                    <span className="font-mono text-sm text-text-primary">{pf.path}</span>
                    <span className="ml-2 text-xs text-text-muted">({(pf.size_bytes / 1024).toFixed(1)} KB)</span>
                  </div>
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${badgeClass}`}>
                    {normalizeSeverity(pf.severity)}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Dependency confusion */}
      {confusionRisks.length > 0 && (
        <div className="mb-6">
          <h3 className="text-sm font-bold text-text-muted uppercase tracking-widest mb-3 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            Dependency Confusion Risks
          </h3>
          <div className="flex flex-col gap-2">
            {confusionRisks.map((r, i) => (
              <div key={i} className="bg-red-500/5 border border-red-500/20 rounded-card p-3">
                <div className="font-mono text-sm text-orange-400">{r.package}</div>
                <p className="text-xs text-text-muted mt-1">{r.detail}</p>
                <span className="text-[10px] text-text-muted font-mono mt-1 inline-block">in {r.file}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All detected libraries */}
      {allLibs.length > 0 && (
        <div>
          <h3 className="text-sm font-bold text-text-muted uppercase tracking-widest mb-3">
            Detected Client-Side Libraries ({allLibs.length})
          </h3>
          <div className="flex flex-wrap gap-2">
            {displayLibs.map((lib, i) => (
              <div
                key={i}
                className={`
                  flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-mono
                  ${lib.is_outdated
                    ? 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400'
                    : 'bg-surface border-card-border text-text-muted'
                  }
                `}
              >
                {lib.name}
                <span className="opacity-70">@{lib.detected_version}</span>
                {lib.is_outdated && <AlertTriangle className="w-3 h-3" />}
              </div>
            ))}
          </div>
          {allLibs.length > 12 && (
            <button
              onClick={() => setShowAll(!showAll)}
              className="mt-3 text-xs text-primary hover:text-primary/80 font-bold"
            >
              {showAll ? 'Show less ↑' : `Show all ${allLibs.length} ↓`}
            </button>
          )}
        </div>
      )}
    </section>
  );
}
