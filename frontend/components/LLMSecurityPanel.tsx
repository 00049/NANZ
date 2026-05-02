'use client';

import React, { useState } from 'react';
import { Cpu, AlertTriangle, XCircle, CheckCircle2, ChevronDown, ChevronRight, Bot, ShieldAlert, Zap } from 'lucide-react';

interface LLMFinding {
  owasp_id: string;
  owasp_name: string;
  endpoint: string;
  severity: string;
  detail: string;
  confirmed?: boolean;
}

interface LLMSecurityData {
  llm_surface_detected?: boolean;
  active_llm_endpoints?: string[];
  model_ids_disclosed?: string[];
  api_keys_in_response?: { type: string; endpoint: string; severity: string }[];
  system_prompt_leaked?: boolean;
  system_prompt_hints?: { endpoint: string; probe: string; severity: string }[];
  prompt_injection_surfaces?: { type: string; matched: string; severity: string; detail: string }[];
  indirect_injection_surfaces?: { endpoint: string; severity: string; detail: string }[];
  excessive_agency_indicators?: { endpoint: string; severity: string; detail: string }[];
  rate_limited?: boolean;
  token_limit_enforced?: boolean;
  findings?: LLMFinding[];
  probes_sent?: number;
  error?: string;
}

interface LLMSecurityPanelProps {
  data?: LLMSecurityData;
}

const OWASP_LLM_COLORS: Record<string, string> = {
  LLM01: '#ef4444',
  LLM02: '#f97316',
  LLM03: '#eab308',
  LLM04: '#84cc16',
  LLM05: '#22c55e',
  LLM06: '#14b8a6',
  LLM07: '#6366f1',
  LLM08: '#8b5cf6',
  LLM09: '#ec4899',
  LLM10: '#f43f5e',
};

const SEV_CONFIG: Record<string, { bg: string; text: string; border: string; label: string }> = {
  CRITICAL: { bg: 'bg-red-500/10',    text: 'text-red-400',    border: 'border-red-500/30',    label: 'Critical' },
  RED:      { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30', label: 'High' },
  AMBER:    { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30', label: 'Medium' },
  GREEN:    { bg: 'bg-green-500/10',  text: 'text-green-400',  border: 'border-green-500/30',  label: 'Low' },
};

export default function LLMSecurityPanel({ data }: LLMSecurityPanelProps) {
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);

  if (!data) return null;

  const findings = data.findings || [];
  const hasLLM = data.llm_surface_detected || findings.length > 0;

  if (!hasLLM) return null;

  return (
    <section id="llm-security" className="scroll-mt-8">
      <h2 className="text-2xl font-bold text-text-primary mb-6 border-b border-card-border pb-2 flex items-center gap-3">
        <Bot className="w-6 h-6 text-primary" />
        AI / LLM Security Audit
        <span className="text-xs font-normal text-text-muted ml-1">OWASP LLM Top 10 (2025)</span>
      </h2>

      {/* Status cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
        {[
          {
            label: 'LLM Surface',
            value: data.llm_surface_detected ? 'Detected' : 'Not Found',
            color: data.llm_surface_detected ? 'text-orange-400' : 'text-green-400',
            icon: data.llm_surface_detected ? <Cpu className="w-4 h-4" /> : <CheckCircle2 className="w-4 h-4" />,
          },
          {
            label: 'System Prompt',
            value: data.system_prompt_leaked ? 'LEAKED' : 'Protected',
            color: data.system_prompt_leaked ? 'text-red-400' : 'text-green-400',
            icon: data.system_prompt_leaked ? <XCircle className="w-4 h-4" /> : <CheckCircle2 className="w-4 h-4" />,
          },
          {
            label: 'Rate Limiting',
            value: data.rate_limited ? 'Enforced' : 'MISSING',
            color: data.rate_limited ? 'text-green-400' : 'text-red-400',
            icon: data.rate_limited ? <CheckCircle2 className="w-4 h-4" /> : <Zap className="w-4 h-4" />,
          },
          {
            label: 'API Keys',
            value: (data.api_keys_in_response?.length || 0) > 0 ? 'EXPOSED!' : 'Safe',
            color: (data.api_keys_in_response?.length || 0) > 0 ? 'text-red-400' : 'text-green-400',
            icon: (data.api_keys_in_response?.length || 0) > 0
              ? <ShieldAlert className="w-4 h-4" />
              : <CheckCircle2 className="w-4 h-4" />,
          },
        ].map(({ label, value, color, icon }) => (
          <div key={label} className="bg-surface border border-card-border rounded-card p-3 text-center">
            <div className={`flex items-center justify-center gap-1.5 mb-1 ${color}`}>
              {icon}
              <span className="font-black text-sm">{value}</span>
            </div>
            <div className="text-xs text-text-muted">{label}</div>
          </div>
        ))}
      </div>

      {/* Active endpoints */}
      {(data.active_llm_endpoints?.length || 0) > 0 && (
        <div className="mb-4 bg-surface border border-card-border rounded-card p-4">
          <h3 className="text-xs font-bold text-text-muted uppercase tracking-widest mb-3">
            Active LLM Endpoints ({data.active_llm_endpoints!.length})
          </h3>
          <div className="flex flex-wrap gap-2">
            {data.active_llm_endpoints!.map((ep, i) => (
              <span key={i} className="text-xs font-mono bg-primary/10 text-primary border border-primary/20 px-2 py-1 rounded">
                {ep}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Model disclosures */}
      {(data.model_ids_disclosed?.length || 0) > 0 && (
        <div className="mb-4 bg-surface border border-yellow-500/20 rounded-card p-4">
          <h3 className="text-xs font-bold text-yellow-400 uppercase tracking-widest mb-2">
            Model IDs Disclosed
          </h3>
          <div className="flex flex-wrap gap-2">
            {data.model_ids_disclosed!.map((model, i) => (
              <span key={i} className="text-xs font-mono text-yellow-400 bg-yellow-500/10 border border-yellow-500/20 px-2 py-1 rounded">
                {model}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* OWASP LLM Findings */}
      {findings.length > 0 && (
        <div>
          <h3 className="text-sm font-bold text-text-muted uppercase tracking-widest mb-3">
            OWASP LLM Top 10 Findings ({findings.length})
          </h3>
          <div className="flex flex-col gap-2">
            {findings.map((finding, idx) => {
              const sev = SEV_CONFIG[finding.severity] || SEV_CONFIG.AMBER;
              const isExpanded = expandedIdx === idx;
              const dotColor = OWASP_LLM_COLORS[finding.owasp_id] || '#6366f1';

              return (
                <div
                  key={idx}
                  className={`rounded-card border overflow-hidden cursor-pointer transition-all ${sev.bg} ${sev.border}`}
                  onClick={() => setExpandedIdx(isExpanded ? null : idx)}
                >
                  <div className="flex items-center gap-3 p-3">
                    {/* OWASP ID dot */}
                    <div
                      className="w-8 h-8 rounded-full flex items-center justify-center text-[9px] font-black text-white shrink-0"
                      style={{ backgroundColor: `${dotColor}30`, border: `1px solid ${dotColor}60`, color: dotColor }}
                    >
                      {finding.owasp_id}
                    </div>

                    {/* Name + severity */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-bold text-sm text-text-primary">{finding.owasp_name}</span>
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${sev.bg} ${sev.text} ${sev.border}`}>
                          {sev.label}
                        </span>
                        {finding.confirmed && (
                          <span className="text-[10px] text-red-400 font-bold">• CONFIRMED</span>
                        )}
                      </div>
                      <p className="text-xs text-text-muted truncate">{finding.detail}</p>
                    </div>

                    {isExpanded ? <ChevronDown className="w-4 h-4 text-text-muted shrink-0" /> : <ChevronRight className="w-4 h-4 text-text-muted shrink-0" />}
                  </div>

                  {isExpanded && (
                    <div className="px-3 pb-3 border-t border-card-border/30">
                      <p className="text-sm text-text-primary mt-2 leading-relaxed">{finding.detail}</p>
                      {finding.endpoint && (
                        <div className="mt-2 p-2 bg-background/60 rounded-md">
                          <code className="text-xs text-text-muted font-mono">{finding.endpoint}</code>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Probes sent note */}
      {(data.probes_sent || 0) > 0 && (
        <p className="mt-4 text-xs text-text-muted">
          {data.probes_sent} passive probes sent — no exploit payloads
        </p>
      )}
    </section>
  );
}
