'use client';

import React from 'react';
import { AlertTriangle, ShieldAlert, Globe, FileSearch, ExternalLink } from 'lucide-react';

interface BrandThreat {
  threat_type: 'typosquat' | 'homoglyph' | 'ct_alert';
  domain: string;
  similarity_score: number;
  is_live: boolean;
  cert_issued_at?: string;
  issuing_ca?: string;
  ip_address?: string;
  threat_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

interface BrandThreatData {
  domain: string;
  total_threats: number;
  critical_threats: number;
  high_threats: number;
  medium_threats: number;
  typosquats_checked: number;
  homoglyphs_checked: number;
  ct_certs_checked: number;
  threats: BrandThreat[];
}

const THREAT_TYPE_META = {
  typosquat: {
    label: 'Typosquatting',
    icon: <Globe className="w-4 h-4" />,
    description: 'Domain registered with slight character variations to deceive users',
    tier: 'Tier 1',
    color: 'text-orange-400 border-orange-500/30 bg-orange-500/10',
  },
  homoglyph: {
    label: 'Homoglyph Spoof',
    icon: <ShieldAlert className="w-4 h-4" />,
    description: 'Visually identical domain using Unicode lookalike characters (Cyrillic/Greek)',
    tier: 'Tier 2',
    color: 'text-red-400 border-red-500/30 bg-red-500/10',
  },
  ct_alert: {
    label: 'CT Log Alert',
    icon: <FileSearch className="w-4 h-4" />,
    description: 'New certificate issued for a similar domain — potential phishing infrastructure',
    tier: 'Tier 3',
    color: 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10',
  },
};

const LEVEL_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-500/20 border-red-500/40',
  HIGH:     'text-orange-400 bg-orange-500/20 border-orange-500/40',
  MEDIUM:   'text-yellow-400 bg-yellow-500/20 border-yellow-500/40',
  LOW:      'text-blue-400 bg-blue-500/20 border-blue-500/40',
};

function ThreatCard({ threat }: { threat: BrandThreat }) {
  const meta = THREAT_TYPE_META[threat.threat_type] || THREAT_TYPE_META.ct_alert;

  return (
    <div className={`rounded-card border p-4 ${meta.color}`}>
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          {meta.icon}
          <span className="text-xs font-bold uppercase tracking-wider opacity-80">{meta.tier} — {meta.label}</span>
        </div>
        <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${LEVEL_COLORS[threat.threat_level]}`}>
          {threat.threat_level}
        </span>
      </div>

      <div className="flex items-center gap-2 mb-1">
        <code className="text-sm font-bold text-text-primary">{threat.domain}</code>
        <a
          href={`https://${threat.domain}`}
          target="_blank"
          rel="noopener noreferrer"
          className="opacity-50 hover:opacity-100 transition-opacity"
        >
          <ExternalLink className="w-3 h-3" />
        </a>
        {threat.is_live && (
          <span className="text-[10px] font-bold text-red-400 bg-red-500/20 px-1.5 py-0.5 rounded">LIVE</span>
        )}
      </div>

      <p className="text-xs text-text-muted mb-2">{meta.description}</p>

      <div className="grid grid-cols-2 gap-2 text-xs text-text-muted">
        <div>
          <span className="opacity-60">Similarity: </span>
          <span className="font-bold text-text-primary">{Math.round(threat.similarity_score * 100)}%</span>
        </div>
        {threat.cert_issued_at && (
          <div>
            <span className="opacity-60">Cert Issued: </span>
            <span className="font-bold text-text-primary">
              {new Date(threat.cert_issued_at).toLocaleDateString()}
            </span>
          </div>
        )}
        {threat.issuing_ca && (
          <div className="col-span-2">
            <span className="opacity-60">Issuing CA: </span>
            <span className="font-medium">{threat.issuing_ca.split(',')[0]}</span>
          </div>
        )}
      </div>
    </div>
  );
}

export default function BrandThreatCard({ data }: { data: BrandThreatData | null }) {
  if (!data) return null;

  const threats = data.threats || [];
  const total_threats = data.total_threats || 0;
  const critical_threats = data.critical_threats || 0;
  const high_threats = data.high_threats || 0;
  const typosquats_checked = data.typosquats_checked || 0;
  const homoglyphs_checked = data.homoglyphs_checked || 0;
  const ct_certs_checked = data.ct_certs_checked || 0;
  const domain = data.domain || 'this domain';

  return (
    <section id="brand-threats" className="scroll-mt-8">
      <div className="flex items-center gap-3 mb-6 border-b border-card-border pb-3">
        <ShieldAlert className="w-6 h-6 text-orange-400" />
        <h2 className="text-2xl font-bold text-text-primary">Brand Protection & Threat Intelligence</h2>
        {total_threats > 0 && (
          <span className="ml-auto bg-orange-500/20 text-orange-400 font-black text-sm px-3 py-1 rounded-full border border-orange-500/30">
            {total_threats} Threat{total_threats !== 1 ? 's' : ''} Detected
          </span>
        )}
      </div>

      {/* Coverage summary */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        {[
          { label: 'Typosquats Checked', value: typosquats_checked, tier: 'Tier 1', color: 'text-orange-400' },
          { label: 'Homoglyphs Checked', value: homoglyphs_checked, tier: 'Tier 2', color: 'text-red-400' },
          { label: 'CT Certs Scanned', value: ct_certs_checked, tier: 'Tier 3', color: 'text-yellow-400' },
        ].map((stat, i) => (
          <div key={i} className="bg-surface rounded-card border border-card-border p-4 text-center">
            <div className={`text-2xl font-black ${stat.color}`}>{stat.value.toLocaleString()}</div>
            <div className="text-xs text-text-muted mt-1">{stat.label}</div>
            <div className="text-[10px] font-bold text-text-muted opacity-50 mt-0.5">{stat.tier}</div>
          </div>
        ))}
      </div>

      {total_threats === 0 ? (
        <div className="bg-green-500/10 border border-green-500/30 rounded-card p-6 text-center">
          <div className="w-12 h-12 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-3">
            <AlertTriangle className="w-6 h-6 text-green-400" />
          </div>
          <h3 className="font-bold text-green-400 text-lg mb-1">No Brand Threats Detected</h3>
          <p className="text-text-muted text-sm">
            No typosquatting, homoglyph, or CT log threats were identified for <strong>{domain}</strong>.
          </p>
        </div>
      ) : (
        <>
          {(critical_threats > 0 || high_threats > 0) && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-card p-4 mb-4 flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
              <p className="text-sm text-red-300">
                <strong>{critical_threats + high_threats} live threat(s)</strong> detected. These domains are actively resolving
                and may be used for phishing or brand impersonation. Report them immediately to your domain registrar and CERT-In.
              </p>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {threats.map((threat, i) => (
              <ThreatCard key={i} threat={threat} />
            ))}
          </div>
        </>
      )}
    </section>
  );
}
