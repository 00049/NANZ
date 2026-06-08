// ─────────────────────────────────────────────────────────────────────────────
// ShieldCheck / NAANZ — Frontend Type Definitions v2
// Includes full enterprise fields: ALE, RRF, EPSS, CISA KEV, SLA, compliance
// ─────────────────────────────────────────────────────────────────────────────

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'RED' | 'AMBER' | 'GREEN' | 'INFO';
export type VisualWeight = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FixDifficulty = 'Easy' | 'Medium' | 'Hard';
export type SLATier = 'P0' | 'P1' | 'P2' | 'P3';
export type Role = 'ciso' | 'analyst' | 'developer';
export type SBOMFormat = 'cyclonedx' | 'spdx';

// ─── Scan lifecycle ───────────────────────────────────────────────────────────

export interface ScanResponse {
  scan_id: string;
  status: string;
  estimated_duration_seconds: number;
}

export interface ScanProgress {
  scan_id: string;
  status: string;
  progress: Record<string, string>;
  overall_severity?: Severity;
  overall_score?: number;
  preview_risk?: {
    title: string;
    severity: Severity;
    business_impact: string;
    fix_action: string;
    confidence: string;
    fix_difficulty: FixDifficulty;
    estimated_fix_time: string;
  };
}

// ─── Free preview ─────────────────────────────────────────────────────────────

export interface RiskPreview {
  title: string;
  severity: Severity;
  business_impact: string;
  ale_reduction_inr?: number;
  ale_display?: string;
  sla_tier?: SLATier;
  sla_deadline?: string;
}

export interface PreviewResponse {
  overall_severity: Severity;
  overall_score: number;
  executive_summary: string;
  top_risks: RiskPreview[];
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  total_findings: number;
  locked_risks_count: number;
  is_paid: boolean;
  waf_detected?: boolean;
  waf_provider?: string;
  industry_comparison?: string;
  // Enterprise preview fields
  total_ale_reduction_inr?: number;
  total_ale_display?: string;
  dpdp_compliance_score?: number;
  dpdp_risk_level?: string;
  dpdp_penalty_crore?: number;
  kev_findings_count?: number;
}

// ─── Risk Item — full enterprise finding ──────────────────────────────────────

export interface RiskItem {
  id?: string;
  title: string;
  severity: Severity;
  cvss_score?: number;
  cve_id?: string;
  check_domain?: string;
  check_type?: string;
  key?: string;
  module?: string;
  
  // ── 5-Part Finding Structure ────────────────────────────────────────────────
  observation?: string;
  business_impact: string;
  evidence?: string;
  fix_action: string;
  verification_steps?: string;
  
  technical_detail?: string;
  fix_difficulty?: FixDifficulty;
  estimated_fix_time?: string;
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  references?: string[];

  // ── EPSS + CISA KEV ──────────────────────────────────────────────────────
  epss_score?: number;           // 0.0–1.0
  epss_percentile?: number;      // 0–100
  cisa_kev?: boolean;            // In CISA Known Exploited Vulns catalog
  actively_exploited?: boolean;  // kev OR epss >= 0.5
  epss_badge?: string;           // "🚨 CISA KEV" | "⚡ Actively Exploited"

  // ── Contextual severity override ──────────────────────────────────────────
  contextual_severity?: Severity;
  severity_adjusted?: boolean;
  severity_reason?: string;
  
  // ── Exceptions ────────────────────────────────────────────────────────────
  exception_status?: 'accepted' | 'mitigated' | 'false_positive';
  exception_justification?: string;
  exception_owner?: string;
  exception_expires_at?: string;
  original_severity?: Severity;

  // ── RRF (Risk Reduction Factor) ───────────────────────────────────────────
  rrf_score?: number;            // 0.00–3.00
  rrf_label?: string;            // "High" | "Medium" | "Low"
  rrf_display?: string;          // "Risk Reduction: 2.14 (High)"

  // ── ALE (Annual Loss Expectancy) in INR ───────────────────────────────────
  ale_reduction_inr?: number;
  ale_display?: string;          // "Rs. 38.2 lakh/year"
  ale_data?: Record<string, unknown>;

  // ── SLA Tier ──────────────────────────────────────────────────────────────
  sla_deadline?: string;         // "24 hours" | "7 days" | "30 days" | "90 days"
  sla_tier?: SLATier;

  // ── OWASP / compliance mapping ────────────────────────────────────────────
  owasp_categories?: string[];
  compliance_violations?: any[];  // ["DPDP S.8(4)"] or [{framework, clause_id}]

  // ── Scanner provenance ────────────────────────────────────────────────────
  source_scanner?: string;
  ingested?: boolean;
  confirmed_by?: string[];
  affected_file?: string;
  affected_line?: number;
}

// ─── Score breakdown (transparent scoring) ────────────────────────────────────

export interface ScoreBreakdownItem {
  label: string;
  delta: number;         // negative = penalty, positive = bonus
  reason: string;
  finding_key?: string;
}

export interface ScoreBreakdown {
  base_score: number;
  final_score: number;
  items: ScoreBreakdownItem[];
  epss_adjustments?: string[];
  waf_adjustments?: string[];
}

// ─── OWASP Coverage ───────────────────────────────────────────────────────────

export interface OWASPCategory {
  id: string;                    // "A01:2021"
  name: string;
  status: 'TESTED' | 'PARTIAL' | 'NOT_TESTED';
  findings_count: number;
  highest_severity: Severity;
  findings: string[];
  modules_tested: string[];
  notes?: string;
  // LLM-specific (for LLM Top 10)
  description?: string;
}

export interface OWASPCoverage {
  categories: Record<string, OWASPCategory>;
  owasp_coverage_score: number;
  owasp_overall_pass: number;
  owasp_partial_test: number;
  owasp_not_tested: number;
}

export interface OWASPLLMCoverage {
  categories: Record<string, OWASPCategory>;
  llm_coverage_score: number;
  llm_endpoints_scanned: number;
  total_llm_findings: number;
  llm_detected: boolean;
}

// ─── Compliance engines ───────────────────────────────────────────────────────

export interface DPDPViolation {
  section: string;
  section_title: string;
  description: string;
  trigger_findings: string[];
  severity: string;
  max_penalty_crore: number;
  penalty_display: string;
  remediation_hint: string;
}

export interface DPDPReport {
  dpdp_score: number;
  dpdp_risk_level: string;
  dpdp_status: string;
  is_significant_data_fiduciary: boolean;
  violated_sections: DPDPViolation[];
  passing_controls: string[];
  total_max_penalty_crore: number;
  total_penalty_display: string;
  audit_evidence: unknown[];
}

export interface GDPRReport {
  gdpr_score: number;
  gdpr_status: string;
  violated_articles: {
    article: string;
    article_title: string;
    description: string;
    trigger_findings: string[];
    severity: string;
    max_fine_eur: string;
    remediation_hint: string;
  }[];
  passing_controls: string[];
  breach_notification_required: boolean;
  dpo_referral_recommended: boolean;
}

export interface PCIReport {
  pci_score: number;
  pci_status: string;
  pci_applicable: boolean;
  violated_requirements: {
    requirement: string;
    requirement_title: string;
    description: string;
    trigger_findings: string[];
    severity: string;
    qsa_note: string;
  }[];
  passing_controls: string[];
  waf_detected: boolean;
}

export interface SOC2Report {
  soc2_score: number;
  soc2_status: string;
  violated_criteria: {
    criteria_id: string;
    criteria_title: string;
    description: string;
    trigger_findings: string[];
    severity: string;
    auditor_note: string;
  }[];
  passing_controls: string[];
  continuous_monitoring_gaps: string[];
}

export interface ComplianceV2 {
  dpdp?: DPDPReport;
  gdpr?: GDPRReport;
  pci_dss?: PCIReport;
  soc2?: SOC2Report;
}

// ─── Risk portfolio summary ───────────────────────────────────────────────────

export interface PortfolioRiskSummary {
  total_ale_reduction_inr: number;
  total_ale_display: string;
  avg_rrf_score: number;
  highest_rrf: number;
  kev_findings_count: number;
  epss_enriched_count: number;
  severity_adjusted_count: number;
  p0_count: number;
  p1_count: number;
  p2_count: number;
  p3_count: number;
}

// ─── ASPM report ─────────────────────────────────────────────────────────────

export interface ASPMReport {
  aspm_score: number;
  posture_tier: string;
  posture_label: string;
  posture_color: string;
  posture_description: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  total_findings: number;
  // Legacy OWASP
  owasp_coverage: OWASPCategory[];
  owasp_covered_count: number;
  owasp_total: number;
  // Structured OWASP v2
  owasp_top10_structured?: OWASPCoverage;
  owasp_llm_structured?: OWASPLLMCoverage;
  owasp_coverage_score?: number;
  owasp_llm_coverage_score?: number;
  // Module data
  modules_tested: string[];
  modules_with_findings: string[];
  enterprise_modules_active: boolean;
  // Roadmap
  remediation_roadmap: RemediationItem[];
  quick_wins: RemediationItem[];
  immediate_actions: RemediationItem[];
  // Compliance
  dpdp_impact: number;
  gdpr_impact: number;
  pci_impact: number;
  // Enterprise risk quantification v2
  risk_portfolio_summary?: PortfolioRiskSummary;
  total_ale_reduction_inr?: number;
  total_ale_display?: string;
  avg_rrf_score?: number;
  kev_findings_count?: number;
  epss_enriched_count?: number;
  severity_adjusted_count?: number;
  p0_count?: number;
  p1_count?: number;
  p2_count?: number;
  p3_count?: number;
  // Deep compliance v2
  compliance_v2?: ComplianceV2;
  dpdp_penalty_crore?: number;
  dpdp_risk_level?: string;
  gdpr_status?: string;
  pci_status?: string;
  soc2_status?: string;
  // Score breakdown
  score_trend?: string;
  generated_at?: string;
}

export interface RemediationItem {
  priority: number;
  severity: Severity;
  title: string;
  finding_key: string;
  module: string;
  estimated_fix_time: string;
  impact_score: number;
  quick_win?: boolean;
  ale_reduction_inr?: number;
  ale_display?: string;
  rrf_score?: number;
  sla_tier?: SLATier;
  fix_difficulty?: FixDifficulty;
}

// ─── Full paid report ─────────────────────────────────────────────────────────

export interface FullReport {
  scan_id: string;
  domain?: string;
  scan_duration_seconds?: number;
  overall_score: number;
  overall_severity: Severity;
  executive_summary: string;
  ai_summary?: string;
  score_breakdown?: ScoreBreakdown;

  // Risk items
  findings?: RiskItem[];
  risk_items?: RiskItem[];
  critical_risks?: RiskItem[];
  high_risks?: RiskItem[];
  medium_risks?: RiskItem[];
  low_risks?: RiskItem[];
  info_risks?: RiskItem[];

  // Domain reports
  domain_reports?: Record<string, unknown>;

  // Finding counts
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  info_count?: number;
  total_findings?: number;

  // Legacy DPDP
  dpdp_compliance_score?: number;
  dpdp_issues?: string[];

  // Enterprise compliance v2
  compliance_report_v2?: ComplianceV2;
  dpdp_penalty_crore?: number;
  dpdp_risk_level?: string;
  gdpr_status?: string;
  pci_status?: string;
  soc2_status?: string;

  // OWASP
  owasp_coverage?: OWASPCoverage;
  owasp_llm_coverage?: OWASPLLMCoverage;
  owasp_coverage_score?: number;
  owasp_llm_coverage_score?: number;

  // Risk quantification
  total_ale_reduction_inr?: number;
  total_ale_display?: string;
  avg_rrf_score?: number;
  kev_findings_count?: number;
  epss_enriched_count?: number;
  severity_adjusted_count?: number;
  p0_count?: number;
  p1_count?: number;
  p2_count?: number;
  p3_count?: number;

  // SBOM
  sbom_generated?: boolean;
  sbom_component_count?: number;

  // Ingestion
  ingested_findings_count?: number;
  deduplication_savings?: number;
  ingestion_sources?: string[];

  // Module data
  waf_detected?: boolean;
  waf_provider?: string;
  compliance_report?: unknown;
  brand_threats?: unknown;
  bola_findings?: unknown;
  llm_findings?: unknown;
  tech_inventory?: unknown;
  cve_data?: unknown;

  is_paid?: boolean;
  generated_at?: string;
}

// ─── Remediation roadmap ──────────────────────────────────────────────────────

export interface RemediationRoadmap {
  phases: {
    phase_1_immediate?: RemediationItem[];
    phase_2_short_term?: RemediationItem[];
    phase_3_long_term?: RemediationItem[];
  };
  total_items?: number;
  estimated_score_gain?: number;
  detected_framework?: string;
}

// ─── Scan module status ───────────────────────────────────────────────────────

export interface ModuleStatus {
  name: string;
  display_name: string;
  status: 'success' | 'failed' | 'degraded' | 'skipped';
  error?: string;
  findings_count?: number;
}

// ─── BYOS Ingestion ───────────────────────────────────────────────────────────

export interface IngestResponse {
  status: string;
  scan_id: string;
  new_findings: number;
  merged_duplicates: number;
  total_findings: number;
  ingestion_sources: string[];
  deduplication_rate: number;
  message: string;
}

// ─── ALE formatting helper ────────────────────────────────────────────────────

/** Format an INR amount as a human-readable ALE display string */
export function formatALE(amount: number | undefined): string {
  if (!amount || amount <= 0) return '';
  if (amount >= 10_000_000) {
    return `Rs. ${(amount / 10_000_000).toFixed(1)} crore/year`;
  }
  if (amount >= 100_000) {
    return `Rs. ${(amount / 100_000).toFixed(1)} lakh/year`;
  }
  if (amount >= 1_000) {
    return `Rs. ${amount.toLocaleString('en-IN')}/year`;
  }
  return `Rs. ${amount}/year`;
}

/** Color class for an ALE amount */
export function aleColorClass(amount: number | undefined): string {
  if (!amount) return 'text-slate-400';
  if (amount >= 5_000_000) return 'text-red-400';     // > 50 lakh
  if (amount >= 1_000_000) return 'text-amber-400';   // > 10 lakh
  return 'text-blue-400';
}

/** Map severity to visual weight */
export function severityToWeight(severity: Severity): VisualWeight {
  switch (severity) {
    case 'CRITICAL': return 'critical';
    case 'RED':
    case 'HIGH':     return 'high';
    case 'AMBER':
    case 'MEDIUM':   return 'medium';
    case 'GREEN':
    case 'LOW':      return 'low';
    default:         return 'info';
  }
}
