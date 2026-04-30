export interface ScanResponse {
  scan_id: string;
  status: string;
  estimated_duration_seconds: number;
}

export interface ScanProgress {
  scan_id: string;
  status: string;
  progress: Record<string, string>;
  overall_severity?: string;
  overall_score?: number;
  preview_risk?: {
    title: string;
    severity: string;
    business_impact: string;
    fix_action: string;
    confidence: string;
    fix_difficulty: string;
    estimated_fix_time: string;
  };
}

export interface RiskPreview {
  title: string;
  severity: string;
  business_impact: string;
}

export interface PreviewResponse {
  overall_severity: string;
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
}

export interface FullReport {
  scan_id: string;
  score_breakdown?: any;
  domain_reports: any;
  findings?: any[];
  risk_items?: any[];
  tech_inventory?: any;
  cve_data?: any;
  dpdp_score?: any;
  dpdp_compliance_score?: number;
  waf_detected?: boolean;
  waf_provider?: string;
  overall_score: number;
  overall_severity: string;
  executive_summary: string;
  ai_summary?: string;
  // Finding counts
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  info_count?: number;
  total_findings?: number;
  // New module data
  compliance_report?: any;
  brand_threats?: any;
  bola_findings?: any;
  llm_findings?: any;
}

export interface RemediationRoadmap {
  phases: {
    phase_1_immediate?: any[];
    phase_2_short_term?: any[];
    phase_3_long_term?: any[];
  };
  total_items?: number;
  estimated_score_gain?: number;
  detected_framework?: string;
}
