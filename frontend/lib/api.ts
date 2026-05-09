import { ScanResponse, ScanProgress, PreviewResponse, FullReport, RemediationRoadmap, SBOMFormat, IngestResponse } from '../types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export async function startScan(url: string, options?: any): Promise<ScanResponse> {
  const res = await fetch(`${API_BASE}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, options }),
  });
  if (!res.ok) throw new Error('Failed to start scan');
  return res.json();
}

export async function getScanProgress(scanId: string): Promise<ScanProgress> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}`);
  if (!res.ok) throw new Error('Failed to fetch scan progress');
  return res.json();
}

export async function getScanPreview(scanId: string): Promise<PreviewResponse> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}/preview`);
  if (!res.ok) throw new Error('Failed to fetch scan preview');
  return res.json();
}

export async function createPaymentOrder(scanId: string, email: string) {
  const res = await fetch(`${API_BASE}/api/payments/create-order`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scan_id: scanId, email }),
  });
  if (!res.ok) throw new Error('Failed to create payment order');
  return res.json();
}

export async function verifyPayment(data: any) {
  const res = await fetch(`${API_BASE}/api/payments/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Payment verification failed');
  return res.json();
}

export async function getFullReport(scanId: string, token: string): Promise<FullReport> {
  const res = await fetch(`${API_BASE}/api/reports/${scanId}`);
  if (!res.ok) throw new Error('Failed to fetch full report');
  return res.json();
}

export async function getRoadmap(scanId: string, token: string): Promise<RemediationRoadmap> {
  const res = await fetch(`${API_BASE}/api/reports/${scanId}/roadmap`);
  if (!res.ok) throw new Error('Failed to fetch roadmap');
  return res.json();
}

export async function getComplianceReport(scanId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/reports/${scanId}/compliance`);
  if (!res.ok) return null;
  return res.json();
}

export async function getBrandThreats(scanId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/reports/${scanId}/brand-threats`);
  if (!res.ok) return null;
  return res.json();
}

export async function getEnterpriseData(scanId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/reports/${scanId}/enterprise`);
  if (!res.ok) return null;
  return res.json();
}

export async function getASPMScore(scanId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/reports/${scanId}/aspm`);
  if (!res.ok) return null;
  return res.json();
}


export async function downloadSBOM(scanId: string, format: SBOMFormat = 'cyclonedx'): Promise<any> {
  const res = await fetch(`${API_BASE}/api/reports/${scanId}/sbom?format=${format}`);
  if (!res.ok) throw new Error('SBOM generation failed');
  return res.json();
}

export async function submitFindingFeedback(
  scanId: string,
  findingId: string,
  action: 'mark_fixed' | 'false_positive',
): Promise<any> {
  const res = await fetch(`${API_BASE}/api/reports/${scanId}/findings/${findingId}/feedback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action }),
  });
  if (!res.ok) return null;
  return res.json();
}

export async function ingestFindings(
  scanId: string,
  payload: { scanner: string; data: unknown },
): Promise<IngestResponse> {
  const res = await fetch(`${API_BASE}/api/ingest/${scanId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error('Ingestion failed');
  return res.json();
}

export async function listScans(limit: number = 50, offset: number = 0): Promise<{ total: number; scans: any[] }> {
  const res = await fetch(`${API_BASE}/api/scans?limit=${limit}&offset=${offset}`);
  if (!res.ok) throw new Error('Failed to fetch scans');
  return res.json();
}

// --- AUTHENTICATION ---
export async function registerUser(data: any) {
  const res = await fetch(`${API_BASE}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Registration failed');
  return res.json();
}

export async function loginUser(data: any) {
  // OAuth2 expects form-encoded data
  const formData = new URLSearchParams();
  formData.append('username', data.email);
  formData.append('password', data.password);

  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: formData.toString(),
  });
  if (!res.ok) throw new Error('Login failed');
  return res.json();
}

export async function getCurrentUser(token: string) {
  const res = await fetch(`${API_BASE}/api/auth/me`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!res.ok) throw new Error('Failed to get user');
  return res.json();
}

// --- DOMAINS ---
export async function getDomains(token: string) {
  const res = await fetch(`${API_BASE}/api/domains`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!res.ok) throw new Error('Failed to get domains');
  return res.json();
}

export async function createDomain(token: string, domain_name: string) {
  const res = await fetch(`${API_BASE}/api/domains`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`
    },
    body: JSON.stringify({ domain_name }),
  });
  if (!res.ok) throw new Error('Failed to create domain');
  return res.json();
}

// --- WORKSPACES ---
export async function getMyWorkspaces(token: string) {
  const res = await fetch(`${API_BASE}/api/workspaces/my`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!res.ok) throw new Error('Failed to get workspaces');
  return res.json();
}
