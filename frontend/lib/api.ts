import { ScanResponse, ScanProgress, PreviewResponse, FullReport, RemediationRoadmap, SBOMFormat, IngestResponse } from '../types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// Helper: read auth token from persisted Zustand store (works outside React components)
function getStoredToken(): string | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = localStorage.getItem('nanz-auth-storage');
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed?.state?.token) return parsed.state.token;
    }
  } catch (e) {
    // Ignore parse errors
  }
  
  try {
    const rawScan = localStorage.getItem('nanz-scan-storage-v2');
    if (rawScan) {
      const parsed = JSON.parse(rawScan);
      if (parsed?.state?.reportJWT) return parsed.state.reportJWT;
    }
  } catch (e) {
    // Ignore parse errors
  }

  return null;
}

function authHeaders(extra?: Record<string, string>): Record<string, string> {
  const token = getStoredToken();
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...extra,
  };
}

export async function startScan(url: string, options?: any): Promise<ScanResponse> {
  const res = await fetch(`${API_BASE}/api/scans`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ url, options }),
  });
  if (!res.ok) {
    let errorMsg = 'Failed to start scan';
    try {
      const errorData = await res.json();
      if (errorData.detail) {
        errorMsg = typeof errorData.detail === 'string' ? errorData.detail : JSON.stringify(errorData.detail);
      } else if (errorData.error) {
        errorMsg = errorData.error;
      }
    } catch (e) {}
    throw new Error(errorMsg);
  }
  return res.json();
}

export async function getScanProgress(scanId: string): Promise<ScanProgress> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}`, { headers: authHeaders() });
  if (!res.ok) throw new Error('Failed to fetch scan progress');
  return res.json();
}

export async function getScanPreview(scanId: string): Promise<PreviewResponse> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}/preview`, { headers: authHeaders() });
  if (!res.ok) throw new Error('Failed to fetch scan preview');
  return res.json();
}

export async function createPaymentOrder(scanId: string, email: string) {
  const res = await fetch(`${API_BASE}/api/payments/create`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ scan_id: scanId, email }),
  });
  if (!res.ok) throw new Error('Failed to create payment order');
  return res.json();
}

export async function verifyPayment(data: any) {
  const res = await fetch(`${API_BASE}/api/payments/verify`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Payment verification failed');
  return res.json();
}

export async function getFullReport(scanId: string, token?: string | null): Promise<FullReport | any> {
  const t = token || getStoredToken();
  const res = await fetch(`${API_BASE}/api/reports/${scanId}`, {
    headers: t ? { Authorization: `Bearer ${t}` } : {},
    cache: 'no-store',
  });
  if (res.status === 402) {
    return res.json();
  }
  if (!res.ok) {
    const err = new Error('Failed to fetch full report');
    (err as any).response = { status: res.status };
    throw err;
  }
  return res.json();
}

export async function getRoadmap(scanId: string, token?: string | null): Promise<RemediationRoadmap> {
  const t = token || getStoredToken();
  const res = await fetch(`${API_BASE}/api/reports/${scanId}/roadmap`, {
    headers: t ? { Authorization: `Bearer ${t}` } : {},
    cache: 'no-store',
  });
  if (!res.ok) throw new Error('Failed to fetch roadmap');
  return res.json();
}

export async function getComplianceReport(scanId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/reports/${scanId}/compliance`, { headers: authHeaders(), cache: 'no-store' });
  if (!res.ok) throw new Error('Failed to fetch compliance report');
  return res.json();
}

export async function getBrandThreats(scanId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/reports/${scanId}/brand-threats`, { headers: authHeaders(), cache: 'no-store' });
  if (!res.ok) throw new Error('Failed to fetch brand threats');
  return res.json();
}

export async function getEnterpriseData(scanId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/reports/${scanId}/enterprise`, { headers: authHeaders(), cache: 'no-store' });
  if (!res.ok) throw new Error('Failed to fetch enterprise data');
  return res.json();
}

export async function getASPMScore(scanId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/api/reports/${scanId}/aspm`, { headers: authHeaders(), cache: 'no-store' });
  if (!res.ok) throw new Error('Failed to fetch ASPM score');
  return res.json();
}


export async function downloadSBOM(scanId: string, format: SBOMFormat = 'cyclonedx'): Promise<any> {
  const res = await fetch(`${API_BASE}/api/reports/${scanId}/sbom?format=${format}`, { headers: authHeaders(), cache: 'no-store' });
  if (!res.ok) throw new Error('Failed to download SBOM');
  return res.json();
}

export async function submitFindingFeedback(
  scanId: string,
  findingId: string,
  action: 'mark_fixed' | 'false_positive',
): Promise<any> {
  const res = await fetch(`${API_BASE}/api/reports/${scanId}/findings/${findingId}/feedback`, {
    method: 'POST',
    headers: authHeaders(),
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
    headers: authHeaders(),
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error('Ingestion failed');
  return res.json();
}

export async function listScans(limit: number = 50, offset: number = 0): Promise<{ total: number; scans: any[] }> {
  const token = getStoredToken();
  const res = await fetch(`${API_BASE}/api/scans?limit=${limit}&offset=${offset}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
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
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    let errorMessage = 'Registration failed';
    if (Array.isArray(errorData.detail)) {
      errorMessage = errorData.detail[0].msg;
    } else if (typeof errorData.detail === 'string') {
      errorMessage = errorData.detail;
    }
    throw new Error(errorMessage);
  }
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
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    let errorMessage = 'Login failed';
    if (Array.isArray(errorData.detail)) {
      errorMessage = errorData.detail[0].msg;
    } else if (typeof errorData.detail === 'string') {
      errorMessage = errorData.detail;
    }
    throw new Error(errorMessage);
  }
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
