// API Client for CognoSieve backend
const API_BASE = import.meta.env.VITE_API_URL || '';

export async function checkHealth() {
  const res = await fetch(`${API_BASE}/api/health`);
  if (!res.ok) throw new Error('Health check failed');
  return res.json();
}

export async function validateScope(targetUrl, inScope, outOfScope = '') {
  const params = new URLSearchParams({
    target_url: targetUrl,
    in_scope: inScope,
    out_of_scope: outOfScope
  });
  const res = await fetch(`${API_BASE}/api/validate-scope?${params}`, {
    method: 'POST'
  });
  if (!res.ok) return { is_in_scope: false, reason: 'Scope check error' };
  return res.json();
}

export async function submitScan(payload) {
  const res = await fetch(`${API_BASE}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || 'Failed to initiate vulnerability scan');
  }
  return data;
}

export async function getScans() {
  const res = await fetch(`${API_BASE}/api/scans`);
  if (!res.ok) throw new Error('Failed to load past scans');
  return res.json();
}

export async function getScan(scanId) {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}`);
  if (!res.ok) throw new Error('Failed to retrieve scan details');
  return res.json();
}

export async function getScanAudit(scanId) {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}/audit`);
  if (!res.ok) throw new Error('Failed to fetch audit log');
  return res.json();
}

export function getHtmlReportUrl(scanId) {
  return `${API_BASE}/api/scans/${scanId}/report/html`;
}

export function getPdfReportUrl(scanId) {
  return `${API_BASE}/api/scans/${scanId}/report/pdf`;
}
