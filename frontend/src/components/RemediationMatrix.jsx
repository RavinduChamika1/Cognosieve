import React from 'react';
import { CheckSquare } from 'lucide-react';

export default function RemediationMatrix({ findings }) {
  const activeFindings = findings.filter(f => f.ai_verdict !== 'false_positive');

  if (activeFindings.length === 0) return null;

  return (
    <div className="glass-panel" style={{ padding: '24px', marginBottom: '28px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
        <CheckSquare size={20} color="#10b981" />
        <h3 style={{ fontSize: '18px', fontWeight: 700 }}>
          Remediation Action Matrix ({activeFindings.length} Items)
        </h3>
      </div>
      <p style={{ fontSize: '12px', color: '#94a3b8', marginBottom: '16px' }}>
        Prioritized mitigation guidance sorted by technical severity and business impact.
      </p>

      <div style={{ overflowX: 'auto' }}>
        <table className="findings-table">
          <thead>
            <tr>
              <th style={{ width: '10%' }}>ID</th>
              <th style={{ width: '22%' }}>Vulnerability</th>
              <th style={{ width: '10%' }}>Severity</th>
              <th style={{ width: '10%' }}>CWE</th>
              <th style={{ width: '48%' }}>Specific Fix</th>
            </tr>
          </thead>
          <tbody>
            {activeFindings.map((f) => (
              <tr key={f.finding_id}>
                <td style={{ fontFamily: 'monospace', fontWeight: 700, color: '#38bdf8' }}>
                  {f.finding_id}
                </td>
                <td style={{ fontWeight: 600, color: '#f8fafc' }}>
                  {f.title}
                </td>
                <td>
                  <span className={`severity-pill ${f.severity.toLowerCase()}`}>
                    {f.severity}
                  </span>
                </td>
                <td style={{ fontFamily: 'monospace' }}>
                  {f.cwe_id}
                </td>
                <td style={{ fontFamily: 'monospace', fontSize: '12px', color: '#cbd5e1' }}>
                  {f.remediation.length > 200 ? `${f.remediation.substring(0, 200)}...` : f.remediation}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
