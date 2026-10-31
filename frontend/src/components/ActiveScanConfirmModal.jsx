import React, { useState } from 'react';
import { AlertOctagon, ShieldAlert, Check } from 'lucide-react';

export default function ActiveScanConfirmModal({ targetUrl, onConfirm, onCancel }) {
  const [understood, setUnderstood] = useState(false);

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ maxWidth: '580px' }}>
        <div className="modal-header" style={{ borderBottomColor: '#dc2626' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertOctagon size={24} color="#ef4444" />
            <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#f8fafc' }}>
              Explicit Active Scanning Confirmation
            </h3>
          </div>
        </div>

        <div className="modal-body">
          <div style={{
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '8px',
            padding: '16px',
            marginBottom: '16px',
            color: '#fca5a5',
            fontSize: '13px',
            lineHeight: 1.5
          }}>
            <p><strong>Warning:</strong> You have selected <strong>Active Scan Mode</strong> against:</p>
            <p style={{ fontFamily: 'monospace', fontWeight: 700, color: '#ffffff', margin: '8px 0' }}>{targetUrl}</p>
            <p>
              Active scanning injects simulated attack vectors, SQL injection probes, cross-site scripting strings, and fuzzing payloads directly into web forms, URL parameters, and API endpoints.
            </p>
          </div>

          <ul style={{ fontSize: '13px', color: '#cbd5e1', marginLeft: '20px', marginBottom: '18px', lineHeight: 1.6 }}>
            <li>Active probes may populate databases with test records.</li>
            <li>High-frequency fuzzing could degrade server performance or trigger WAF/IDS rate limits.</li>
            <li>Production environments should only be scanned during approved maintenance windows.</li>
          </ul>

          <label className="checkbox-card" style={{ borderColor: understood ? '#10b981' : '#dc2626' }}>
            <input
              type="checkbox"
              checked={understood}
              onChange={(e) => setUnderstood(e.target.checked)}
            />
            <div className="checkbox-text">
              <strong>I Understand & Explicitly Authorize Active Payloads:</strong> I verify that this target is an authorized testing environment and I approve the execution of active DAST attack vectors.
            </div>
          </label>
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onCancel}>
            Cancel Scan
          </button>
          <button
            className="btn btn-danger"
            disabled={!understood}
            onClick={() => onConfirm(true)}
          >
            <Check size={16} />
            <span>Confirm & Launch Active Scan</span>
          </button>
        </div>
      </div>
    </div>
  );
}
