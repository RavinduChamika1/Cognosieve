import React from 'react';
import { Loader2, CheckCircle, AlertCircle, Shield } from 'lucide-react';

export default function ScanProgress({ scan }) {
  if (!scan) return null;

  const pct = scan.progress_percent || 0;
  const isCompleted = scan.status === 'completed';
  const isFailed = scan.status === 'failed';

  return (
    <div className="glass-panel progress-card">
      <div className="progress-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            {!isCompleted && !isFailed && <Loader2 size={16} className="spin" color="#38bdf8" />}
            {isCompleted && <CheckCircle size={16} color="#10b981" />}
            {isFailed && <AlertCircle size={16} color="#ef4444" />}
            <span style={{ fontSize: '15px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              {scan.status}
            </span>
            <span style={{ fontSize: '13px', color: '#94a3b8' }}>&bull; {scan.target_url}</span>
          </div>
          <p style={{ fontSize: '13px', color: '#cbd5e1' }}>
            {scan.current_step || 'Initializing assessment...'}
          </p>
        </div>

        <div style={{ fontFamily: 'monospace', fontWeight: 800, fontSize: '20px', color: '#38bdf8' }}>
          {pct}%
        </div>
      </div>

      <div className="progress-bar-container">
        <div
          className="progress-bar-fill"
          style={{
            width: `${pct}%`,
            background: isFailed ? '#ef4444' : isCompleted ? '#10b981' : undefined
          }}
        />
      </div>

      {isFailed && scan.error_message && (
        <div style={{ color: '#f87171', fontSize: '12px', marginTop: '6px' }}>
          <strong>Failure Reason:</strong> {scan.error_message}
        </div>
      )}
    </div>
  );
}
