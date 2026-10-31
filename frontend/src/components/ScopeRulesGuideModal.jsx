import React from 'react';
import { BookOpen, X, Check, AlertCircle } from 'lucide-react';

export default function ScopeRulesGuideModal({ onClose }) {
  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ maxWidth: '650px' }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <BookOpen size={20} color="#38bdf8" />
            <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#f8fafc' }}>
              Scope & Allow-List Syntax Guide
            </h3>
          </div>
          <button className="btn btn-secondary" style={{ padding: '4px 8px' }} onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <div className="modal-body" style={{ fontSize: '13px', lineHeight: 1.6 }}>
          <p style={{ color: '#cbd5e1', marginBottom: '14px' }}>
            CognoSieve strictly confines all ZAP spidering, passive analysis, active probes, and LLM red-teaming to your defined scope. Specify one rule per line.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ background: '#090e1a', padding: '12px 16px', borderRadius: '8px', border: '1px solid #1e293b' }}>
              <strong style={{ color: '#38bdf8' }}>1. Wildcard Subdomains:</strong>
              <pre style={{ margin: '6px 0', color: '#94a3b8' }}>*.example.com</pre>
              <span style={{ color: '#cbd5e1' }}>Matches <code>app.example.com</code>, <code>api.example.com</code>, and <code>example.com</code>.</span>
            </div>

            <div style={{ background: '#090e1a', padding: '12px 16px', borderRadius: '8px', border: '1px solid #1e293b' }}>
              <strong style={{ color: '#38bdf8' }}>2. Path Prefixes:</strong>
              <pre style={{ margin: '6px 0', color: '#94a3b8' }}>/api/*  or  https://example.com/v1/*</pre>
              <span style={{ color: '#cbd5e1' }}>Restricts the scanner exclusively to designated URL route subtrees.</span>
            </div>

            <div style={{ background: '#090e1a', padding: '12px 16px', borderRadius: '8px', border: '1px solid #1e293b' }}>
              <strong style={{ color: '#38bdf8' }}>3. CIDR Subnets & IP Addresses:</strong>
              <pre style={{ margin: '6px 0', color: '#94a3b8' }}>192.168.1.0/24  or  10.0.0.15</pre>
              <span style={{ color: '#cbd5e1' }}>Permits testing across IP address ranges and internal subnets.</span>
            </div>

            <div style={{ background: 'rgba(239, 68, 68, 0.08)', padding: '12px 16px', borderRadius: '8px', border: '1px solid rgba(239, 68, 68, 0.25)' }}>
              <strong style={{ color: '#f87171' }}>Precedence Rule:</strong>
              <p style={{ marginTop: '4px', color: '#fca5a5' }}>
                <strong>Out-of-scope rules ALWAYS override in-scope rules.</strong> For instance, if in-scope is <code>*.example.com</code> and out-of-scope is <code>/admin/*</code>, any request to <code>example.com/admin/*</code> is blocked and never queued.
              </p>
            </div>
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn btn-primary" onClick={onClose}>
            Got It
          </button>
        </div>
      </div>
    </div>
  );
}
