import React, { useState } from 'react';
import { X, Sparkles, Copy, Check, ExternalLink, ShieldCheck, AlertTriangle } from 'lucide-react';

export default function FindingDetailModal({ finding, onClose }) {
  if (!finding) return null;

  const [activeTab, setActiveTab] = useState('response');
  const [copied, setCopied] = useState(false);

  const reqSnippet = finding.evidence?.request || '';
  const respSnippet = finding.evidence?.response || '';

  const copyEvidence = () => {
    const textToCopy = activeTab === 'request' ? reqSnippet : respSnippet;
    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityColor = (sev) => {
    const s = (sev || '').toLowerCase();
    if (s === 'critical') return '#ef4444';
    if (s === 'high') return '#f97316';
    if (s === 'medium') return '#eab308';
    if (s === 'low') return '#3b82f6';
    return '#6b7280';
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        {/* Modal Header */}
        <div className="modal-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <span style={{ fontFamily: 'monospace', fontWeight: 800, color: '#38bdf8', fontSize: '15px' }}>
                {finding.finding_id}
              </span>
              <span
                className="severity-pill"
                style={{ backgroundColor: getSeverityColor(finding.severity) }}
              >
                {finding.severity}
              </span>
              {finding.novel_pattern_flag && (
                <span className="novel-tag">Novel Pattern Flagged</span>
              )}
            </div>
            <h2 style={{ fontSize: '18px', fontWeight: 700, marginTop: '6px', color: '#f8fafc' }}>
              {finding.title}
            </h2>
          </div>

          <button className="btn btn-secondary" style={{ padding: '6px 10px' }} onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="modal-body">
          {/* Metadata Badges */}
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '18px' }}>
            <span className="chip" style={{ color: '#38bdf8' }}>
              CVSS: {finding.cvss_score} ({finding.cvss_vector})
            </span>
            <span className="chip">{finding.cwe_id}</span>
            <span className="chip">{finding.owasp_category}</span>
            {finding.mitre_attack_technique && (
              <span className="chip" style={{ color: '#c084fc' }}>
                MITRE ATT&CK: {finding.mitre_attack_technique}
              </span>
            )}
          </div>

          {/* Affected URL */}
          <div style={{ marginBottom: '16px' }}>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#94a3b8', fontWeight: 700, marginBottom: '4px' }}>
              Affected Endpoint URL
            </div>
            <div style={{
              background: '#070b14',
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid #1e293b',
              fontFamily: 'monospace',
              fontSize: '13px',
              color: '#38bdf8',
              wordBreak: 'break-all'
            }}>
              {finding.affected_url}
            </div>
          </div>

          {/* Description */}
          <div style={{ marginBottom: '18px' }}>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#94a3b8', fontWeight: 700, marginBottom: '4px' }}>
              Vulnerability Description
            </div>
            <p style={{ fontSize: '13px', color: '#cbd5e1', lineHeight: 1.6 }}>
              {finding.description}
            </p>
          </div>

          {/* Gemini AI Triage Insight */}
          <div className="ai-highlight-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Sparkles size={16} color="#38bdf8" />
                <strong style={{ fontSize: '14px', color: '#f8fafc' }}>
                  Gemini AI Triage Assessment
                </strong>
              </div>
              <span className={`verdict-badge ${finding.ai_verdict}`}>
                VERDICT: {finding.ai_verdict.toUpperCase()}
              </span>
            </div>

            <div style={{ fontSize: '13px', color: '#94a3b8' }}>
              <strong>Evidence-Quoted Reasoning:</strong>
            </div>
            <div className="ai-reasoning-quote">
              "{finding.ai_reasoning}"
            </div>

            {finding.novel_pattern_flag && (
              <div style={{ marginTop: '10px', fontSize: '12px', color: '#c084fc', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <AlertTriangle size={14} />
                <span>Gemini flagged this finding as an unfamiliar instance of a known weakness class ({finding.cwe_id}) not previously seen in this target environment.</span>
              </div>
            )}
          </div>

          {/* Evidence Viewer (Request / Response) */}
          <div style={{ marginTop: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div className="tabs" style={{ margin: 0 }}>
                <button
                  className={`tab-btn ${activeTab === 'response' ? 'active' : ''}`}
                  onClick={() => setActiveTab('response')}
                >
                  HTTP Response Evidence ({respSnippet.length} chars)
                </button>
                <button
                  className={`tab-btn ${activeTab === 'request' ? 'active' : ''}`}
                  onClick={() => setActiveTab('request')}
                >
                  HTTP Request Payload ({reqSnippet.length} chars)
                </button>
              </div>

              <button
                className="btn btn-secondary"
                style={{ padding: '4px 10px', fontSize: '11px' }}
                onClick={copyEvidence}
              >
                {copied ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            <div className="code-box">
              {activeTab === 'request' ? (
                reqSnippet || '// No HTTP request excerpt was captured for this alert.'
              ) : (
                respSnippet || '// No HTTP response excerpt was captured for this alert.'
              )}
            </div>
          </div>

          {/* Actionable Remediation */}
          <div style={{ marginTop: '20px' }}>
            <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#10b981', fontWeight: 700, marginBottom: '6px' }}>
              Actionable Remediation Guidance
            </div>
            <div className="remed-highlight">
              {finding.remediation}
            </div>
          </div>

          {/* References */}
          {finding.references && finding.references.length > 0 && (
            <div style={{ marginTop: '18px' }}>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#94a3b8', fontWeight: 700, marginBottom: '6px' }}>
                Security Standards & References
              </div>
              <ul style={{ listStyleType: 'none', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {finding.references.map((url, i) => (
                  <li key={i}>
                    <a
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ color: '#38bdf8', fontSize: '12px', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '6px' }}
                    >
                      <ExternalLink size={12} />
                      <span>{url}</span>
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="modal-footer">
          <button className="btn btn-primary" onClick={onClose}>
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}
