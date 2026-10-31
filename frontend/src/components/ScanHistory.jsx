import React from 'react';
import { History, X, ExternalLink, Download, FileText, CheckCircle, Clock } from 'lucide-react';
import { getHtmlReportUrl, getPdfReportUrl } from '../api/client';

export default function ScanHistory({ scans, onSelectScan, onClose }) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: '850px' }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <History size={20} color="#38bdf8" />
            <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#f8fafc' }}>
              Historical Security Assessments ({scans.length})
            </h3>
          </div>
          <button className="btn btn-secondary" style={{ padding: '6px 10px' }} onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div className="modal-body">
          {scans.length === 0 ? (
            <p style={{ textAlign: 'center', color: '#94a3b8', padding: '30px' }}>
              No previous scans recorded. Submit an assessment to begin tracking.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {scans.map((s) => {
                const score = s.summary?.overall_risk_score !== undefined ? s.summary.overall_risk_score : 0.0;
                return (
                  <div
                    key={s.id}
                    style={{
                      background: '#090e1a',
                      border: '1px solid #1e293b',
                      borderRadius: '8px',
                      padding: '16px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: '16px',
                      flexWrap: 'wrap'
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                        <span style={{ fontWeight: 700, fontSize: '15px', color: '#f8fafc' }}>
                          {s.target_url}
                        </span>
                        <span className="chip" style={{ fontSize: '10px', textTransform: 'uppercase' }}>
                          {s.scan_mode}
                        </span>
                        <span className={`verdict-badge ${s.status === 'completed' ? 'confirmed' : 'needs_review'}`}>
                          {s.status.toUpperCase()}
                        </span>
                      </div>
                      <div style={{ fontSize: '12px', color: '#94a3b8', display: 'flex', gap: '12px' }}>
                        <span>Date: {new Date(s.created_at).toLocaleString()}</span>
                        <span>Risk Score: <strong style={{ color: '#38bdf8' }}>{score}</strong></span>
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '6px 12px', fontSize: '12px' }}
                        onClick={() => {
                          onSelectScan(s.id);
                          onClose();
                        }}
                      >
                        <span>Load in Dashboard</span>
                      </button>
                      {s.status === 'completed' && (
                        <>
                          <a
                            href={getHtmlReportUrl(s.id)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="btn btn-secondary"
                            style={{ padding: '6px 10px', fontSize: '12px' }}
                            title="View HTML Report"
                          >
                            <FileText size={14} />
                          </a>
                          <a
                            href={getPdfReportUrl(s.id)}
                            download
                            className="btn btn-primary"
                            style={{ padding: '6px 10px', fontSize: '12px' }}
                            title="Download PDF Report"
                          >
                            <Download size={14} />
                          </a>
                        </>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn btn-primary" onClick={onClose}>
            Close History
          </button>
        </div>
      </div>
    </div>
  );
}
