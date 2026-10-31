import React from 'react';
import { ShieldCheck, FileText, Download, Sparkles } from 'lucide-react';
import { getHtmlReportUrl, getPdfReportUrl } from '../api/client';

export default function SummaryCards({ scan, findings }) {
  const summary = scan?.summary || {};
  const riskScore = summary.overall_risk_score !== undefined ? summary.overall_risk_score : 0.0;

  // Filter findings
  const activeFindings = findings.filter(f => f.ai_verdict !== 'false_positive');
  const falsePositives = findings.filter(f => f.ai_verdict === 'false_positive');
  const novelCount = findings.filter(f => f.novel_pattern_flag).length;

  const criticals = activeFindings.filter(f => f.severity === 'Critical').length;
  const highs = activeFindings.filter(f => f.severity === 'High').length;
  const mediums = activeFindings.filter(f => f.severity === 'Medium').length;
  const lows = activeFindings.filter(f => f.severity === 'Low').length;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 700 }}>Assessment Executive Summary</h2>
          <p style={{ fontSize: '13px', color: '#94a3b8' }}>
            Risk metrics triaged via OWASP ZAP DAST engine and Google Gemini AI validation.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <a
            href={getHtmlReportUrl(scan.id)}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-secondary"
          >
            <FileText size={16} />
            <span>Standalone HTML Report</span>
          </a>
          <a
            href={getPdfReportUrl(scan.id)}
            download
            className="btn btn-primary"
          >
            <Download size={16} />
            <span>Download PDF Report</span>
          </a>
        </div>
      </div>

      <div className="metrics-row">
        {/* Risk Score */}
        <div className="risk-score-card">
          <div className="risk-score-number">{riskScore}</div>
          <div style={{ fontSize: '12px', fontWeight: 700, textTransform: 'uppercase', color: '#38bdf8', letterSpacing: '1px' }}>
            {riskScore >= 9.0 ? 'CRITICAL RISK' : riskScore >= 7.0 ? 'HIGH RISK' : riskScore >= 4.0 ? 'MODERATE RISK' : 'LOW RISK'}
          </div>
          <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px' }}>
            Weighted CVSS Matrix
          </div>
        </div>

        {/* Critical */}
        <div className="metric-box">
          <div className="metric-num" style={{ color: '#ef4444' }}>{criticals}</div>
          <div className="metric-label">Critical</div>
        </div>

        {/* High */}
        <div className="metric-box">
          <div className="metric-num" style={{ color: '#f97316' }}>{highs}</div>
          <div className="metric-label">High</div>
        </div>

        {/* Medium */}
        <div className="metric-box">
          <div className="metric-num" style={{ color: '#eab308' }}>{mediums}</div>
          <div className="metric-label">Medium</div>
        </div>

        {/* Low */}
        <div className="metric-box">
          <div className="metric-num" style={{ color: '#3b82f6' }}>{lows}</div>
          <div className="metric-label">Low</div>
        </div>

        {/* False Positives Filtered */}
        <div className="metric-box">
          <div className="metric-num" style={{ color: '#10b981' }}>{falsePositives.length}</div>
          <div className="metric-label">AI False Positives</div>
        </div>

        {/* Novel Patterns */}
        <div className="metric-box">
          <div className="metric-num" style={{ color: '#a855f7' }}>{novelCount}</div>
          <div className="metric-label">Novel Patterns</div>
        </div>
      </div>
    </div>
  );
}
