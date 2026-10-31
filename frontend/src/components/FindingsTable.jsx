import React, { useState, useMemo } from 'react';
import { Search, Filter, Sparkles, ExternalLink, ShieldAlert } from 'lucide-react';

export default function FindingsTable({ findings, onSelectFinding }) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [verdictFilter, setVerdictFilter] = useState('ACTIVE'); // ACTIVE = confirmed + needs_review
  const [novelOnly, setNovelOnly] = useState(false);

  const filtered = useMemo(() => {
    return findings.filter(f => {
      // Search
      const q = search.toLowerCase();
      const matchSearch = !q ||
        f.finding_id?.toLowerCase().includes(q) ||
        f.title?.toLowerCase().includes(q) ||
        f.cwe_id?.toLowerCase().includes(q) ||
        f.affected_url?.toLowerCase().includes(q) ||
        f.owasp_category?.toLowerCase().includes(q);

      if (!matchSearch) return false;

      // Severity
      if (severityFilter !== 'ALL' && f.severity !== severityFilter) {
        return false;
      }

      // Verdict
      if (verdictFilter === 'ACTIVE') {
        if (f.ai_verdict === 'false_positive') return false;
      } else if (verdictFilter !== 'ALL' && f.ai_verdict !== verdictFilter) {
        return false;
      }

      // Novel pattern
      if (novelOnly && !f.novel_pattern_flag) {
        return false;
      }

      return true;
    });
  }, [findings, search, severityFilter, verdictFilter, novelOnly]);

  const getSeverityClass = (sev) => {
    return (sev || 'medium').toLowerCase();
  };

  return (
    <div className="glass-panel findings-container">
      <div className="findings-toolbar">
        <div>
          <h3 style={{ fontSize: '18px', fontWeight: 700 }}>
            Triaged Vulnerability Findings ({filtered.length})
          </h3>
          <p style={{ fontSize: '12px', color: '#94a3b8' }}>
            Click any finding row to inspect request/response evidence and Gemini AI analysis.
          </p>
        </div>

        <div className="filter-group">
          <input
            type="text"
            className="search-input"
            placeholder="Search findings or CWE..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />

          <select
            className="form-select"
            style={{ width: 'auto', padding: '8px 12px', fontSize: '13px' }}
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="ALL">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          <select
            className="form-select"
            style={{ width: 'auto', padding: '8px 12px', fontSize: '13px' }}
            value={verdictFilter}
            onChange={(e) => setVerdictFilter(e.target.value)}
          >
            <option value="ACTIVE">Confirmed & Needs Review</option>
            <option value="ALL">All (Including False Positives)</option>
            <option value="confirmed">Confirmed Only</option>
            <option value="needs_review">Needs Review Only</option>
            <option value="false_positive">False Positives Only</option>
          </select>

          <button
            type="button"
            className={`btn ${novelOnly ? 'btn-primary' : 'btn-secondary'}`}
            style={{ padding: '8px 12px' }}
            onClick={() => setNovelOnly(!novelOnly)}
          >
            <Sparkles size={14} />
            <span>Novel ({findings.filter(f => f.novel_pattern_flag).length})</span>
          </button>
        </div>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table className="findings-table">
          <thead>
            <tr>
              <th style={{ width: '10%' }}>ID</th>
              <th style={{ width: '28%' }}>Vulnerability Title</th>
              <th style={{ width: '10%' }}>Severity</th>
              <th style={{ width: '8%' }}>CVSS</th>
              <th style={{ width: '12%' }}>CWE ID</th>
              <th style={{ width: '14%' }}>AI Verdict</th>
              <th style={{ width: '10%' }}>Novel Flag</th>
              <th style={{ width: '8%', textAlign: 'right' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ textAlign: 'center', padding: '36px', color: '#94a3b8' }}>
                  No findings matching current filter criteria.
                </td>
              </tr>
            ) : (
              filtered.map((f) => (
                <tr
                  key={f.finding_id}
                  onClick={() => onSelectFinding(f)}
                  style={{ cursor: 'pointer' }}
                >
                  <td style={{ fontFamily: 'monospace', fontWeight: 700, color: '#38bdf8' }}>
                    {f.finding_id}
                  </td>
                  <td>
                    <div style={{ fontWeight: 600, color: '#f8fafc' }}>{f.title}</div>
                    <div style={{ fontSize: '11px', color: '#94a3b8', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                      {f.affected_url}
                    </div>
                  </td>
                  <td>
                    <span className={`severity-pill ${getSeverityClass(f.severity)}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'monospace', fontWeight: 700 }}>
                    {f.cvss_score}
                  </td>
                  <td style={{ fontFamily: 'monospace' }}>
                    {f.cwe_id}
                  </td>
                  <td>
                    <span className={`verdict-badge ${f.ai_verdict}`}>
                      {f.ai_verdict === 'confirmed' ? 'Confirmed' : f.ai_verdict === 'needs_review' ? 'Needs Review' : 'False Positive'}
                    </span>
                  </td>
                  <td>
                    {f.novel_pattern_flag ? (
                      <span className="novel-tag">Novel Pattern</span>
                    ) : (
                      <span style={{ color: '#64748b', fontSize: '12px' }}>&mdash;</span>
                    )}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      className="btn btn-secondary"
                      style={{ padding: '4px 8px', fontSize: '11px' }}
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectFinding(f);
                      }}
                    >
                      <ExternalLink size={12} />
                      <span>Inspect</span>
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
