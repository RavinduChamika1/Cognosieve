import React, { useState, useEffect } from 'react';
import { Play, CheckCircle2, XCircle, Info, Shield, Zap } from 'lucide-react';
import { validateScope } from '../api/client';

export default function ScanForm({ onSubmit, loading }) {
  const [targetUrl, setTargetUrl] = useState('https://testphp.vulnweb.com');
  const [llmEndpointUrl, setLlmEndpointUrl] = useState('');
  const [inScope, setInScope] = useState('*.vulnweb.com\ntestphp.vulnweb.com\n/api/*');
  const [outOfScope, setOutOfScope] = useState('/admin/*\n/internal/*');
  const [authConfirmed, setAuthConfirmed] = useState(false);
  const [scanMode, setScanMode] = useState('passive');
  const [multiplier, setMultiplier] = useState(1.0);
  const [exposure, setExposure] = useState(1.0);

  const [scopeValid, setScopeValid] = useState(null);
  const [scopeReason, setScopeReason] = useState('');

  // Live scope validation debounced
  useEffect(() => {
    if (!targetUrl) {
      setScopeValid(null);
      setScopeReason('');
      return;
    }

    const timer = setTimeout(async () => {
      try {
        const res = await validateScope(targetUrl, inScope, outOfScope);
        setScopeValid(res.is_in_scope);
        setScopeReason(res.reason);
      } catch (e) {
        setScopeValid(false);
        setScopeReason('Scope validation check failed');
      }
    }, 350);

    return () => clearTimeout(timer);
  }, [targetUrl, inScope, outOfScope]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!authConfirmed) {
      alert('You must check the authorization confirmation to proceed.');
      return;
    }
    if (scopeValid === false) {
      alert(`Scope safety violation: ${scopeReason}`);
      return;
    }

    onSubmit({
      target_url: targetUrl.trim(),
      llm_endpoint_url: llmEndpointUrl.trim() || undefined,
      in_scope: inScope.trim(),
      out_of_scope: outOfScope.trim(),
      authorization_confirmation: authConfirmed,
      scan_mode: scanMode,
      business_impact_multiplier: parseFloat(multiplier),
      exposure_factor: parseFloat(exposure)
    });
  };

  const setPreset = (type) => {
    if (type === 'vulnweb') {
      setTargetUrl('https://testphp.vulnweb.com');
      setInScope('*.vulnweb.com\ntestphp.vulnweb.com');
      setOutOfScope('/admin/*');
    } else if (type === 'juiceshop') {
      setTargetUrl('https://juice-shop.herokuapp.com');
      setInScope('juice-shop.herokuapp.com\n/rest/*\n/api/*');
      setOutOfScope('/ftp/*');
    } else if (type === 'local') {
      setTargetUrl('http://localhost:3000');
      setInScope('localhost:3000\n127.0.0.1');
      setOutOfScope('');
    }
  };

  return (
    <div className="glass-panel form-card">
      <div className="form-header">
        <h2 className="form-title">Vulnerability Assessment Scope & Target</h2>
        <p className="form-subtitle">
          Define the target base URL and strictly bounded in-scope allow-list. Out-of-scope rules take precedence.
        </p>
      </div>

      <form onSubmit={handleSubmit}>
        <div className="form-grid">
          {/* Target URL */}
          <div className="form-group full-width">
            <div className="form-label">
              <span>Target Base URL *</span>
              <div style={{ display: 'flex', gap: '6px' }}>
                <span className="chip" onClick={() => setPreset('vulnweb')}>TestPHP Preset</span>
                <span className="chip" onClick={() => setPreset('juiceshop')}>JuiceShop Preset</span>
                <span className="chip" onClick={() => setPreset('local')}>Localhost Preset</span>
              </div>
            </div>
            <input
              type="url"
              className="form-input"
              required
              placeholder="https://example.com"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
            />
            {scopeValid !== null && (
              <div className={`validation-indicator ${scopeValid ? 'valid' : 'invalid'}`}>
                {scopeValid ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                <span>{scopeReason}</span>
              </div>
            )}
          </div>

          {/* LLM Endpoint URL (Optional) */}
          <div className="form-group full-width">
            <div className="form-label">
              <span>LLM / AI Endpoint URL (Optional)</span>
              <span style={{ fontSize: '11px', color: '#a78bfa' }}>
                🤖 OWASP Top 10 for LLM Applications 2025 (Red-Team)
              </span>
            </div>
            <input
              type="url"
              className="form-input"
              placeholder="e.g. https://api.example.com/v1/chat or http://localhost:8000/api/chat"
              value={llmEndpointUrl}
              onChange={(e) => setLlmEndpointUrl(e.target.value)}
            />
            <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px' }}>
              Leave blank for standard web vulnerability scanning. If filled, CognoSieve executes promptfoo red-teaming against this endpoint first, then correlates both into one combined report.
            </div>
          </div>

          {/* In-Scope Rules */}
          <div className="form-group">
            <div className="form-label">
              <span>In-Scope Rules (Optional)</span>
              <span style={{ fontSize: '11px', color: inScope ? '#94a3b8' : '#38bdf8' }}>
                {inScope ? 'One rule per line' : '⚡ Defaults to full URL attack'}
              </span>
            </div>
            <textarea
              className="form-textarea"
              rows={4}
              placeholder="Leave blank to directly attack/scan the full Target URL, or enter:&#10;*.example.com&#10;/api/*&#10;192.168.1.0/24"
              value={inScope}
              onChange={(e) => setInScope(e.target.value)}
            />
            <div className="scope-chips">
              <span className="chip" onClick={() => setInScope(prev => `${prev}\n*.example.com`.trim())}>+ Wildcard domain</span>
              <span className="chip" onClick={() => setInScope(prev => `${prev}\n/api/*`.trim())}>+ Path prefix</span>
              <span className="chip" onClick={() => setInScope(prev => `${prev}\n10.0.0.0/24`.trim())}>+ CIDR subnet</span>
              {inScope && (
                <span className="chip" style={{ color: '#f87171' }} onClick={() => setInScope('')}>Clear (Direct Target URL Mode)</span>
              )}
            </div>
          </div>

          {/* Out-of-Scope Rules */}
          <div className="form-group">
            <div className="form-label">
              <span>Out-of-Scope Rules (Exclusions)</span>
              <span style={{ fontSize: '11px', color: '#f87171' }}>Always overrides in-scope</span>
            </div>
            <textarea
              className="form-textarea"
              rows={4}
              placeholder="/admin/*&#10;*.billing.example.com&#10;192.168.1.50"
              value={outOfScope}
              onChange={(e) => setOutOfScope(e.target.value)}
            />
            <div className="scope-chips">
              <span className="chip" onClick={() => setOutOfScope(prev => `${prev}\n/admin/*`.trim())}>+ Admin path</span>
              <span className="chip" onClick={() => setOutOfScope(prev => `${prev}\n/internal/*`.trim())}>+ Internal path</span>
              <span className="chip" onClick={() => setOutOfScope(prev => `${prev}\n*.staging.*`.trim())}>+ Staging hosts</span>
            </div>
          </div>

          {/* Scan Mode */}
          <div className="form-group">
            <div className="form-label">
              <span>Assessment Mode</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <button
                type="button"
                className={`btn ${scanMode === 'passive' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setScanMode('passive')}
                style={{ justifyContent: 'center' }}
              >
                <Shield size={16} />
                <span>Passive Scan (Safe)</span>
              </button>

              <button
                type="button"
                className={`btn ${scanMode === 'active' ? 'btn-danger' : 'btn-secondary'}`}
                onClick={() => setScanMode('active')}
                style={{ justifyContent: 'center' }}
              >
                <Zap size={16} />
                <span>Active Scan (Intrusive)</span>
              </button>
            </div>
          </div>

          {/* Exposure Factor */}
          <div className="form-group">
            <div className="form-label">
              <span>Exposure Context</span>
            </div>
            <select
              className="form-select"
              value={exposure}
              onChange={(e) => setExposure(parseFloat(e.target.value))}
            >
              <option value={1.0}>Internet-Facing / Public Web (1.0x)</option>
              <option value={0.8}>Authenticated Access / Partner API (0.8x)</option>
              <option value={0.6}>Internal Corporate Network / Anonymous (0.6x)</option>
            </select>
          </div>

          {/* Business Impact Multiplier */}
          <div className="form-group full-width">
            <div className="form-label">
              <span>Business Impact Multiplier: <span style={{ color: '#38bdf8' }}>{multiplier}x</span></span>
              <span style={{ fontSize: '11px', color: '#94a3b8' }}>Adjusts technical CVSS scores based on organizational criticality (0.5x to 2.0x)</span>
            </div>
            <div className="slider-container">
              <span style={{ fontSize: '12px', color: '#94a3b8' }}>0.5x (Non-critical)</span>
              <input
                type="range"
                min="0.5"
                max="2.0"
                step="0.1"
                className="slider-input"
                value={multiplier}
                onChange={(e) => setMultiplier(parseFloat(e.target.value))}
              />
              <span style={{ fontSize: '12px', color: '#94a3b8' }}>2.0x (Mission-Critical)</span>
            </div>
          </div>

          {/* Authorization Checkbox (REQUIRED) */}
          <div className="form-group full-width">
            <label className="checkbox-card">
              <input
                type="checkbox"
                required
                checked={authConfirmed}
                onChange={(e) => setAuthConfirmed(e.target.checked)}
              />
              <div className="checkbox-text">
                <strong>Authorization Confirmation (Required):</strong> I affirm under penalty of applicable cybersecurity laws that I own this target or have documented, written authorization from the owner to conduct dynamic application security testing and vulnerability assessment.
              </div>
            </label>
          </div>
        </div>

        <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end' }}>
          <button
            type="submit"
            className="btn btn-primary"
            style={{ padding: '12px 28px', fontSize: '14px' }}
            disabled={loading || !authConfirmed || scopeValid === false}
          >
            <Play size={18} />
            <span>{loading ? 'Launching Scan...' : scanMode === 'active' ? 'Proceed to Active Scan Confirmation' : 'Start Vulnerability Scan'}</span>
          </button>
        </div>
      </form>
    </div>
  );
}
