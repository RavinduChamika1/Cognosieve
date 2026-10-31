import React from 'react';
import { ShieldAlert, BookOpen, History, PlusCircle, FileDown } from 'lucide-react';

export default function Header({ health, currentScan, onNewScan, onOpenHistory, onOpenGuide }) {
  const zapOnline = health?.zap_daemon_online;
  const geminiConfigured = health?.gemini_api_configured;

  return (
    <header className="header-wrapper">
      <div className="header-inner">
        <div className="brand-section" onClick={onNewScan}>
          <div className="brand-logo-icon">
            <ShieldAlert size={22} />
          </div>
          <div>
            <div className="brand-name">COGNOSIEVE</div>
            <div className="brand-tagline">Web &amp; LLM Vulnerability Assessment &bull; Gemini AI Triage</div>
          </div>
        </div>

        <div className="header-status-group">
          {/* ZAP Status */}
          <div className="status-pill" title={`ZAP Daemon: ${zapOnline ? 'Connected' : 'Offline (Simulator Active)'}`}>
            <span className={`status-dot ${zapOnline ? 'online' : 'sim'}`} />
            <span>ZAP: {zapOnline ? 'Live' : 'Simulator'}</span>
          </div>

          {/* Gemini Status */}
          <div className="status-pill" title={`Gemini API: ${geminiConfigured ? 'Live Key Active' : 'Fallback Rules Active'}`}>
            <span className={`status-dot ${geminiConfigured ? 'online' : 'sim'}`} />
            <span>Gemini: {geminiConfigured ? 'Live AI' : 'Rules'}</span>
          </div>
        </div>

        <div className="header-actions">
          {currentScan && currentScan.status === 'completed' && (
            <a
              href={`/api/scans/${currentScan.id}/report/pdf`}
              download
              className="btn btn-primary"
              style={{ background: 'linear-gradient(135deg, #059669, #10b981)', boxShadow: '0 0 15px rgba(16, 185, 129, 0.4)' }}
              title="Download Assessment Report as PDF"
            >
              <FileDown size={16} />
              <span>Export PDF Report</span>
            </a>
          )}
          <button className="btn btn-secondary" onClick={onOpenGuide} title="Scope Syntax Reference">
            <BookOpen size={16} />
            <span>Scope Guide</span>
          </button>
          <button className="btn btn-secondary" onClick={onOpenHistory} title="View Past Assessments">
            <History size={16} />
            <span>Scan History</span>
          </button>
          <button className="btn btn-primary" onClick={onNewScan}>
            <PlusCircle size={16} />
            <span>New Scan</span>
          </button>
        </div>
      </div>
    </header>
  );
}
