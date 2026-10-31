import React, { useState, useEffect, useRef } from 'react';
import Header from './components/Header';
import DisclaimerBanner from './components/DisclaimerBanner';
import ScanForm from './components/ScanForm';
import ActiveScanConfirmModal from './components/ActiveScanConfirmModal';
import ScopeRulesGuideModal from './components/ScopeRulesGuideModal';
import ScanProgress from './components/ScanProgress';
import SummaryCards from './components/SummaryCards';
import FindingsTable from './components/FindingsTable';
import FindingDetailModal from './components/FindingDetailModal';
import RemediationMatrix from './components/RemediationMatrix';
import ScanHistory from './components/ScanHistory';

import { checkHealth, submitScan, getScan, getScans } from './api/client';

export default function App() {
  const [health, setHealth] = useState(null);
  const [scans, setScans] = useState([]);
  const [currentScan, setCurrentScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(false);

  // Modals state
  const [pendingActivePayload, setPendingActivePayload] = useState(null);
  const [showGuide, setShowGuide] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Poll timer reference
  const pollTimerRef = useRef(null);

  // Initial health and scan load
  const loadInitialData = async () => {
    try {
      const h = await checkHealth();
      setHealth(h);
    } catch (e) {
      console.warn('Backend offline or healthcheck failed:', e);
    }

    try {
      const pastScans = await getScans();
      setScans(pastScans);
      if (pastScans.length > 0 && !currentScan) {
        // Load latest scan
        loadScanDetails(pastScans[0].id);
      }
    } catch (e) {
      console.warn('Could not load past scans:', e);
    }
  };

  useEffect(() => {
    loadInitialData();
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, []);

  // Poll current scan if active
  useEffect(() => {
    if (!currentScan || ['completed', 'failed'].includes(currentScan.status)) {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      return;
    }

    pollTimerRef.current = setInterval(async () => {
      try {
        const updated = await getScan(currentScan.id);
        setCurrentScan(updated);
        if (updated.findings) {
          setFindings(updated.findings);
        }
        if (['completed', 'failed'].includes(updated.status)) {
          clearInterval(pollTimerRef.current);
          setLoading(false);
          // Refresh past scans list
          const pastScans = await getScans();
          setScans(pastScans);
        }
      } catch (e) {
        console.error('Error polling scan status:', e);
      }
    }, 2500);

    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [currentScan?.id, currentScan?.status]);

  const loadScanDetails = async (scanId) => {
    try {
      const s = await getScan(scanId);
      setCurrentScan(s);
      setFindings(s.findings || []);
    } catch (e) {
      alert(`Failed to load scan: ${e.message}`);
    }
  };

  const handleFormSubmit = async (formData) => {
    if (formData.scan_mode === 'active' && !formData.active_scan_confirmed) {
      setPendingActivePayload(formData);
      return;
    }

    await launchScan(formData);
  };

  const launchScan = async (payload) => {
    setLoading(true);
    try {
      const created = await submitScan(payload);
      setCurrentScan(created);
      setFindings([]);
      // Scroll to progress
      window.scrollTo({ top: 300, behavior: 'smooth' });
    } catch (e) {
      alert(`Scan failed to start: ${e.message}`);
      setLoading(false);
    }
  };

  const handleActiveConfirmed = async () => {
    if (!pendingActivePayload) return;
    const finalPayload = {
      ...pendingActivePayload,
      active_scan_confirmed: true
    };
    setPendingActivePayload(null);
    await launchScan(finalPayload);
  };

  return (
    <div className="app-container">
      <Header
        health={health}
        currentScan={currentScan}
        onNewScan={() => {
          setCurrentScan(null);
          setFindings([]);
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }}
        onOpenHistory={() => setShowHistory(true)}
        onOpenGuide={() => setShowGuide(true)}
      />

      <main className="main-content">
        <DisclaimerBanner />

        {/* Scan Input Form (Shown always or when launching new) */}
        <ScanForm
          onSubmit={handleFormSubmit}
          loading={loading}
        />

        {/* Live Progress Bar (when scan in progress or just finished) */}
        {currentScan && (
          <ScanProgress scan={currentScan} />
        )}

        {/* Dashboard Results (When scan is completed) */}
        {currentScan?.status === 'completed' && (
          <>
            <SummaryCards
              scan={currentScan}
              findings={findings}
            />

            <FindingsTable
              findings={findings}
              onSelectFinding={(f) => setSelectedFinding(f)}
            />

            <RemediationMatrix
              findings={findings}
            />
          </>
        )}
      </main>

      {/* Active Scan Double Confirmation Modal */}
      {pendingActivePayload && (
        <ActiveScanConfirmModal
          targetUrl={pendingActivePayload.target_url}
          onConfirm={handleActiveConfirmed}
          onCancel={() => setPendingActivePayload(null)}
        />
      )}

      {/* Scope Rules Guide Modal */}
      {showGuide && (
        <ScopeRulesGuideModal
          onClose={() => setShowGuide(false)}
        />
      )}

      {/* Historical Scans Drawer */}
      {showHistory && (
        <ScanHistory
          scans={scans}
          onSelectScan={loadScanDetails}
          onClose={() => setShowHistory(false)}
        />
      )}

      {/* Finding Detail Inspection Modal */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  );
}
