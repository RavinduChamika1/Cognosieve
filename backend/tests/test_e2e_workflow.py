import asyncio
import uuid
import pytest
from pathlib import Path
from database import init_db, create_scan_record, get_scan_record, get_scan_findings, get_scan_audit_logs
from services.scan_orchestrator import ScanOrchestrator
from config import settings

@pytest.mark.asyncio
async def test_full_e2e_scan_workflow():
    init_db()
    orchestrator = ScanOrchestrator()
    scan_id = f"test-e2e-{uuid.uuid4()}"

    scan_params = {
        "target_url": "https://testphp.vulnweb.com",
        "in_scope": "*.vulnweb.com\ntestphp.vulnweb.com",
        "out_of_scope": "/admin/*",
        "authorization_confirmation": True,
        "scan_mode": "passive",
        "active_scan_confirmed": False,
        "business_impact_multiplier": 1.2,
        "exposure_factor": 1.0
    }

    # Create scan record first (as main.py does)
    create_scan_record(scan_id, scan_params)

    # Execute orchestrator
    await orchestrator.execute_scan(scan_id, scan_params)

    # 1. Verify scan record in DB
    scan_rec = get_scan_record(scan_id)
    assert scan_rec is not None
    assert scan_rec["status"] == "completed"
    assert scan_rec["progress_percent"] == 100
    assert scan_rec["summary"] is not None
    assert scan_rec["summary"]["overall_risk_score"] > 0

    # 2. Verify findings
    findings = get_scan_findings(scan_id, include_false_positives=True)
    assert len(findings) > 0

    for f in findings:
        assert f["finding_id"].startswith("CS-") or f["finding_id"].startswith("BS-FIND-")
        assert f["severity"] in ("Critical", "High", "Medium", "Low")
        assert 0.0 <= f["cvss_score"] <= 10.0
        assert "CVSS:3.1" in f["cvss_vector"]
        assert f["cwe_id"].startswith("CWE-")
        assert f["owasp_category"] != ""
        assert f["ai_verdict"] in ("confirmed", "needs_review", "false_positive")
        assert len(f["ai_reasoning"]) > 10
        assert len(f["remediation"]) > 10

    # 3. Verify false-positive filter logic: false positive alert is marked
    fps = [f for f in findings if f["ai_verdict"] == "false_positive"]
    assert len(fps) >= 1  # False positive rule in simulation was classified correctly
    assert "false_positive" in fps[0]["ai_verdict"]

    # 4. Verify audit trail logs
    audit_logs = get_scan_audit_logs(scan_id)
    assert len(audit_logs) >= 4
    event_types = [a["event_type"] for a in audit_logs]
    assert "SCOPE_VERIFIED" in event_types
    assert "FINDINGS_SAVED" in event_types
    assert "REPORTS_GENERATED" in event_types
    assert "SCAN_COMPLETED" in event_types

    # 5. Verify HTML and PDF reports exist on disk
    reports_dir = Path(settings.REPORTS_DIR)
    html_report = reports_dir / f"cognosieve_report_{scan_id}.html"
    pdf_report = reports_dir / f"cognosieve_report_{scan_id}.pdf"

    assert html_report.exists()
    assert html_report.stat().st_size > 500
    assert pdf_report.exists()
    assert pdf_report.stat().st_size > 1000
