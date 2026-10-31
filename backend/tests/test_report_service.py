import os
from pathlib import Path
import pytest
from services.report_service import ReportService

@pytest.fixture
def sample_scan():
    return {
        "id": "test-scan-1234",
        "target_url": "https://example.com",
        "in_scope": "*.example.com\n/api/*",
        "out_of_scope": "/admin/*",
        "scan_mode": "passive",
        "active_scan_confirmed": False,
        "authorized_at": "2026-10-17T04:00:00Z",
        "business_impact_multiplier": 1.2,
        "exposure_factor": 1.0,
        "summary": {
            "overall_risk_score": 6.8,
            "total_findings": 2,
            "critical": 0,
            "high": 1,
            "medium": 1,
            "low": 0,
            "novel_patterns": 1
        }
    }

@pytest.fixture
def sample_findings():
    return [
        {
            "id": "f-1",
            "finding_id": "BS-FIND-001",
            "title": "Anti-clickjacking Header Not Set",
            "severity": "Medium",
            "cvss_score": 5.2,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "cwe_id": "CWE-1021",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "mitre_attack_technique": "T1190",
            "affected_url": "https://example.com/login",
            "description": "Missing X-Frame-Options or CSP frame-ancestors.",
            "evidence": {
                "request": "GET /login HTTP/1.1\nHost: example.com",
                "response": "HTTP/1.1 200 OK\nContent-Type: text/html"
            },
            "ai_verdict": "confirmed",
            "ai_reasoning": "Confirmed: Response headers omit X-Frame-Options and CSP frame-ancestors directive.",
            "novel_pattern_flag": False,
            "remediation": "Add Content-Security-Policy: frame-ancestors 'self';",
            "references": ["https://cwe.mitre.org/data/definitions/1021.html"]
        },
        {
            "id": "f-2",
            "finding_id": "BS-FIND-002",
            "title": "Unfiltered User Reflection in Query String",
            "severity": "High",
            "cvss_score": 8.6,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "cwe_id": "CWE-79",
            "owasp_category": "A03:2021-Injection",
            "mitre_attack_technique": "T1190",
            "affected_url": "https://example.com/search?q=test",
            "description": "User input reflected directly in response.",
            "evidence": {
                "request": "GET /search?q=<script> HTTP/1.1",
                "response": "HTTP/1.1 200 OK\n\n<div><script></div>"
            },
            "ai_verdict": "confirmed",
            "ai_reasoning": "Confirmed: Script tag reflected unencoded in response.",
            "novel_pattern_flag": True,
            "remediation": "Apply contextual output encoding.",
            "references": ["https://cwe.mitre.org/data/definitions/79.html"]
        }
    ]

def test_generate_html_report(sample_scan, sample_findings):
    html = ReportService.generate_html_report(sample_scan, sample_findings)
    assert "<!DOCTYPE html>" in html
    assert "COGNOSIEVE" in html or "BREACHSIEVE" in html
    assert "Executive Summary" or "Overall Risk Score" in html
    assert "BS-FIND-001" in html
    assert "BS-FIND-002" in html
    assert "Scope &amp; Authorization Record" in html or "Scope & Authorization Record" in html
    assert "Remediation Summary Matrix" in html
    assert "Methodology Note" in html

def test_generate_pdf_report(sample_scan, sample_findings, tmp_path):
    pdf_out = tmp_path / "test_report.pdf"
    ReportService.generate_pdf_report(sample_scan, sample_findings, str(pdf_out))
    assert pdf_out.exists()
    assert pdf_out.stat().st_size > 1000  # Generated valid non-empty PDF
