import os
import json
import html
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from config import settings

class ReportService:
    """
    Generates vulnerability assessment reports in standalone styled HTML and PDF formats.
    Includes: Executive Summary, Scope & Authorization Record, Detailed Findings,
    Remediation Summary Matrix, and Methodology Notes.
    """

    @classmethod
    def get_severity_color(cls, severity: str) -> str:
        s = severity.lower()
        if s == "critical":
            return "#ef4444"  # Red
        elif s == "high":
            return "#f97316"  # Orange
        elif s == "medium":
            return "#eab308"  # Yellow
        elif s == "low":
            return "#3b82f6"  # Blue
        return "#6b7280"      # Gray

    @classmethod
    def _generate_llm_section_html(cls, findings: list[dict]) -> str:
        """Generates the HTML for the LLM Security (OWASP Top 10 for LLM Applications) section."""
        llm_findings = [f for f in findings if (f.get("source") == "llm_redteam" or f.get("finding_id", "").startswith("CS-LLM") or f.get("_llm_strategy")) and f.get("ai_verdict") != "false_positive"]
        if not llm_findings:
            return ""

        cards = ""
        for f in llm_findings:
            sev = f.get("severity", "Medium")
            sev_color = cls.get_severity_color(sev)
            owasp_cat = f.get("owasp_category", "")
            plugin_id = f.get("_llm_plugin_id", "")
            strategy = f.get("_llm_strategy", "direct")
            adv_prompt = f.get("evidence", {}).get("request", "") or "[not captured]"
            model_resp = f.get("evidence", {}).get("response", "") or "[not captured]"
            pfoo_reason = f.get("_llm_promptfoo_reason", "")
            remediation = f.get("remediation", "")
            refs = f.get("references", [])
            refs_html = "".join([f'<li><a href="{r}" target="_blank" rel="noopener">{r}</a></li>' for r in refs])

            cards += f"""
            <div class="finding-card" id="{f.get('finding_id')}" style="border-left: 4px solid #a855f7;">
                <div class="finding-header" style="border-bottom: 1px solid #7c3aed;">
                    <div class="finding-title-row">
                        <span class="finding-id" style="color: #a855f7;">{f.get('finding_id')}</span>
                        <h3 class="finding-title">{f.get('title')}</h3>
                        <span class="severity-badge" style="background-color: {sev_color};">{sev}</span>
                        <span style="background:#7c3aed;color:white;padding:4px 10px;border-radius:6px;font-size:11px;font-weight:700;text-transform:uppercase;">LLM Red-Team</span>
                    </div>
                    <div class="finding-meta-row">
                        <span class="meta-tag">{owasp_cat}</span>
                        <span class="meta-tag">Plugin: {plugin_id}</span>
                        <span class="meta-tag">Strategy: {strategy or 'direct'}</span>
                        <span class="meta-tag">CVSS: {f.get('cvss_score')}</span>
                    </div>
                </div>
                <div class="finding-body">
                    <div class="section-label">LLM Endpoint Tested</div>
                    <div class="url-box" style="color: #a855f7;">{f.get('affected_url')}</div>

                    <div class="section-label">OWASP LLM Top 10 Category</div>
                    <p class="description-text">{owasp_cat}</p>

                    <div class="section-label">Description</div>
                    <p class="description-text">{f.get('description', '')}</p>

                    <div class="ai-box" style="border-color: rgba(168,85,247,0.4); background: rgba(168,85,247,0.06);">
                        <div class="ai-box-header">
                            <span class="ai-sparkle">&#10024;</span>
                            <strong>Gemini AI Triage Verdict:</strong>
                            <span class="verdict-tag verdict-{f.get('ai_verdict')}">{f.get('ai_verdict', '').upper()}</span>
                        </div>
                        <div class="ai-reasoning">
                            <strong>Evidence-Quoted Reasoning:</strong> {f.get('ai_reasoning', '')}
                        </div>
                        {f'<div class="ai-reasoning" style="margin-top:6px;"><strong>promptfoo Reason:</strong> {pfoo_reason}</div>' if pfoo_reason else ''}
                    </div>

                    <div class="evidence-grid">
                        <div class="evidence-col">
                            <div class="evidence-title">Adversarial Prompt (Sent to LLM)</div>
                            <pre class="code-block"><code>{adv_prompt[:1500]}</code></pre>
                        </div>
                        <div class="evidence-col">
                            <div class="evidence-title">LLM Model Response (Evidence)</div>
                            <pre class="code-block"><code>{model_resp[:1500]}</code></pre>
                        </div>
                    </div>

                    <div class="section-label">LLM-Specific Remediation</div>
                    <div class="remediation-box" style="border-left-color: #a855f7;">
                        <pre class="remediation-text">{remediation}</pre>
                    </div>

                    {f'<div class="section-label">References &amp; Standards</div><ul class="references-list">{refs_html}</ul>' if refs_html else ''}
                </div>
            </div>
            """

        return f"""
        <div class="section-box" style="border-color: #7c3aed;">
            <h2 class="section-heading" style="color: #a855f7;">&#127760; LLM Security (OWASP Top 10 for LLM Applications) &mdash; {len(llm_findings)} Finding(s)</h2>
            {cards}
        </div>
        """

    @classmethod
    def generate_html_report(cls, scan: dict, findings: list[dict]) -> str:
        """Generates a self-contained, responsive, printable HTML report."""
        summary = scan.get("summary", {})
        active_findings = [f for f in findings if f.get("ai_verdict") != "false_positive"]
        false_positives = [f for f in findings if f.get("ai_verdict") == "false_positive"]

        critical_count = sum(1 for f in active_findings if f.get("severity") == "Critical")
        high_count = sum(1 for f in active_findings if f.get("severity") == "High")
        medium_count = sum(1 for f in active_findings if f.get("severity") == "Medium")
        low_count = sum(1 for f in active_findings if f.get("severity") == "Low")

        has_llm = bool(scan.get("llm_endpoint_url"))
        if has_llm:
            web_findings = [f for f in active_findings if f.get("source") != "llm_redteam" and not f.get("finding_id", "").startswith("CS-LLM") and not f.get("_llm_strategy")]
            llm_section_html = cls._generate_llm_section_html(findings)
        else:
            web_findings = active_findings
            llm_section_html = ""

        findings_html = ""
        for idx, f in enumerate(web_findings, 1):
            sev = f.get("severity", "Medium")
            sev_color = cls.get_severity_color(sev)
            novel_badge = '<span class="novel-badge">Novel Pattern</span>' if f.get("novel_pattern_flag") else ''
            mitre_badge = f'<span class="meta-tag mitre">MITRE ATT&CK: {f.get("mitre_attack_technique")}</span>' if f.get("mitre_attack_technique") else ''
            
            req_snippet = f.get("evidence", {}).get("request", "")
            resp_snippet = f.get("evidence", {}).get("response", "")

            refs_html = "".join([f'<li><a href="{r}" target="_blank" rel="noopener">{r}</a></li>' for r in f.get("references", [])])

            findings_html += f"""
            <div class="finding-card" id="{f.get('finding_id')}">
                <div class="finding-header">
                    <div class="finding-title-row">
                        <span class="finding-id">{f.get('finding_id')}</span>
                        <h3 class="finding-title">{f.get('title')}</h3>
                        <span class="severity-badge" style="background-color: {sev_color};">{sev}</span>
                        {novel_badge}
                    </div>
                    <div class="finding-meta-row">
                        <span class="meta-tag">CVSS: {f.get('cvss_score')} ({f.get('cvss_vector')})</span>
                        <span class="meta-tag">{f.get('cwe_id')}</span>
                        <span class="meta-tag">{f.get('owasp_category')}</span>
                        {mitre_badge}
                    </div>
                </div>

                <div class="finding-body">
                    <div class="section-label">Affected Target URL</div>
                    <div class="url-box">{f.get('affected_url')}</div>

                    <div class="section-label">Vulnerability Description</div>
                    <p class="description-text">{f.get('description')}</p>

                    <div class="ai-box">
                        <div class="ai-box-header">
                            <span class="ai-sparkle">&#10024;</span>
                            <strong>Gemini AI Triage Verdict:</strong>
                            <span class="verdict-tag verdict-{f.get('ai_verdict')}">{f.get('ai_verdict', '').upper()}</span>
                        </div>
                        <div class="ai-reasoning">
                            <strong>Evidence-Quoted Reasoning:</strong> {f.get('ai_reasoning')}
                        </div>
                    </div>

                    <div class="evidence-grid">
                        <div class="evidence-col">
                            <div class="evidence-title">HTTP Request Evidence</div>
                            <pre class="code-block"><code>{req_snippet or '[No request payload captured]'}</code></pre>
                        </div>
                        <div class="evidence-col">
                            <div class="evidence-title">HTTP Response Evidence</div>
                            <pre class="code-block"><code>{resp_snippet or '[No response payload captured]'}</code></pre>
                        </div>
                    </div>

                    <div class="section-label">Actionable Remediation</div>
                    <div class="remediation-box">
                        <pre class="remediation-text">{f.get('remediation')}</pre>
                    </div>

                    {f'<div class="section-label">References & Standards</div><ul class="references-list">{refs_html}</ul>' if refs_html else ''}
                </div>
            </div>
            """

        remediation_rows = ""
        for f in active_findings:
            remediation_rows += f"""
            <tr>
                <td><strong>{f.get('finding_id')}</strong></td>
                <td>{f.get('title')}</td>
                <td><span class="severity-pill" style="background-color: {cls.get_severity_color(f.get('severity'))}">{f.get('severity')}</span></td>
                <td>{f.get('cwe_id')}</td>
                <td class="remed-cell">{f.get('remediation')[:180]}...</td>
            </tr>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CognoSieve Vulnerability Report - {scan.get('target_url')}</title>
    <style>
        :root {{
            --bg-color: #0b1120;
            --surface-color: #1e293b;
            --surface-border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-emerald: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            line-height: 1.6;
            padding: 30px;
        }}
        .report-container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 25px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
        }}
        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--surface-border);
            padding-bottom: 20px;
            margin-bottom: 20px;
        }}
        .logo-title {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .brand {{
            font-size: 28px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(90deg, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .report-subtitle {{
            color: var(--text-muted);
            font-size: 14px;
        }}
        .risk-badge {{
            background: #0f172a;
            border: 1px solid var(--accent-cyan);
            border-radius: 10px;
            padding: 12px 20px;
            text-align: center;
        }}
        .risk-score {{
            font-size: 28px;
            font-weight: 800;
            color: var(--accent-cyan);
        }}
        .risk-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        .metric-card {{
            background: rgba(15, 23, 42, 0.7);
            border: 1px solid var(--surface-border);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 26px;
            font-weight: 700;
        }}
        .metric-name {{
            font-size: 12px;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-top: 4px;
        }}
        .section-box {{
            background: var(--surface-color);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 25px;
        }}
        .section-heading {{
            font-size: 20px;
            font-weight: 700;
            margin-bottom: 16px;
            color: #f1f5f9;
            border-bottom: 2px solid #334155;
            padding-bottom: 8px;
        }}
        .scope-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .scope-table th, .scope-table td {{
            text-align: left;
            padding: 10px 14px;
            border-bottom: 1px solid #334155;
            font-size: 14px;
        }}
        .scope-table th {{
            color: var(--text-muted);
            font-weight: 600;
            width: 25%;
        }}
        .rule-pre {{
            background: #0f172a;
            padding: 8px 12px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 13px;
            white-space: pre-wrap;
            color: #e2e8f0;
        }}
        .finding-card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            margin-bottom: 22px;
            overflow: hidden;
        }}
        .finding-header {{
            background: #0f172a;
            padding: 18px 24px;
            border-bottom: 1px solid #334155;
        }}
        .finding-title-row {{
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 8px;
        }}
        .finding-id {{
            font-family: monospace;
            font-weight: 700;
            color: var(--accent-cyan);
            font-size: 15px;
        }}
        .finding-title {{
            font-size: 18px;
            font-weight: 600;
            flex-grow: 1;
        }}
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 6px;
            font-weight: 700;
            font-size: 12px;
            color: #ffffff;
            text-transform: uppercase;
        }}
        .novel-badge {{
            background: #8b5cf6;
            color: white;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .finding-meta-row {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}
        .meta-tag {{
            background: #1e293b;
            border: 1px solid #475569;
            color: #cbd5e1;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-family: monospace;
        }}
        .finding-body {{
            padding: 24px;
        }}
        .section-label {{
            font-size: 12px;
            text-transform: uppercase;
            font-weight: 700;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin: 16px 0 6px 0;
        }}
        .section-label:first-child {{
            margin-top: 0;
        }}
        .url-box {{
            background: #0f172a;
            padding: 8px 12px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 13px;
            word-break: break-all;
            color: #38bdf8;
            border: 1px solid #1e293b;
        }}
        .description-text {{
            font-size: 14px;
            color: #e2e8f0;
        }}
        .ai-box {{
            background: rgba(14, 165, 233, 0.08);
            border: 1px solid rgba(14, 165, 233, 0.3);
            border-radius: 8px;
            padding: 16px;
            margin: 18px 0;
        }}
        .ai-box-header {{
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 8px;
            font-size: 14px;
        }}
        .verdict-tag {{
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
        }}
        .verdict-confirmed {{ background: #ef4444; color: white; }}
        .verdict-needs_review {{ background: #f59e0b; color: white; }}
        .verdict-false_positive {{ background: #10b981; color: white; }}
        .ai-reasoning {{
            font-size: 13px;
            color: #cbd5e1;
            line-height: 1.5;
        }}
        .evidence-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin: 16px 0;
        }}
        .evidence-title {{
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}
        .code-block {{
            background: #090d16;
            border: 1px solid #1e293b;
            border-radius: 6px;
            padding: 12px;
            font-family: monospace;
            font-size: 12px;
            color: #94a3b8;
            max-height: 220px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .remediation-box {{
            background: #0f172a;
            border-left: 4px solid var(--accent-emerald);
            padding: 14px 18px;
            border-radius: 0 8px 8px 0;
        }}
        .remediation-text {{
            font-family: monospace;
            font-size: 13px;
            color: #e2e8f0;
            white-space: pre-wrap;
        }}
        .references-list {{
            margin-left: 20px;
            margin-top: 6px;
            font-size: 13px;
        }}
        .references-list a {{
            color: #38bdf8;
            text-decoration: none;
        }}
        .references-list a:hover {{
            text-decoration: underline;
        }}
        .remed-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        .remed-table th, .remed-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid #334155;
            text-align: left;
        }}
        .remed-table th {{
            background: #0f172a;
            color: var(--text-muted);
        }}
        .remed-cell {{
            font-family: monospace;
            font-size: 12px;
            color: #cbd5e1;
        }}
        .severity-pill {{
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            color: white;
        }}
        .methodology-box {{
            background: #0f172a;
            border: 1px solid var(--surface-border);
            border-radius: 10px;
            padding: 20px;
            font-size: 13px;
            color: #94a3b8;
            line-height: 1.6;
        }}
        @media print {{
            body {{ background-color: #ffffff; color: #000000; padding: 0; }}
            .report-container {{ max-width: 100%; }}
            .header, .section-box, .finding-card {{
                background: #ffffff !important;
                border: 1px solid #cccccc !important;
                color: #000000 !important;
                page-break-inside: avoid;
            }}
            .code-block, .url-box, .remediation-box {{
                background: #f8fafc !important;
                color: #000000 !important;
                border: 1px solid #e2e8f0 !important;
            }}
            .meta-tag, .finding-header {{
                background: #f1f5f9 !important;
                color: #000000 !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <!-- HEADER & EXECUTIVE SUMMARY -->
        <div class="header">
            <div class="header-top">
                <div class="logo-title">
                    <div>
                        <div class="brand">COGNOSIEVE</div>
                        <div class="report-subtitle">Automated DAST & Gemini-Triaged Security Assessment Report</div>
                    </div>
                </div>
                <div class="risk-badge">
                    <div class="risk-score">{summary.get('overall_risk_score', 0.0)}</div>
                    <div class="risk-label">Overall Risk Score</div>
                </div>
            </div>

            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-value" style="color: #ef4444;">{critical_count}</div>
                    <div class="metric-name">Critical</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: #f97316;">{high_count}</div>
                    <div class="metric-name">High</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: #eab308;">{medium_count}</div>
                    <div class="metric-name">Medium</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: #3b82f6;">{low_count}</div>
                    <div class="metric-name">Low</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: #10b981;">{len(false_positives)}</div>
                    <div class="metric-name">False Positives Filtered</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: #a855f7;">{summary.get('novel_patterns', 0)}</div>
                    <div class="metric-name">Novel Patterns</div>
                </div>
            </div>
        </div>

        <!-- SCOPE AND AUTHORIZATION RECORD -->
        <div class="section-box">
            <h2 class="section-heading">Scope & Authorization Record</h2>
            <table class="scope-table">
                <tr>
                    <th>Target Base URL:</th>
                    <td><strong>{scan.get('target_url')}</strong></td>
                </tr>
                <tr>
                    <th>Scan Mode:</th>
                    <td>{scan.get('scan_mode', '').upper()} {'(Explicit 2nd confirmation verified)' if scan.get('active_scan_confirmed') else ''}</td>
                </tr>
                <tr>
                    <th>Authorization Status:</th>
                    <td>&#9989; CONFIRMED - "I own this target or have written permission to test it"</td>
                </tr>
                <tr>
                    <th>Authorization Timestamp:</th>
                    <td>{scan.get('authorized_at', scan.get('created_at'))}</td>
                </tr>
                <tr>
                    <th>Business Multiplier:</th>
                    <td>{scan.get('business_impact_multiplier', 1.0)}x</td>
                </tr>
                <tr>
                    <th>Exposure Factor:</th>
                    <td>{scan.get('exposure_factor', 1.0)}x</td>
                </tr>
                <tr>
                    <th>In-Scope Allow-List Rules:</th>
                    <td><div class="rule-pre">{scan.get('in_scope')}</div></td>
                </tr>
                <tr>
                    <th>Out-of-Scope Rules:</th>
                    <td><div class="rule-pre">{scan.get('out_of_scope') or '[None specified]'}</div></td>
                </tr>
            </table>
        </div>

        <!-- DETAILED FINDINGS -->
        <div class="section-box">
            <h2 class="section-heading">Confirmed &amp; Needs-Review Vulnerability Findings ({len(web_findings)})</h2>
            {findings_html if findings_html else '<p style="color: var(--text-muted);">No confirmed security vulnerabilities detected within scope.</p>'}
        </div>

        {llm_section_html}

        <!-- REMEDIATION SUMMARY MATRIX -->
        <div class="section-box">
            <h2 class="section-heading">Remediation Summary Matrix</h2>
            <table class="remed-table">
                <thead>
                    <tr>
                        <th style="width: 12%;">ID</th>
                        <th style="width: 25%;">Vulnerability</th>
                        <th style="width: 10%;">Severity</th>
                        <th style="width: 12%;">CWE</th>
                        <th style="width: 41%;">Remediation Guidance</th>
                    </tr>
                </thead>
                <tbody>
                    {remediation_rows if remediation_rows else '<tr><td colspan="5">No remediation actions needed.</td></tr>'}
                </tbody>
            </table>
        </div>

        <!-- METHODOLOGY NOTE -->
        <div class="section-box">
            <h2 class="section-heading">Methodology Note</h2>
            <div class="methodology-box">
                <p>
                    <strong>Assessment Methodology:</strong> This assessment was conducted utilizing automated OWASP ZAP dynamic application security testing (DAST) restricted strictly to authorized in-scope endpoints, integrated with Google Gemini API for deep triage and false-positive reduction. Raw scanner alerts were grouped by root cause and correlated against HTTP request and response evidence. Gemini AI validated each alert to eliminate scanner hallucinations and identify novel vulnerability patterns.
                </p>
                <br>
                <p>
                    <strong>Important Disclaimer:</strong> This automated and AI-assisted assessment augments, but does not replace, comprehensive manual penetration testing, source code review, and threat modeling. Testing was conducted exclusively against targets authorized by the assessment requestor.
                </p>
            </div>
        </div>
    </div>
</body>
</html>
"""
        return html_template

    @classmethod
    def generate_pdf_report(cls, scan: dict, findings: list[dict], output_filepath: str) -> str:
        """Generates a professional PDF report using ReportLab."""
        Path(output_filepath).parent.mkdir(parents=True, exist_ok=True)
        doc = SimpleDocTemplate(
            output_filepath,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0f172a'),
            fontName='Helvetica-Bold'
        )
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#475569')
        )
        h2_style = ParagraphStyle(
            'H2',
            parent=styles['Heading2'],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#0f172a'),
            fontName='Helvetica-Bold',
            spaceBefore=14,
            spaceAfter=8
        )
        body_style = ParagraphStyle(
            'Body',
            parent=styles['Normal'],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#1e293b')
        )
        code_style = ParagraphStyle(
            'Code',
            parent=styles['Normal'],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#334155'),
            fontName='Courier'
        )

        story = []

        # Title
        story.append(Paragraph("COGNOSIEVE - Vulnerability Assessment Report", title_style))
        story.append(Paragraph(f"Target: {scan.get('target_url')} | Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style))
        story.append(Spacer(1, 12))

        # Executive Summary Metrics Table
        summary = scan.get("summary", {})
        active_findings = [f for f in findings if f.get("ai_verdict") != "false_positive"]
        false_positives = [f for f in findings if f.get("ai_verdict") == "false_positive"]

        critical_count = sum(1 for f in active_findings if f.get("severity") == "Critical")
        high_count = sum(1 for f in active_findings if f.get("severity") == "High")
        medium_count = sum(1 for f in active_findings if f.get("severity") == "Medium")
        low_count = sum(1 for f in active_findings if f.get("severity") == "Low")

        metrics_data = [
            ["Risk Score", "Critical", "High", "Medium", "Low", "False Positives", "Novel Patterns"],
            [
                str(summary.get("overall_risk_score", 0.0)),
                str(critical_count),
                str(high_count),
                str(medium_count),
                str(low_count),
                str(len(false_positives)),
                str(summary.get("novel_patterns", 0))
            ]
        ]
        t_metrics = Table(metrics_data, colWidths=[75, 75, 75, 75, 75, 85, 80])
        t_metrics.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f8fafc')),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 1), (-1, 1), 12),
        ]))
        story.append(t_metrics)
        story.append(Spacer(1, 14))

        # Scope and Authorization Record
        story.append(Paragraph("Scope & Authorization Record", h2_style))
        scope_data = [
            ["Target URL", scan.get("target_url", "")],
            ["Scan Mode", f"{scan.get('scan_mode', '').upper()} (Active Confirmed: {scan.get('active_scan_confirmed')})"],
            ["Authorization Status", "CONFIRMED - Explicit authorization granted by operator"],
            ["Authorized At", str(scan.get("authorized_at", scan.get("created_at")))],
            ["In-Scope Rules", scan.get("in_scope", "")],
            ["Out-of-Scope Rules", scan.get("out_of_scope", "") or "None"]
        ]
        t_scope = Table(scope_data, colWidths=[140, 400])
        t_scope.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_scope)
        story.append(Spacer(1, 14))

        # Findings Detail
        has_llm = bool(scan.get("llm_endpoint_url"))
        web_findings = [f for f in active_findings if f.get("source") != "llm_redteam" and not f.get("finding_id", "").startswith("CS-LLM") and not f.get("_llm_strategy")] if has_llm else active_findings
        story.append(Paragraph(f"Confirmed Vulnerability Findings ({len(web_findings)})", h2_style))
        for f in web_findings:
            sev = html.escape(str(f.get("severity", "Medium")))
            fid = html.escape(str(f.get("finding_id", "")))
            title = html.escape(str(f.get("title", "")))
            score = f.get("cvss_score", 0.0)
            cwe = html.escape(str(f.get("cwe_id", "")))
            owasp = html.escape(str(f.get("owasp_category", "")))
            mitre = html.escape(str(f.get("mitre_attack_technique") or "N/A"))
            url = html.escape(str(f.get("affected_url", "")))
            desc = html.escape(str(f.get("description", "")))
            verdict = html.escape(str(f.get("ai_verdict", "")).upper())
            reasoning = html.escape(str(f.get("ai_reasoning", "")))
            remed = html.escape(str(f.get("remediation", ""))[:250])

            finding_content = [
                Paragraph(f"<b>[{fid}] {title}</b> - <b>{sev} (CVSS: {score})</b>", body_style),
                Spacer(1, 3),
                Paragraph(f"<b>CWE:</b> {cwe} | <b>OWASP:</b> {owasp} | <b>MITRE:</b> {mitre}", body_style),
                Paragraph(f"<b>URL:</b> {url}", body_style),
                Paragraph(f"<b>Description:</b> {desc}", body_style),
                Paragraph(f"<b>Gemini AI Verdict:</b> [{verdict}] {reasoning}", body_style),
                Paragraph(f"<b>Remediation:</b> {remed}", body_style),
                Spacer(1, 8),
                HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e2e8f0'), spaceAfter=8)
            ]
            story.append(KeepTogether(finding_content))

        # LLM Security Section in PDF
        if scan.get("llm_endpoint_url"):
            story.append(Spacer(1, 10))
            story.append(Paragraph("LLM Security (OWASP Top 10 for LLM Applications)", h2_style))
            story.append(Paragraph(f"Target LLM Endpoint: {scan.get('llm_endpoint_url')}", subtitle_style))
            story.append(Spacer(1, 8))
            llm_findings = [f for f in active_findings if (f.get("source") == "llm_redteam" or f.get("finding_id", "").startswith("CS-LLM") or f.get("_llm_strategy"))]
            if llm_findings:
                for f in llm_findings:
                    sev = html.escape(str(f.get("severity", "Medium")))
                    fid = html.escape(str(f.get("finding_id", "")))
                    title = html.escape(str(f.get("title", "")))
                    score = f.get("cvss_score", 0.0)
                    owasp = html.escape(str(f.get("owasp_category", "")))
                    strategy = html.escape(str(f.get("_llm_strategy") or "direct"))
                    url = html.escape(str(f.get("affected_url", "")))
                    desc = html.escape(str(f.get("description", "")))
                    verdict = html.escape(str(f.get("ai_verdict", "")).upper())
                    reasoning = html.escape(str(f.get("ai_reasoning", "")))
                    remed = html.escape(str(f.get("remediation", ""))[:250])

                    llm_content = [
                        Paragraph(f"<b>[{fid}] {title}</b> - <b>{sev} (Score: {score})</b>", body_style),
                        Spacer(1, 3),
                        Paragraph(f"<b>OWASP LLM:</b> {owasp} | <b>Strategy:</b> {strategy}", body_style),
                        Paragraph(f"<b>Endpoint:</b> {url}", body_style),
                        Paragraph(f"<b>Description:</b> {desc}", body_style),
                        Paragraph(f"<b>Gemini AI Verdict:</b> [{verdict}] {reasoning}", body_style),
                        Paragraph(f"<b>Remediation:</b> {remed}", body_style),
                        Spacer(1, 8),
                        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e2e8f0'), spaceAfter=8)
                    ]
                    story.append(KeepTogether(llm_content))
            else:
                story.append(Paragraph("No LLM vulnerabilities detected. Model successfully resisted prompt injection attacks.", body_style))

        # Remediation Summary Matrix
        story.append(Spacer(1, 10))
        story.append(Paragraph("Remediation Summary Matrix", h2_style))
        remed_table_data = [["ID", "Title", "Severity", "Actionable Fix"]]
        for f in active_findings:
            remed_table_data.append([
                f.get("finding_id"),
                f.get("title")[:30],
                f.get("severity"),
                f.get("remediation")[:100] + "..."
            ])
        t_remed = Table(remed_table_data, colWidths=[65, 130, 65, 280])
        t_remed.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_remed)

        # Methodology Note
        story.append(Spacer(1, 16))
        story.append(Paragraph("Methodology Note", h2_style))
        methodology_text = (
            "This assessment was performed using CognoSieve's combined pipeline: automated OWASP ZAP DAST "
            "scanning restricted to verified in-scope allow-list rules, plus optional OWASP Top 10 for LLM "
            "Applications 2025 red-teaming via promptfoo when an LLM endpoint was provided. "
            "All alerts were triaged via Google Gemini API using evidence-based analysis to filter false "
            "positives and identify novel patterns. "
            "This automated assessment augments, not replaces, comprehensive manual security testing."
        )
        story.append(Paragraph(methodology_text, body_style))

        doc.build(story)
        return output_filepath
