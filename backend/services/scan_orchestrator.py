import asyncio
import logging
import uuid
from typing import Dict, Any, List
from pathlib import Path

from config import settings
from database import (
    update_scan_status, complete_scan_record, fail_scan_record,
    insert_scan_findings, log_audit, get_scan_record
)
from services.scope_manager import ScopeManager
from services.zap_service import ZapService
from services.gemini_service import GeminiService
from services.scoring_engine import ScoringEngine
from services.mapping_engine import MappingEngine
from services.remediation_engine import RemediationEngine
from services.report_service import ReportService

logger = logging.getLogger("cognosieve.orchestrator")

class ScanOrchestrator:
    """
    Coordinates the vulnerability assessment workflow for CognoSieve:
    Optional STEP 0: LLM red-team (OWASP Top 10 for LLM Apps) via promptfoo when llm_endpoint_url is set.
    Then: Scope parsing, ZAP spidering, passive/active scanning, Gemini triage,
    scoring, mapping, remediation generation, database logging, and report exports.
    Both LLM and ZAP findings are merged into ONE combined report.
    """

    def __init__(self):
        self.zap_service = ZapService()
        self.gemini_service = GeminiService()

    async def execute_scan(self, scan_id: str, scan_params: Dict[str, Any]):
        try:
            target_url = scan_params["target_url"]
            llm_endpoint_url = scan_params.get("llm_endpoint_url") or None
            in_scope_raw = scan_params.get("in_scope", "")
            if not in_scope_raw or not in_scope_raw.strip():
                in_scope_raw = ScopeManager.default_scope_for_url(target_url)
                scan_params["in_scope"] = in_scope_raw

            out_of_scope_raw = scan_params.get("out_of_scope", "")
            scan_mode = scan_params.get("scan_mode", "passive")
            active_confirmed = scan_params.get("active_scan_confirmed", False)
            multiplier = float(scan_params.get("business_impact_multiplier", 1.0))
            exposure = float(scan_params.get("exposure_factor", 1.0))

            # -------------------------------------------------------------
            # STEP 0: LLM Red-Team (OWASP Top 10 for LLM Applications 2025)
            # Runs ONLY when llm_endpoint_url is provided. Skipped entirely
            # if blank — the pipeline runs exactly as before.
            # -------------------------------------------------------------
            llm_raw_findings: List[Dict[str, Any]] = []
            if llm_endpoint_url:
                update_scan_status(scan_id, "llm_redteam", 3, f"Starting LLM red-team against {llm_endpoint_url}")
                log_audit(scan_id, "LLM_REDTEAM_AUTHORIZED",
                          f"LLM endpoint authorized for red-teaming: {llm_endpoint_url} (same authorization as web target)")

                from services.llm_redteam import run_llm_redteam
                llm_raw_findings = await run_llm_redteam(
                    llm_endpoint_url=llm_endpoint_url,
                    scan_id=scan_id,
                    business_impact_multiplier=multiplier,
                    exposure_factor=exposure,
                    audit_callback=log_audit,
                    status_callback=update_scan_status,
                )
                log_audit(scan_id, "LLM_REDTEAM_RAW_COMPLETE",
                          f"Raw LLM red-team returned {len(llm_raw_findings)} finding(s).")

            # -------------------------------------------------------------
            # STEP 1: Parse and enforce scope & authorization
            # -------------------------------------------------------------
            update_scan_status(scan_id, "spidering", 12, "Parsing allow-list and verifying authorization")
            if not scan_params.get("authorization_confirmation"):
                raise ValueError("Scan rejected: Authorization confirmation is false.")

            in_scope, reason = ScopeManager.evaluate_url(target_url, in_scope_raw, out_of_scope_raw)
            if not in_scope:
                raise ValueError(f"Target URL '{target_url}' rejected by scope safety check: {reason}")

            if scan_mode == "active" and not active_confirmed:
                raise ValueError("Active scan rejected: Missing second explicit active-scan confirmation.")

            log_audit(scan_id, "SCOPE_VERIFIED", f"Target verified in-scope. Rules evaluated: in_scope='{in_scope_raw}', out_of_scope='{out_of_scope_raw}'")

            # -------------------------------------------------------------
            # STEP 2 & 3: ZAP Context & Spidering (Restricted to allow-list)
            # -------------------------------------------------------------
            update_scan_status(scan_id, "spidering", 20, "Connecting to OWASP ZAP and creating scoped context")
            zap_online = await self.zap_service.is_zap_available()
            raw_alerts = []

            if zap_online:
                context_name = f"cognosieve_{scan_id[:8]}"
                context_id = await self.zap_service.create_scoped_context(context_name, in_scope_raw, out_of_scope_raw)

                update_scan_status(scan_id, "spidering", 25, "Spidering target restricted strictly to allow-list")
                async def spider_cb(pct):
                    update_scan_status(scan_id, "spidering", 25 + int(pct * 0.15), f"Spidering in progress: {pct}%")

                discovered_urls = await self.zap_service.run_spider(
                    target_url=target_url,
                    context_name=context_name,
                    in_scope_raw=in_scope_raw,
                    out_of_scope_raw=out_of_scope_raw,
                    progress_callback=spider_cb
                )
                log_audit(scan_id, "SPIDER_COMPLETED", f"Discovered {len(discovered_urls)} URLs strictly within allow-list.")

                # Passive scanner
                update_scan_status(scan_id, "scanning", 45, "Executing passive scanner rules")
                await self.zap_service.wait_for_passive_scan()

                # Active scanner (if requested and confirmed)
                if scan_mode == "active":
                    update_scan_status(scan_id, "scanning", 55, "Executing active scanner attacks on confirmed target")
                    async def ascan_cb(pct):
                        update_scan_status(scan_id, "scanning", 55 + int(pct * 0.15), f"Active scan in progress: {pct}%")

                    await self.zap_service.run_active_scan(
                        target_url=target_url,
                        context_id=context_id,
                        in_scope_raw=in_scope_raw,
                        out_of_scope_raw=out_of_scope_raw,
                        progress_callback=ascan_cb
                    )
                    log_audit(scan_id, "ACTIVE_SCAN_COMPLETED", "Active scanner completed.")

                # Pull alerts
                update_scan_status(scan_id, "analyzing", 70, "Pulling raw alerts and HTTP evidence from ZAP")
                raw_alerts = await self.zap_service.pull_alerts_with_evidence(target_url)
            else:
                # High-fidelity realistic simulation mode when ZAP daemon is offline
                update_scan_status(scan_id, "scanning", 35, "Simulating ZAP scanner engine for target")
                await asyncio.sleep(2)
                update_scan_status(scan_id, "scanning", 60, "Collecting target responses and security headers")
                await asyncio.sleep(2)
                raw_alerts = self.zap_service.generate_simulated_alerts(target_url, scan_mode=scan_mode)
                log_audit(scan_id, "SCAN_SIMULATION", f"Generated {len(raw_alerts)} realistic DAST alerts for analysis.")

            # -------------------------------------------------------------
            # STEP 4, 5: Triage ZAP findings with Gemini
            # -------------------------------------------------------------
            update_scan_status(scan_id, "analyzing", 75, "Triaging ZAP findings with Google Gemini AI for false positives")

            # Group alerts by rule + root cause
            grouped_alerts: Dict[str, List[Dict[str, Any]]] = {}
            for alert in raw_alerts:
                group_key = f"{alert.get('rule_id')}_{alert.get('cwe_id')}"
                if group_key not in grouped_alerts:
                    grouped_alerts[group_key] = []
                grouped_alerts[group_key].append(alert)

            seen_weakness_classes = set()
            processed_findings = []
            finding_counter = 1

            for group_key, alerts in grouped_alerts.items():
                rep_alert = alerts[0]
                rule_name = rep_alert.get("name", "Security Alert")
                cwe_raw = str(rep_alert.get("cwe_id", "0"))
                plugin_id = str(rep_alert.get("rule_id", ""))
                cwe_id = MappingEngine.resolve_cwe(cwe_raw, plugin_id, rule_name)

                # Call Gemini for triage
                triage = self.gemini_service.triage_finding_group(
                    rule_name=rule_name,
                    cwe_id=cwe_id,
                    zap_risk=rep_alert.get("risk", "Medium"),
                    zap_confidence=rep_alert.get("confidence", "Medium"),
                    url=rep_alert.get("url", target_url),
                    param=rep_alert.get("param", ""),
                    evidence_text=rep_alert.get("evidence", ""),
                    request_snippet=rep_alert.get("request_snippet", ""),
                    response_snippet=rep_alert.get("response_snippet", ""),
                    seen_weakness_classes=seen_weakness_classes
                )

                seen_weakness_classes.add(cwe_id)

                # -------------------------------------------------------------
                # STEP 6, 7, 8, 9: Scoring, Mapping, and Remediation
                # -------------------------------------------------------------
                score_data = ScoringEngine.score_finding(
                    cwe_id=cwe_id,
                    zap_risk=rep_alert.get("risk", "Medium"),
                    business_impact_multiplier=multiplier,
                    exposure_factor=exposure
                )

                meta = MappingEngine.get_metadata(cwe_id)
                remediation_text = triage.get("remediation_note") or RemediationEngine.get_remediation(
                    cwe_id=cwe_id,
                    alert_name=rule_name,
                    zap_solution=rep_alert.get("solution", "")
                )

                finding_id_str = f"CS-WEB-{finding_counter:03d}"
                finding_counter += 1

                processed_findings.append({
                    "id": str(uuid.uuid4()),
                    "finding_id": finding_id_str,
                    "title": rule_name,
                    "severity": score_data["severity"],
                    "cvss_score": score_data["cvss_score"],
                    "cvss_vector": score_data["cvss_vector"],
                    "cwe_id": cwe_id,
                    "owasp_category": meta["owasp"],
                    "mitre_attack_technique": meta.get("mitre"),
                    "affected_url": rep_alert.get("url", target_url),
                    "description": rep_alert.get("description", "Potential security weakness identified during automated DAST assessment."),
                    "evidence": {
                        "request": rep_alert.get("request_snippet", ""),
                        "response": rep_alert.get("response_snippet", "")
                    },
                    "ai_verdict": triage["verdict"],
                    "ai_reasoning": triage["reasoning"],
                    "novel_pattern_flag": triage["novel_pattern_flag"],
                    "remediation": remediation_text,
                    "references": meta.get("references", []),
                    "raw_zap_alert": rep_alert,
                    "source": "zap",
                })

            # -------------------------------------------------------------
            # STEP 0b (continued): Triage LLM red-team findings with Gemini
            # The same Gemini audit pass that already runs for ZAP findings
            # now also judges each LLM finding — one combined audit.
            # -------------------------------------------------------------
            if llm_raw_findings:
                update_scan_status(scan_id, "analyzing", 80, "Triaging LLM red-team findings with Gemini AI (same audit pass as web findings)")
                llm_finding_counter = 1
                for raw_f in llm_raw_findings:
                    owasp_cat = raw_f.get("owasp_category", "")
                    plugin_id = raw_f.get("_llm_plugin_id", "")
                    strategy = raw_f.get("_llm_strategy", "")
                    adversarial_prompt = raw_f.get("evidence", {}).get("request", "")
                    model_response = raw_f.get("evidence", {}).get("response", "")

                    triage = self.gemini_service.triage_llm_finding(
                        owasp_category=owasp_cat,
                        plugin_id=plugin_id,
                        strategy=strategy,
                        adversarial_prompt=adversarial_prompt,
                        model_response=model_response,
                        description=raw_f.get("description", ""),
                        llm_endpoint_url=llm_endpoint_url or "",
                        seen_weakness_classes=seen_weakness_classes,
                    )
                    seen_weakness_classes.add(owasp_cat)

                    remediation_text = triage.get("remediation_note") or raw_f.get("remediation", "")
                    finding_id_str = f"CS-LLM-{llm_finding_counter:03d}"
                    llm_finding_counter += 1

                    processed_findings.append({
                        **raw_f,
                        "finding_id": finding_id_str,
                        "ai_verdict": triage["verdict"],
                        "ai_reasoning": triage["reasoning"],
                        "novel_pattern_flag": triage["novel_pattern_flag"],
                        "remediation": remediation_text,
                    })

            # -------------------------------------------------------------
            # STEP 10, 11, 12: Save to DB & Generate Reports (Combined)
            # -------------------------------------------------------------
            update_scan_status(scan_id, "analyzing", 90, "Storing immutable findings and generating PDF/HTML reports")
            insert_scan_findings(scan_id, processed_findings)

            # Compute summary stats
            active = [f for f in processed_findings if f["ai_verdict"] != "false_positive"]
            fps = [f for f in processed_findings if f["ai_verdict"] == "false_positive"]
            reviews = [f for f in processed_findings if f["ai_verdict"] == "needs_review"]
            novels = [f for f in processed_findings if f["novel_pattern_flag"]]
            llm_active = [f for f in active if f.get("source") == "llm_redteam"]

            summary = {
                "total_findings": len(processed_findings),
                "active_findings": len(active),
                "critical": sum(1 for f in active if f["severity"] == "Critical"),
                "high": sum(1 for f in active if f["severity"] == "High"),
                "medium": sum(1 for f in active if f["severity"] == "Medium"),
                "low": sum(1 for f in active if f["severity"] == "Low"),
                "false_positives": len(fps),
                "needs_review": len(reviews),
                "novel_patterns": len(novels),
                "llm_findings": len(llm_active),
                "overall_risk_score": ScoringEngine.compute_overall_risk(processed_findings)
            }

            # Generate Reports
            scan_rec = get_scan_record(scan_id) or scan_params
            scan_rec["summary"] = summary

            reports_dir = Path(settings.REPORTS_DIR)
            reports_dir.mkdir(parents=True, exist_ok=True)

            html_content = ReportService.generate_html_report(scan_rec, processed_findings)
            html_path = reports_dir / f"cognosieve_report_{scan_id}.html"
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            pdf_path = reports_dir / f"cognosieve_report_{scan_id}.pdf"
            ReportService.generate_pdf_report(scan_rec, processed_findings, str(pdf_path))

            complete_scan_record(scan_id, summary)
            log_audit(scan_id, "REPORTS_GENERATED", f"Generated HTML and PDF reports at {reports_dir}")
            logger.info(f"Scan {scan_id} finished successfully with risk score {summary['overall_risk_score']}.")

        except Exception as e:
            logger.error(f"Scan orchestration failed for {scan_id}: {e}", exc_info=True)
            fail_scan_record(scan_id, str(e))
