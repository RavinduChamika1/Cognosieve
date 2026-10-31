import sqlite3
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Any
from pathlib import Path
from config import settings

logger = logging.getLogger("cognosieve.database")

def get_db_path() -> str:
    db_path = Path(settings.DATABASE_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return str(db_path)

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(get_db_path(), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        target_url TEXT NOT NULL,
        in_scope TEXT NOT NULL,
        out_of_scope TEXT,
        authorization_confirmed INTEGER NOT NULL,
        authorized_at TEXT NOT NULL,
        scan_mode TEXT NOT NULL,
        active_scan_confirmed INTEGER NOT NULL DEFAULT 0,
        business_impact_multiplier REAL NOT NULL DEFAULT 1.0,
        exposure_factor REAL NOT NULL DEFAULT 1.0,
        status TEXT NOT NULL,
        progress_percent INTEGER NOT NULL DEFAULT 0,
        current_step TEXT,
        error_message TEXT,
        summary_json TEXT,
        created_at TEXT NOT NULL,
        completed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        cvss_vector TEXT NOT NULL,
        cwe_id TEXT NOT NULL,
        owasp_category TEXT NOT NULL,
        mitre_attack_technique TEXT,
        affected_url TEXT NOT NULL,
        description TEXT NOT NULL,
        request_evidence TEXT,
        response_evidence TEXT,
        ai_verdict TEXT NOT NULL,
        ai_reasoning TEXT NOT NULL,
        novel_pattern_flag INTEGER NOT NULL DEFAULT 0,
        remediation TEXT NOT NULL,
        references_json TEXT NOT NULL,
        raw_zap_alert_json TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        details TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_findings_verdict ON findings(ai_verdict);
    CREATE INDEX IF NOT EXISTS idx_audit_scan_id ON audit_logs(scan_id);
    """)

    conn.commit()

    # Migrate: add llm_endpoint_url column if it does not exist yet (idempotent)
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN llm_endpoint_url TEXT")
        conn.commit()
        logger.info("Migrated scans table: added llm_endpoint_url column.")
    except sqlite3.OperationalError:
        pass  # Column already exists

    conn.close()
    logger.info("Database schema initialized successfully.")

def log_audit(scan_id: str, event_type: str, details: str):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        "INSERT INTO audit_logs (scan_id, timestamp, event_type, details) VALUES (?, ?, ?, ?)",
        (scan_id, now, event_type, details)
    )
    conn.commit()
    conn.close()

def create_scan_record(scan_id: str, data: dict) -> dict:
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()

    cursor.execute("""
        INSERT INTO scans (
            id, target_url, llm_endpoint_url, in_scope, out_of_scope, authorization_confirmed,
            authorized_at, scan_mode, active_scan_confirmed,
            business_impact_multiplier, exposure_factor, status,
            progress_percent, current_step, error_message, summary_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        data["target_url"],
        data.get("llm_endpoint_url"),
        data["in_scope"],
        data.get("out_of_scope", ""),
        1 if data.get("authorization_confirmation") else 0,
        now,
        data.get("scan_mode", "passive"),
        1 if data.get("active_scan_confirmed") else 0,
        float(data.get("business_impact_multiplier", 1.0)),
        float(data.get("exposure_factor", 1.0)),
        "pending",
        0,
        "Initialized scan and verified authorization",
        None,
        json.dumps({}),
        now
    ))

    conn.commit()
    conn.close()

    log_audit(
        scan_id,
        "AUTHORIZATION_RECORDED",
        f"Authorization confirmed: target={data['target_url']}, llm_endpoint={data.get('llm_endpoint_url') or 'N/A'}, mode={data.get('scan_mode')}, multiplier={data.get('business_impact_multiplier')}"
    )

    return get_scan_record(scan_id)

def update_scan_status(scan_id: str, status: str, progress: int, current_step: str, error: Optional[str] = None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE scans
        SET status = ?, progress_percent = ?, current_step = ?, error_message = ?
        WHERE id = ?
    """, (status, progress, current_step, error, scan_id))
    conn.commit()
    conn.close()

    log_audit(scan_id, f"STATUS_{status.upper()}", f"Progress: {progress}% - {current_step}" + (f" - Error: {error}" if error else ""))

def complete_scan_record(scan_id: str, summary: dict):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        UPDATE scans
        SET status = 'completed', progress_percent = 100, current_step = 'Scan completed successfully',
            summary_json = ?, completed_at = ?
        WHERE id = ?
    """, (json.dumps(summary), now, scan_id))
    conn.commit()
    conn.close()

    log_audit(scan_id, "SCAN_COMPLETED", f"Summary: {json.dumps(summary)}")

def fail_scan_record(scan_id: str, error_message: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE scans
        SET status = 'failed', current_step = 'Scan failed', error_message = ?
        WHERE id = ?
    """, (error_message, scan_id))
    conn.commit()
    conn.close()

    log_audit(scan_id, "SCAN_FAILED", f"Error: {error_message}")

def get_scan_record(scan_id: str) -> Optional[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    if d.get("summary_json"):
        try:
            d["summary"] = json.loads(d["summary_json"])
        except Exception:
            d["summary"] = {}
    return d

def list_scan_records() -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        if d.get("summary_json"):
            try:
                d["summary"] = json.loads(d["summary_json"])
            except Exception:
                d["summary"] = {}
        result.append(d)
    return result

def insert_scan_findings(scan_id: str, findings: list[dict]):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()

    for f in findings:
        cursor.execute("""
            INSERT INTO findings (
                id, scan_id, finding_id, title, severity, cvss_score, cvss_vector,
                cwe_id, owasp_category, mitre_attack_technique, affected_url,
                description, request_evidence, response_evidence, ai_verdict,
                ai_reasoning, novel_pattern_flag, remediation, references_json,
                raw_zap_alert_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f.get("id"),
            scan_id,
            f.get("finding_id"),
            f.get("title"),
            f.get("severity"),
            float(f.get("cvss_score", 0.0)),
            f.get("cvss_vector", ""),
            f.get("cwe_id", ""),
            f.get("owasp_category", ""),
            f.get("mitre_attack_technique"),
            f.get("affected_url", ""),
            f.get("description", ""),
            f.get("evidence", {}).get("request", "") if isinstance(f.get("evidence"), dict) else "",
            f.get("evidence", {}).get("response", "") if isinstance(f.get("evidence"), dict) else "",
            f.get("ai_verdict", "confirmed"),
            f.get("ai_reasoning", ""),
            1 if f.get("novel_pattern_flag") else 0,
            f.get("remediation", ""),
            json.dumps(f.get("references", [])),
            json.dumps(f.get("raw_zap_alert", {})),
            now
        ))

    conn.commit()
    conn.close()
    log_audit(scan_id, "FINDINGS_SAVED", f"Saved {len(findings)} findings into database.")

def get_scan_findings(scan_id: str, include_false_positives: bool = True) -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    if include_false_positives:
        cursor.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY cvss_score DESC", (scan_id,))
    else:
        cursor.execute("SELECT * FROM findings WHERE scan_id = ? AND ai_verdict != 'false_positive' ORDER BY cvss_score DESC", (scan_id,))

    rows = cursor.fetchall()
    conn.close()

    findings = []
    for r in rows:
        d = dict(r)
        d["novel_pattern_flag"] = bool(d["novel_pattern_flag"])
        d["evidence"] = {
            "request": d.pop("request_evidence", ""),
            "response": d.pop("response_evidence", "")
        }
        try:
            d["references"] = json.loads(d.pop("references_json", "[]"))
        except Exception:
            d["references"] = []
        try:
            d["raw_zap_alert"] = json.loads(d.pop("raw_zap_alert_json", "{}"))
        except Exception:
            d["raw_zap_alert"] = {}
        findings.append(d)

    return findings

def get_scan_audit_logs(scan_id: str) -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs WHERE scan_id = ? ORDER BY id ASC", (scan_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
