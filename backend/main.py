import asyncio
import os
import uuid
from pathlib import Path
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from config import settings
from database import (
    init_db, create_scan_record, get_scan_record, list_scan_records,
    get_scan_findings, get_scan_audit_logs
)
from schemas import ScanCreateRequest, ScanResponse, FindingReportSchema
from services.scope_manager import ScopeManager
from services.scan_orchestrator import ScanOrchestrator
from services.zap_service import ZapService
from services.gemini_service import GeminiService

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    init_db()
    yield

app = FastAPI(
    title="CognoSieve API",
    description="Automated Vulnerability Assessment with OWASP ZAP & Gemini AI Triage + LLM Red-Teaming",
    version="2.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = ScanOrchestrator()
zap_client = ZapService()
gemini_client = GeminiService()

@app.get("/api/health")
async def health_check():
    zap_online = await zap_client.is_zap_available()
    gemini_configured = gemini_client.is_live()
    return {
        "status": "healthy",
        "service": "CognoSieve",
        "zap_daemon_online": zap_online,
        "zap_base_url": settings.ZAP_BASE_URL,
        "gemini_api_configured": gemini_configured,
        "gemini_model": settings.GEMINI_MODEL,
        "storage_path": settings.DATABASE_PATH
    }

@app.post("/api/validate-scope")
async def validate_scope(
    target_url: str = Query(..., description="URL to check"),
    in_scope: str = Query(..., description="In-scope rules"),
    out_of_scope: str = Query("", description="Out-of-scope rules")
):
    """Real-time validation helper for frontend form."""
    is_in, reason = ScopeManager.evaluate_url(target_url, in_scope, out_of_scope)
    return {
        "is_in_scope": is_in,
        "reason": reason
    }

@app.post("/api/scans", response_model=ScanResponse, status_code=201)
async def start_scan(request: ScanCreateRequest, background_tasks: BackgroundTasks):
    """
    Submits a new vulnerability scan.
    Strictly verifies in-scope/out-of-scope rules and explicit authorizations.
    If in-scope is omitted, automatically defaults directly to full target URL.
    """
    # 1. Non-negotiable authorization check
    if not request.authorization_confirmation:
        raise HTTPException(
            status_code=403,
            detail="Authorization rejected: You must explicitly confirm ownership or written authorization to test this target."
        )

    # 2. Auto-default scope to target URL if not specified
    if not request.in_scope or not request.in_scope.strip():
        request.in_scope = ScopeManager.default_scope_for_url(request.target_url)

    # 3. Scope Safety Validation
    is_in_scope, reason = ScopeManager.evaluate_url(request.target_url, request.in_scope, request.out_of_scope or "")
    if not is_in_scope:
        raise HTTPException(
            status_code=400,
            detail=f"Target URL is not authorized by the defined scope: {reason}"
        )

    # 4. Active Scan Double Confirmation Check
    if request.scan_mode == "active" and not request.active_scan_confirmed:
        raise HTTPException(
            status_code=400,
            detail="Active scanning requires second explicit confirmation in the UI before execution."
        )

    # 4. Create Scan Record in DB (Audit trail)
    scan_id = str(uuid.uuid4())
    scan_data = request.model_dump()
    scan_rec = create_scan_record(scan_id, scan_data)

    # 5. Launch background orchestration
    background_tasks.add_task(orchestrator.execute_scan, scan_id, scan_data)

    return scan_rec

@app.get("/api/scans", response_model=List[ScanResponse])
async def list_scans():
    """Lists all vulnerability assessment scans."""
    return list_scan_records()

@app.get("/api/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, include_fps: bool = True):
    """Fetches scan details, progress, and triaged findings."""
    scan = get_scan_record(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    findings = get_scan_findings(scan_id, include_false_positives=include_fps)
    scan["findings"] = findings
    return scan

@app.get("/api/scans/{scan_id}/audit")
async def get_scan_audit(scan_id: str):
    """Returns the immutable audit trail for the scan."""
    logs = get_scan_audit_logs(scan_id)
    return {"scan_id": scan_id, "logs": logs}

@app.get("/api/scans/{scan_id}/report/html")
async def download_html_report(scan_id: str):
    """Returns standalone styled HTML report."""
    reports_dir = Path(settings.REPORTS_DIR)
    html_file = reports_dir / f"cognosieve_report_{scan_id}.html"

    if not html_file.exists():
        scan = get_scan_record(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")
        findings = get_scan_findings(scan_id, include_false_positives=True)
        from services.report_service import ReportService
        content = ReportService.generate_html_report(scan, findings)
        return HTMLResponse(content=content)

    return FileResponse(
        path=str(html_file),
        media_type="text/html",
        filename=f"cognosieve_{scan_id[:8]}_report.html"
    )

@app.get("/api/scans/{scan_id}/report/pdf")
@app.get("/api/scans/{scan_id}/export/pdf")
async def download_pdf_report(scan_id: str):
    """Returns downloadable PDF vulnerability report."""
    reports_dir = Path(settings.REPORTS_DIR)
    pdf_file = reports_dir / f"cognosieve_report_{scan_id}.pdf"

    if not pdf_file.exists():
        scan = get_scan_record(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")
        findings = get_scan_findings(scan_id, include_false_positives=True)
        from services.report_service import ReportService
        ReportService.generate_pdf_report(scan, findings, str(pdf_file))

    return FileResponse(
        path=str(pdf_file),
        media_type="application/pdf",
        filename=f"cognosieve_{scan_id[:8]}_report.pdf",
        content_disposition_type="attachment"
    )
