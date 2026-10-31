from pydantic import BaseModel, Field, field_validator
from typing import Optional, Literal
from enum import Enum

class ScanMode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"

class ScanCreateRequest(BaseModel):
    target_url: str = Field(..., description="Target base URL to assess, e.g. https://example.com")
    llm_endpoint_url: Optional[str] = Field(None, description="Optional: LLM-powered endpoint URL to red-team (chatbot API, AI feature endpoint). If provided, OWASP LLM Top 10 red-teaming runs before the web scan.")
    in_scope: Optional[str] = Field("", description="In-scope rules, one per line. If omitted, automatically defaults to the full target URL")
    out_of_scope: Optional[str] = Field("", description="Out-of-scope rules, one per line. Always wins over in-scope rules")
    authorization_confirmation: bool = Field(..., description="Confirmation that user owns the target or has written permission")
    scan_mode: ScanMode = Field(ScanMode.PASSIVE, description="passive or active scan mode")
    active_scan_confirmed: bool = Field(False, description="Second explicit confirmation required for active scanning")
    business_impact_multiplier: float = Field(1.0, ge=0.5, le=2.0, description="Business impact multiplier (0.5 to 2.0)")
    exposure_factor: float = Field(1.0, ge=0.1, le=1.0, description="Exposure factor: 1.0 (Internet-facing), 0.8 (Authenticated), 0.6 (Internal)")

    @field_validator("authorization_confirmation")
    @classmethod
    def validate_auth(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Authorization confirmation is required to proceed. You must own the target or have written permission.")
        return v

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v_clean = v.strip()
        if not (v_clean.startswith("http://") or v_clean.startswith("https://")):
            raise ValueError("target_url must begin with http:// or https://")
        return v_clean

    @field_validator("llm_endpoint_url")
    @classmethod
    def validate_llm_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not v.strip():
            return None
        v_clean = v.strip()
        if not (v_clean.startswith("http://") or v_clean.startswith("https://")):
            raise ValueError("llm_endpoint_url must begin with http:// or https://")
        return v_clean

class EvidenceSchema(BaseModel):
    request: str = Field("", description="Raw HTTP request snippet")
    response: str = Field("", description="Raw HTTP response snippet")

class FindingReportSchema(BaseModel):
    finding_id: str
    title: str
    severity: Literal["Critical", "High", "Medium", "Low"]
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    cvss_vector: str
    cwe_id: str
    owasp_category: str
    mitre_attack_technique: Optional[str] = None
    affected_url: str
    description: str
    evidence: EvidenceSchema
    ai_verdict: Literal["confirmed", "needs_review", "false_positive"]
    ai_reasoning: str
    novel_pattern_flag: bool = Field(False, description="True if Gemini flagged this as an unfamiliar instance of a known weakness class")
    remediation: str
    references: list[str] = Field(default_factory=list)

class ScanSummary(BaseModel):
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    false_positives: int = 0
    needs_review: int = 0
    novel_patterns: int = 0
    overall_risk_score: float = 0.0

class ScanResponse(BaseModel):
    id: str
    target_url: str
    llm_endpoint_url: Optional[str] = None
    in_scope: str
    out_of_scope: Optional[str] = ""
    authorization_confirmed: bool
    authorized_at: str
    scan_mode: str
    active_scan_confirmed: bool
    business_impact_multiplier: float
    exposure_factor: float
    status: str
    progress_percent: int
    current_step: Optional[str] = None
    error_message: Optional[str] = None
    summary: Optional[dict] = None
    created_at: str
    completed_at: Optional[str] = None
    findings: Optional[list[FindingReportSchema]] = None
