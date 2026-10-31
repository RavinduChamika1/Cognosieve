import math
from typing import Tuple, Dict, Any, Optional

class ScoringEngine:
    """
    Computes technical CVSS v3.1 base scores, applies business impact multipliers
    and exposure factors, and maps scores into standardized severity bands.
    """

    # Baseline CVSS scores for common vulnerability types
    DEFAULT_BASE_SCORES = {
        "CWE-89": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # SQLi
        "CWE-79": (7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),      # XSS
        "CWE-352": (8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"),     # CSRF
        "CWE-22": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),      # Path Traversal
        "CWE-78": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # Command Injection
        "CWE-94": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),      # Code Injection
        "CWE-918": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),     # SSRF
        "CWE-611": (8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),     # XXE
        "CWE-16": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),      # Misconfiguration
        "CWE-200": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),     # Information Disclosure
        "CWE-693": (5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"),     # Missing Security Headers
        "CWE-1021": (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),    # Clickjacking / X-Frame-Options
        "CWE-319": (7.4, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),     # Cleartext Transmission
        "CWE-384": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),     # Session Fixation
        "CWE-287": (8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),     # Improper Authentication
        "CWE-862": (7.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),     # Missing Authorization
        "CWE-942": (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),     # Permissive CORS
    }

    # Fallback scores based on ZAP Risk Level
    ZAP_RISK_FALLBACK = {
        "High": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
        "Medium": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
        "Low": (3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
        "Informational": (1.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    }

    @classmethod
    def get_base_score_and_vector(cls, cwe_id: str, zap_risk: str = "Medium") -> Tuple[float, str]:
        """Resolves base CVSS v3.1 score and vector by CWE or ZAP risk."""
        cwe_clean = (cwe_id or "").upper().strip()
        if cwe_clean in cls.DEFAULT_BASE_SCORES:
            return cls.DEFAULT_BASE_SCORES[cwe_clean]
        
        # Try finding prefix match e.g. CWE-79 in CWE-79: Cross-site Scripting
        for cwe_key, val in cls.DEFAULT_BASE_SCORES.items():
            if cwe_key in cwe_clean:
                return val

        risk_clean = zap_risk.capitalize()
        return cls.ZAP_RISK_FALLBACK.get(risk_clean, (5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"))

    @classmethod
    def calculate_adjusted_score(
        cls,
        base_score: float,
        business_impact_multiplier: float = 1.0,
        exposure_factor: float = 1.0
    ) -> float:
        """
        Calculates adjusted CVSS score:
        Adjusted = min(10.0, max(0.1, round(base_score * multiplier * exposure, 1)))
        """
        # Constrain multipliers to sane bounds
        mult = max(0.5, min(2.0, float(business_impact_multiplier)))
        exp = max(0.1, min(1.0, float(exposure_factor)))

        raw = base_score * mult * exp
        adjusted = round(raw, 1)
        return min(10.0, max(0.1, adjusted))

    @classmethod
    def map_score_to_severity(cls, score: float) -> str:
        """
        Maps CVSS score to standard vulnerability severity bands:
        - Critical: 9.0 - 10.0
        - High: 7.0 - 8.9
        - Medium: 4.0 - 6.9
        - Low: 0.1 - 3.9
        """
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        else:
            return "Low"

    @classmethod
    def score_finding(
        cls,
        cwe_id: str,
        zap_risk: str,
        business_impact_multiplier: float = 1.0,
        exposure_factor: float = 1.0
    ) -> Dict[str, Any]:
        """Calculates final score, vector, and severity band for a finding."""
        base_score, vector = cls.get_base_score_and_vector(cwe_id, zap_risk)
        final_score = cls.calculate_adjusted_score(base_score, business_impact_multiplier, exposure_factor)
        severity = cls.map_score_to_severity(final_score)

        return {
            "cvss_base_score": base_score,
            "cvss_score": final_score,
            "cvss_vector": vector,
            "severity": severity,
            "business_impact_multiplier": business_impact_multiplier,
            "exposure_factor": exposure_factor
        }

    @classmethod
    def compute_overall_risk(cls, scored_findings: list[dict]) -> float:
        """Calculates aggregate risk score on a 0-10 scale based on confirmed findings."""
        confirmed = [f for f in scored_findings if f.get("ai_verdict") != "false_positive"]
        if not confirmed:
            return 0.0

        scores = [f.get("cvss_score", 0.0) for f in confirmed]
        # Highest finding takes 60% weight, average of remaining takes 40%
        highest = max(scores)
        if len(scores) > 1:
            avg_others = sum(scores) / len(scores)
            combined = (0.65 * highest) + (0.35 * avg_others)
        else:
            combined = highest

        return min(10.0, round(combined, 1))

    @classmethod
    def score_llm_finding(
        cls,
        owasp_llm_key: str,
        business_impact_multiplier: float = 1.0,
        exposure_factor: float = 1.0,
    ) -> Dict[str, Any]:
        """
        Scores an OWASP LLM Top 10 finding using the likelihood × impact weight table
        defined in services.llm_redteam.OWASP_LLM_SEVERITY_WEIGHTS.

        This is the scoring path for LLM red-team findings which have no CVSS vector
        (there is no CVE for 'the chatbot leaked its system prompt').
        The resulting score uses the same 0-10 scale and severity bands as score_finding(),
        so both ZAP and LLM findings feed into the same compute_overall_risk() aggregate.
        """
        try:
            from services.llm_redteam import OWASP_LLM_SEVERITY_WEIGHTS
            entry = OWASP_LLM_SEVERITY_WEIGHTS.get(
                owasp_llm_key.upper(), OWASP_LLM_SEVERITY_WEIGHTS["LLM01"]
            )
            base_score = entry["base_score"]
            vector = entry["cvss_vector"]
        except Exception:
            base_score = 5.0
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"

        final_score = cls.calculate_adjusted_score(base_score, business_impact_multiplier, exposure_factor)
        severity = cls.map_score_to_severity(final_score)

        return {
            "cvss_base_score": base_score,
            "cvss_score": final_score,
            "cvss_vector": vector,
            "severity": severity,
            "business_impact_multiplier": business_impact_multiplier,
            "exposure_factor": exposure_factor,
        }
