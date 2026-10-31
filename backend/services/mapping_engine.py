from typing import Dict, Any, Optional, List

class MappingEngine:
    """
    Maps findings to standardized CWE IDs, OWASP Top 10 categories,
    and MITRE ATT&CK technique IDs with reference links.
    """

    # Comprehensive CWE metadata dictionary
    CWE_DATABASE: Dict[str, Dict[str, Any]] = {
        "CWE-89": {
            "name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
            "owasp": "A03:2021-Injection",
            "mitre": "T1190",
            "mitre_name": "Exploit Public-Facing Application",
            "references": [
                "https://cwe.mitre.org/data/definitions/89.html",
                "https://owasp.org/Top10/A03_2021-Injection/",
                "https://attack.mitre.org/techniques/T1190/"
            ]
        },
        "CWE-79": {
            "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "owasp": "A03:2021-Injection",
            "mitre": "T1190",
            "mitre_name": "Exploit Public-Facing Application",
            "references": [
                "https://cwe.mitre.org/data/definitions/79.html",
                "https://owasp.org/www-community/attacks/xss/",
                "https://attack.mitre.org/techniques/T1190/"
            ]
        },
        "CWE-352": {
            "name": "Cross-Site Request Forgery (CSRF)",
            "owasp": "A01:2021-Broken Access Control",
            "mitre": "T1539",
            "mitre_name": "Steal Web Session Cookie",
            "references": [
                "https://cwe.mitre.org/data/definitions/352.html",
                "https://owasp.org/www-community/attacks/csrf"
            ]
        },
        "CWE-22": {
            "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            "owasp": "A01:2021-Broken Access Control",
            "mitre": "T1083",
            "mitre_name": "File and Directory Discovery",
            "references": [
                "https://cwe.mitre.org/data/definitions/22.html",
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
            ]
        },
        "CWE-918": {
            "name": "Server-Side Request Forgery (SSRF)",
            "owasp": "A10:2021-Server-Side Request Forgery (SSRF)",
            "mitre": "T1190",
            "mitre_name": "Exploit Public-Facing Application",
            "references": [
                "https://cwe.mitre.org/data/definitions/918.html",
                "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
            ]
        },
        "CWE-16": {
            "name": "Configuration",
            "owasp": "A05:2021-Security Misconfiguration",
            "mitre": "T1082",
            "mitre_name": "System Information Discovery",
            "references": [
                "https://cwe.mitre.org/data/definitions/16.html",
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
            ]
        },
        "CWE-693": {
            "name": "Protection Mechanism Failure (Missing Security Headers)",
            "owasp": "A05:2021-Security Misconfiguration",
            "mitre": "T1562",
            "mitre_name": "Impair Defenses",
            "references": [
                "https://cwe.mitre.org/data/definitions/693.html",
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
            ]
        },
        "CWE-1021": {
            "name": "Improper Restriction of Rendered UI Layers or Frames ('Clickjacking')",
            "owasp": "A05:2021-Security Misconfiguration",
            "mitre": "T1190",
            "mitre_name": "Exploit Public-Facing Application",
            "references": [
                "https://cwe.mitre.org/data/definitions/1021.html",
                "https://owasp.org/www-community/attacks/Clickjacking"
            ]
        },
        "CWE-200": {
            "name": "Exposure of Sensitive Information to an Unauthorized Actor",
            "owasp": "A01:2021-Broken Access Control",
            "mitre": "T1552",
            "mitre_name": "Unsecured Credentials",
            "references": [
                "https://cwe.mitre.org/data/definitions/200.html",
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
            ]
        },
        "CWE-319": {
            "name": "Cleartext Transmission of Sensitive Information",
            "owasp": "A02:2021-Cryptographic Failures",
            "mitre": "T1557",
            "mitre_name": "Adversary-in-the-Middle",
            "references": [
                "https://cwe.mitre.org/data/definitions/319.html",
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
            ]
        },
        "CWE-942": {
            "name": "Permissive Cross-origin Resource Sharing Policy",
            "owasp": "A05:2021-Security Misconfiguration",
            "mitre": "T1190",
            "mitre_name": "Exploit Public-Facing Application",
            "references": [
                "https://cwe.mitre.org/data/definitions/942.html",
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
            ]
        },
        "CWE-614": {
            "name": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
            "owasp": "A05:2021-Security Misconfiguration",
            "mitre": "T1539",
            "mitre_name": "Steal Web Session Cookie",
            "references": [
                "https://cwe.mitre.org/data/definitions/614.html",
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
            ]
        },
        "CWE-1004": {
            "name": "Sensitive Cookie Without 'HttpOnly' Flag",
            "owasp": "A05:2021-Security Misconfiguration",
            "mitre": "T1539",
            "mitre_name": "Steal Web Session Cookie",
            "references": [
                "https://cwe.mitre.org/data/definitions/1004.html",
                "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
            ]
        }
    }

    # Mapping of ZAP Plugin / Rule IDs to CWEs
    ZAP_PLUGIN_TO_CWE: Dict[str, str] = {
        "10020": "CWE-1021",  # Anti-clickjacking Header (X-Frame-Options)
        "10038": "CWE-693",   # Content Security Policy (CSP) Header Not Set
        "10035": "CWE-319",   # Strict-Transport-Security Header Not Set
        "10021": "CWE-693",   # X-Content-Type-Options Header Missing
        "10055": "CWE-693",   # CSP: Wildcard Directive
        "10098": "CWE-942",   # Cross-Domain Misconfiguration (CORS)
        "10054": "CWE-614",   # Cookie Without Secure Flag
        "10010": "CWE-1004",  # Cookie No HttpOnly Flag
        "10027": "CWE-200",   # Information Disclosure - Suspicious Comments
        "10037": "CWE-200",   # Server Leaks Version Information via "Server" HTTP Response Header
        "40012": "CWE-79",    # Reflected Cross Site Scripting
        "40014": "CWE-79",    # Persistent Cross Site Scripting
        "40018": "CWE-89",    # SQL Injection
        "40019": "CWE-89",    # SQL Injection - MySQL
        "40020": "CWE-89",    # SQL Injection - Hypersonic SQL
        "40021": "CWE-89",    # SQL Injection - Oracle
        "40022": "CWE-89",    # SQL Injection - PostgreSQL
        "40024": "CWE-89",    # SQL Injection - SQLite
        "40027": "CWE-352",   # Absence of Anti-CSRF Tokens
        "40028": "CWE-22",    # Path Traversal
        "40046": "CWE-918",   # Server Side Request Forgery
    }

    @classmethod
    def resolve_cwe(cls, zap_cwe_id: str, zap_plugin_id: str, alert_name: str) -> str:
        """Determines the canonical CWE ID from ZAP alert fields."""
        # Check explicit CWE ID from ZAP
        if zap_cwe_id and str(zap_cwe_id).strip() not in ("0", "-1", ""):
            cwe_str = str(zap_cwe_id).strip()
            if not cwe_str.upper().startswith("CWE-"):
                return f"CWE-{cwe_str}"
            return cwe_str.upper()

        # Check plugin ID map
        if zap_plugin_id and str(zap_plugin_id) in cls.ZAP_PLUGIN_TO_CWE:
            return cls.ZAP_PLUGIN_TO_CWE[str(zap_plugin_id)]

        # Keyword matching on alert title
        title_lower = alert_name.lower()
        if "sql injection" in title_lower:
            return "CWE-89"
        elif "cross site scripting" in title_lower or "xss" in title_lower:
            return "CWE-79"
        elif "csrf" in title_lower or "anti-csrf" in title_lower:
            return "CWE-352"
        elif "clickjacking" in title_lower or "x-frame-options" in title_lower:
            return "CWE-1021"
        elif "content security policy" in title_lower or "csp" in title_lower:
            return "CWE-693"
        elif "strict-transport-security" in title_lower or "hsts" in title_lower:
            return "CWE-319"
        elif "content-type-options" in title_lower:
            return "CWE-693"
        elif "path traversal" in title_lower or "directory traversal" in title_lower:
            return "CWE-22"
        elif "information disclosure" in title_lower or "leaks version" in title_lower:
            return "CWE-200"
        elif "cors" in title_lower or "cross-domain" in title_lower:
            return "CWE-942"

        return "CWE-16"  # Generic Configuration Weakness

    @classmethod
    def get_metadata(cls, cwe_id: str) -> Dict[str, Any]:
        """Returns OWASP category, MITRE ATT&CK technique, and reference links."""
        cwe_clean = (cwe_id or "").upper().strip()
        if cwe_clean in cls.CWE_DATABASE:
            return cls.CWE_DATABASE[cwe_clean]

        # Default fallback metadata
        return {
            "name": "Security Weakness",
            "owasp": "A05:2021-Security Misconfiguration",
            "mitre": "T1190",
            "mitre_name": "Exploit Public-Facing Application",
            "references": [
                f"https://cwe.mitre.org/data/definitions/{cwe_clean.replace('CWE-', '')}.html" if "CWE-" in cwe_clean else "https://owasp.org/Top10/",
                "https://attack.mitre.org/techniques/T1190/"
            ]
        }
