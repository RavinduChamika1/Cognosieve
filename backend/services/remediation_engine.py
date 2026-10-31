from typing import Dict, Any, Optional

class RemediationEngine:
    """
    Generates specific, actionable remediation guidance (exact HTTP headers,
    parameter validation logic, and code snippets) instead of generic advice.
    """

    SPECIFIC_REMEDIATIONS = {
        "CWE-1021": (
            "Add the following HTTP response headers on your reverse proxy or web server:\n\n"
            "1. Modern directive:\n"
            "   Content-Security-Policy: frame-ancestors 'self';\n\n"
            "2. Legacy fallback for older browsers:\n"
            "   X-Frame-Options: SAMEORIGIN\n\n"
            "Nginx configuration:\n"
            "   add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
            "   add_header Content-Security-Policy \"frame-ancestors 'self';\" always;"
        ),
        "CWE-693": (
            "Enforce strict browser defense headers across all HTTP responses:\n\n"
            "1. Prevent MIME-type sniffing:\n"
            "   X-Content-Type-Options: nosniff\n\n"
            "2. Restrict resource loading with Content Security Policy:\n"
            "   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';\n\n"
            "3. Referrer privacy policy:\n"
            "   Referrer-Policy: strict-origin-when-cross-origin\n\n"
            "FastAPI / Python middleware implementation:\n"
            "   @app.middleware(\"http\")\n"
            "   async def add_security_headers(request, call_next):\n"
            "       response = await call_next(request)\n"
            "       response.headers[\"X-Content-Type-Options\"] = \"nosniff\"\n"
            "       response.headers[\"Referrer-Policy\"] = \"strict-origin-when-cross-origin\"\n"
            "       return response"
        ),
        "CWE-319": (
            "Enforce HTTP Strict Transport Security (HSTS) with a minimum duration of 1 year:\n\n"
            "Header to add:\n"
            "   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\n"
            "Ensure port 80 redirects immediately with a 301 Permanent Redirect to HTTPS:\n"
            "   return 301 https://$host$request_uri;"
        ),
        "CWE-79": (
            "Apply contextual output encoding and contextual input validation:\n\n"
            "1. In HTML contexts: Encode characters `<, >, &, \", '` to their corresponding HTML entities.\n"
            "2. In JavaScript / JSON contexts: Use strict JSON serializers (`json.dumps` with proper escaping) rather than inline template interpolation.\n"
            "3. Modern React/Vue frameworks auto-escape by default — ensure dangerouslySetInnerHTML or v-html is NOT used on unsanitized inputs.\n"
            "4. Add defense-in-depth CSP header: Content-Security-Policy: default-src 'self'; script-src 'self';"
        ),
        "CWE-89": (
            "Use parameterized queries (prepared statements) or an ORM; never concatenate user input into SQL:\n\n"
            "Vulnerable:\n"
            "   cursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")\n\n"
            "Remediation (Parameterized):\n"
            "   cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n\n"
            "In SQLAlchemy / ORM:\n"
            "   db.query(User).filter(User.id == user_id).first()"
        ),
        "CWE-352": (
            "Implement synchronizer CSRF tokens and SameSite cookie attributes:\n\n"
            "1. Set session and auth cookies with SameSite=Lax or SameSite=Strict:\n"
            "   Set-Cookie: session_id=...; Secure; HttpOnly; SameSite=Lax\n\n"
            "2. For state-changing requests (POST, PUT, DELETE), validate an anti-CSRF token supplied in custom header `X-CSRF-Token` or form payload."
        ),
        "CWE-22": (
            "Sanitize file paths and verify the canonical path remains within the intended root directory:\n\n"
            "Python pattern:\n"
            "   import os\n"
            "   safe_base = os.path.abspath(\"/var/www/uploads\")\n"
            "   target_path = os.path.abspath(os.path.join(safe_base, user_input_filename))\n"
            "   if not target_path.startswith(safe_base):\n"
            "       raise PermissionError(\"Directory traversal attempt detected\")"
        ),
        "CWE-918": (
            "Constrain outbound network requests to an explicit domain allow-list and disable internal private IP addressing:\n\n"
            "1. Block requests to RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and link-local cloud metadata (169.254.169.254).\n"
            "2. Validate resolved IP addresses after DNS resolution before opening socket connections."
        ),
        "CWE-200": (
            "Disable server banner leakage and strip internal debug tokens:\n\n"
            "Nginx: server_tokens off;\n"
            "Apache: ServerTokens Prod; ServerSignature Off;\n"
            "Express.js: app.disable('x-powered-by');"
        ),
        "CWE-942": (
            "Restrict Access-Control-Allow-Origin header to trusted, explicit origin domains:\n\n"
            "Vulnerable: Access-Control-Allow-Origin: *\n"
            "Remediation: Validate request origin against an allow-list and return that specific origin:\n"
            "   Access-Control-Allow-Origin: https://trusted-partner.example.com\n"
            "   Vary: Origin"
        ),
        "CWE-614": (
            "Add the 'Secure' attribute to all sensitive session and authentication cookies:\n\n"
            "Set-Cookie: token=xyz; Path=/; Secure; HttpOnly; SameSite=Strict"
        ),
        "CWE-1004": (
            "Add the 'HttpOnly' flag to cookies containing session identifiers or JWTs to prevent JavaScript read access (mitigating XSS session hijacking):\n\n"
            "Set-Cookie: sessionid=xyz; Path=/; HttpOnly; Secure; SameSite=Lax"
        )
    }

    @classmethod
    def get_remediation(cls, cwe_id: str, alert_name: str = "", zap_solution: str = "") -> str:
        """Returns specific, actionable remediation guidance."""
        cwe_clean = (cwe_id or "").upper().strip()

        if cwe_clean in cls.SPECIFIC_REMEDIATIONS:
            return cls.SPECIFIC_REMEDIATIONS[cwe_clean]

        for cwe_key, guide in cls.SPECIFIC_REMEDIATIONS.items():
            if cwe_key in cwe_clean:
                return guide

        if zap_solution and len(zap_solution.strip()) > 20:
            return zap_solution.strip()

        return (
            "Implement strict input validation on all user-supplied data, enforce contextual output encoding, "
            "and configure defense-in-depth HTTP security headers (CSP, HSTS, X-Content-Type-Options) "
            "following the OWASP Secure Coding Practices Guide."
        )
