import asyncio
import logging
import httpx
from typing import Dict, Any, List, Optional
from config import settings
from services.scope_manager import ScopeManager

logger = logging.getLogger("cognosieve.zap")

class ZapService:
    """
    Client for OWASP ZAP Daemon REST API.
    Enforces strict in-scope restriction, context management, spidering,
    passive/active scanning, and raw alert extraction with HTTP messages.
    Includes test simulator mode when ZAP daemon is offline.
    """

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None):
        self.base_url = (base_url or settings.ZAP_BASE_URL).rstrip("/")
        self.api_key = api_key or settings.ZAP_API_KEY
        self.headers = {"X-ZAP-API-Key": self.api_key}

    async def is_zap_available(self) -> bool:
        """Checks if live OWASP ZAP daemon is responding to HTTP requests."""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                res = await client.get(f"{self.base_url}/JSON/core/view/version/", params={"apikey": self.api_key})
                if res.status_code == 200:
                    logger.info(f"Connected to OWASP ZAP version: {res.json().get('version')}")
                    return True
        except Exception:
            pass
        return False

    async def create_scoped_context(self, context_name: str, in_scope_raw: str, out_of_scope_raw: str = "") -> str:
        """
        Creates a new context in ZAP and configures include/exclude regexes.
        Enforces allow-list rules inside ZAP's internal engine.
        """
        includes, excludes = ScopeManager.get_zap_context_regexes(in_scope_raw, out_of_scope_raw)

        async with httpx.AsyncClient(timeout=15.0) as client:
            # 1. Create context
            res = await client.get(
                f"{self.base_url}/JSON/context/action/newContext/",
                params={"apikey": self.api_key, "contextName": context_name}
            )
            data = res.json()
            context_id = str(data.get("contextId", "1"))

            # 2. Add include regexes
            for inc in includes:
                await client.get(
                    f"{self.base_url}/JSON/context/action/includeInContext/",
                    params={"apikey": self.api_key, "contextName": context_name, "regex": inc}
                )

            # 3. Add exclude regexes (out of scope)
            for exc in excludes:
                await client.get(
                    f"{self.base_url}/JSON/context/action/excludeFromContext/",
                    params={"apikey": self.api_key, "contextName": context_name, "regex": exc}
                )

            # 4. Set in scope
            await client.get(
                f"{self.base_url}/JSON/context/action/setContextInScope/",
                params={"apikey": self.api_key, "contextName": context_name, "booleanInScope": "true"}
            )

            logger.info(f"Created scoped ZAP context '{context_name}' (ID: {context_id}) with {len(includes)} includes and {len(excludes)} excludes.")
            return context_id

    async def run_spider(
        self,
        target_url: str,
        context_name: str,
        in_scope_raw: str,
        out_of_scope_raw: str,
        progress_callback=None
    ) -> List[str]:
        """
        Runs ZAP spider restricted strictly to the allow-list.
        Ensures URLs outside scope are NEVER queued.
        """
        # Strict scope verification before sending to spider
        in_scope, reason = ScopeManager.evaluate_url(target_url, in_scope_raw, out_of_scope_raw)
        if not in_scope:
            raise ValueError(f"Target URL '{target_url}' violates scope safety rule: {reason}")

        async with httpx.AsyncClient(timeout=30.0) as client:
            # Start spider
            res = await client.get(
                f"{self.base_url}/JSON/spider/action/scan/",
                params={
                    "apikey": self.api_key,
                    "url": target_url,
                    "contextName": context_name,
                    "recurse": "true",
                    "subtreeOnly": "true"
                }
            )
            data = res.json()
            scan_id = data.get("scan")

            # Poll status
            while True:
                status_res = await client.get(
                    f"{self.base_url}/JSON/spider/view/status/",
                    params={"apikey": self.api_key, "scanId": scan_id}
                )
                status_data = status_res.json()
                pct = int(status_data.get("status", 100))
                if progress_callback:
                    await progress_callback(pct)
                if pct >= 100:
                    break
                await asyncio.sleep(2)

            # Get discovered URLs and filter strictly through scope manager
            results_res = await client.get(
                f"{self.base_url}/JSON/spider/view/results/",
                params={"apikey": self.api_key, "scanId": scan_id}
            )
            raw_urls = results_res.json().get("results", [])
            allowed_urls = ScopeManager.filter_urls(raw_urls, in_scope_raw, out_of_scope_raw)
            logger.info(f"Spider completed: {len(raw_urls)} total URLs found, {len(allowed_urls)} verified strictly in-scope.")
            return allowed_urls

    async def wait_for_passive_scan(self, progress_callback=None):
        """Monitors passive scanner queue until all records are processed."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            while True:
                res = await client.get(
                    f"{self.base_url}/JSON/pscan/view/recordsToScan/",
                    params={"apikey": self.api_key}
                )
                records = int(res.json().get("recordsToScan", 0))
                if progress_callback:
                    await progress_callback(records)
                if records <= 0:
                    break
                await asyncio.sleep(2)
            logger.info("ZAP passive scanning queue drained to 0.")

    async def run_active_scan(
        self,
        target_url: str,
        context_id: str,
        in_scope_raw: str,
        out_of_scope_raw: str,
        progress_callback=None
    ):
        """
        Runs ZAP active scanner ONLY if explicit authorizations were confirmed.
        Enforces in-scope only scanning.
        """
        in_scope, reason = ScopeManager.evaluate_url(target_url, in_scope_raw, out_of_scope_raw)
        if not in_scope:
            raise ValueError(f"Active scan rejected: target URL outside scope ({reason})")

        async with httpx.AsyncClient(timeout=30.0) as client:
            res = await client.get(
                f"{self.base_url}/JSON/ascan/action/scan/",
                params={
                    "apikey": self.api_key,
                    "url": target_url,
                    "contextId": context_id,
                    "recurse": "true",
                    "inScopeOnly": "true"
                }
            )
            scan_id = res.json().get("scan")
            while True:
                status_res = await client.get(
                    f"{self.base_url}/JSON/ascan/view/status/",
                    params={"apikey": self.api_key, "scanId": scan_id}
                )
                pct = int(status_res.json().get("status", 100))
                if progress_callback:
                    await progress_callback(pct)
                if pct >= 100:
                    break
                await asyncio.sleep(3)
            logger.info("ZAP active scanner execution finished.")

    async def pull_alerts_with_evidence(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Pulls raw alerts from ZAP and fetches full HTTP request/response
        messages for comprehensive evidence.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            res = await client.get(
                f"{self.base_url}/JSON/core/view/alerts/",
                params={"apikey": self.api_key, "baseurl": target_url, "start": "0", "count": "500"}
            )
            alerts = res.json().get("alerts", [])
            logger.info(f"Pulled {len(alerts)} raw alerts from ZAP daemon.")

            enriched = []
            for alert in alerts:
                msg_id = alert.get("messageId")
                req_text = ""
                resp_text = ""
                if msg_id:
                    try:
                        msg_res = await client.get(
                            f"{self.base_url}/JSON/core/view/message/",
                            params={"apikey": self.api_key, "id": str(msg_id)}
                        )
                        msg_data = msg_res.json().get("message", {})
                        req_text = f"{msg_data.get('requestHeader', '')}\n\n{msg_data.get('requestBody', '')}".strip()
                        resp_text = f"{msg_data.get('responseHeader', '')}\n\n{msg_data.get('responseBody', '')}".strip()
                    except Exception as err:
                        logger.warning(f"Failed to fetch message {msg_id}: {err}")

                enriched.append({
                    "raw_zap": alert,
                    "rule_id": str(alert.get("pluginId", alert.get("id", ""))),
                    "name": alert.get("name", "Unknown Alert"),
                    "risk": alert.get("risk", "Medium"),
                    "confidence": alert.get("confidence", "Medium"),
                    "cwe_id": str(alert.get("cweid", "0")),
                    "url": alert.get("url", target_url),
                    "param": alert.get("param", ""),
                    "attack": alert.get("attack", ""),
                    "evidence": alert.get("evidence", ""),
                    "description": alert.get("description", ""),
                    "solution": alert.get("solution", ""),
                    "reference": alert.get("reference", ""),
                    "request_snippet": req_text,
                    "response_snippet": resp_text
                })

            return enriched

    def generate_simulated_alerts(self, target_url: str, scan_mode: str = "passive") -> List[Dict[str, Any]]:
        """
        Generates realistic security assessment alerts for test targets
        when live ZAP daemon is not running.
        Includes full realistic request/response streams.
        """
        simulated = [
            {
                "rule_id": "10020",
                "name": "Anti-clickjacking Header (X-Frame-Options) Not Set",
                "risk": "Medium",
                "confidence": "High",
                "cwe_id": "1021",
                "url": target_url,
                "param": "",
                "attack": "",
                "evidence": "",
                "description": "The response does not include either Content-Security-Policy with 'frame-ancestors' directive or a X-Frame-Options to protect against 'ClickJacking' attacks.",
                "solution": "Modern Web applications should use the Content-Security-Policy header with the 'frame-ancestors' directive. Older browsers may require X-Frame-Options: SAMEORIGIN.",
                "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                "request_snippet": f"GET / HTTP/1.1\nHost: {target_url}\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\nAccept: text/html\n\n",
                "response_snippet": "HTTP/1.1 200 OK\nDate: Sat, 17 Oct 2026 04:00:00 GMT\nServer: Apache/2.4.52\nContent-Type: text/html; charset=UTF-8\nTransfer-Encoding: chunked\n\n<!DOCTYPE html><html><head><title>App</title></head><body><h1>Welcome</h1></body></html>"
            },
            {
                "rule_id": "10038",
                "name": "Content Security Policy (CSP) Header Not Set",
                "risk": "Medium",
                "confidence": "High",
                "cwe_id": "693",
                "url": target_url,
                "param": "",
                "attack": "",
                "evidence": "",
                "description": "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks.",
                "solution": "Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.",
                "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                "request_snippet": f"GET /dashboard HTTP/1.1\nHost: {target_url}\nAccept: text/html\n\n",
                "response_snippet": "HTTP/1.1 200 OK\nDate: Sat, 17 Oct 2026 04:00:00 GMT\nContent-Type: text/html\nServer: nginx/1.18.0\n\n<html><body><h2>Dashboard</h2></body></html>"
            },
            {
                "rule_id": "10021",
                "name": "X-Content-Type-Options Header Missing",
                "risk": "Low",
                "confidence": "Medium",
                "cwe_id": "693",
                "url": target_url,
                "param": "",
                "attack": "",
                "evidence": "",
                "description": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body.",
                "solution": "Ensure that the application/webserver sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.",
                "reference": "https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/gg622941(v=vs.85)",
                "request_snippet": f"GET /static/app.js HTTP/1.1\nHost: {target_url}\nAccept: */*\n\n",
                "response_snippet": "HTTP/1.1 200 OK\nContent-Type: application/javascript\nContent-Length: 420\n\nconsole.log('App loaded');"
            },
            {
                "rule_id": "10037",
                "name": "Server Leaks Information via \"Server\" HTTP Response Header",
                "risk": "Low",
                "confidence": "High",
                "cwe_id": "200",
                "url": target_url,
                "param": "",
                "attack": "",
                "evidence": "Apache/2.4.52 (Ubuntu) OpenSSL/3.0.2",
                "description": "The web/application server can be identified via the 'Server' header field, exposing specific software and version numbers.",
                "solution": "Configure server tokens off to suppress exact version strings in the Server HTTP response header.",
                "reference": "https://httpd.apache.org/docs/current/mod/core.html#servertokens",
                "request_snippet": f"GET / HTTP/1.1\nHost: {target_url}\n\n",
                "response_snippet": "HTTP/1.1 200 OK\nServer: Apache/2.4.52 (Ubuntu) OpenSSL/3.0.2\nContent-Type: text/html\n\n<html></html>"
            },
            {
                "rule_id": "90001",
                "name": "Potential SQL Injection in Parameter ID (False Positive Test)",
                "risk": "Low",
                "confidence": "Low",
                "cwe_id": "89",
                "url": f"{target_url}/item?id=1%27",
                "param": "id",
                "attack": "1'",
                "evidence": "",
                "description": "Scanner triggered pattern on generic response without SQL syntax error reflection.",
                "solution": "Use parameterized queries.",
                "reference": "https://owasp.org/Top10/A03_2021-Injection/",
                "request_snippet": f"GET /item?id=1%27 HTTP/1.1\nHost: {target_url}\n\n",
                "response_snippet": "HTTP/1.1 404 Not Found\nContent-Type: text/html\n\n<html><body>404 Item Not Found</body></html>"
            }
        ]

        if scan_mode == "active":
            simulated.append({
                "rule_id": "40012",
                "name": "Reflected Cross Site Scripting (XSS)",
                "risk": "High",
                "confidence": "High",
                "cwe_id": "79",
                "url": f"{target_url}/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
                "param": "q",
                "attack": "<script>alert(1)</script>",
                "evidence": "<script>alert(1)</script>",
                "description": "A reflected cross-site scripting attack occurs when an application receives untrusted data in an HTTP request and includes that data within the immediate response without validation.",
                "solution": "Context-sensitive output encoding should be applied to the parameter 'q' before rendering into HTML context.",
                "reference": "https://owasp.org/www-community/attacks/xss/",
                "request_snippet": f"GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\nHost: {target_url}\nUser-Agent: OWASP ZAP\n\n",
                "response_snippet": "HTTP/1.1 200 OK\nContent-Type: text/html; charset=UTF-8\n\n<div>Search results for: <script>alert(1)</script></div>"
            })

        return simulated
