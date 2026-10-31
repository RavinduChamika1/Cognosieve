import re
import ipaddress
from urllib.parse import urlparse
import fnmatch
from typing import Tuple, List

class ScopeRule:
    """Represents a parsed scope rule (wildcard domain, path prefix, CIDR, or exact host)."""
    def __init__(self, raw: str):
        self.raw = raw.strip()
        self.is_cidr = False
        self.ip_network = None
        self.is_path_only = False
        self.host_pattern = None
        self.path_pattern = None
        self.port = None

        self._parse()

    def _parse(self):
        rule = self.raw
        if not rule or rule.startswith("#"):
            return

        # Check for CIDR notation e.g., 192.168.1.0/24 or single IP
        try:
            if "/" in rule and not rule.startswith("http") and not rule.startswith("/"):
                # Possible CIDR
                self.ip_network = ipaddress.ip_network(rule, strict=False)
                self.is_cidr = True
                return
            elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", rule):
                self.ip_network = ipaddress.ip_network(f"{rule}/32", strict=False)
                self.is_cidr = True
                return
        except ValueError:
            pass

        # Check for path-only rule e.g. /api/* or /admin
        if rule.startswith("/"):
            self.is_path_only = True
            self.path_pattern = rule
            return

        # Handle full URL or host[:port][/path]
        if "://" not in rule:
            # Add scheme for urllib parsing
            parsed = urlparse(f"http://{rule}")
        else:
            parsed = urlparse(rule)

        host_part = parsed.hostname or ""
        self.port = parsed.port
        self.host_pattern = host_part.lower()
        self.path_pattern = parsed.path if parsed.path else None

    def matches(self, target_url: str) -> bool:
        if not self.raw or self.raw.startswith("#"):
            return False

        parsed_target = urlparse(target_url)
        target_host = (parsed_target.hostname or "").lower()
        target_path = parsed_target.path or "/"
        target_port = parsed_target.port

        # 1. CIDR Matching
        if self.is_cidr and self.ip_network:
            try:
                target_ip = ipaddress.ip_address(target_host)
                return target_ip in self.ip_network
            except ValueError:
                # Target host is a domain, not a raw IP
                return False

        # 2. Path-only Matching (applies to any host if path matches)
        if self.is_path_only and self.path_pattern:
            return fnmatch.fnmatch(target_path, self.path_pattern) or target_path.startswith(self.path_pattern.rstrip("*"))

        # 3. Host and Path Matching
        if self.host_pattern:
            # Check port if specified in rule
            if self.port is not None and target_port is not None:
                if self.port != target_port:
                    return False

            # Wildcard domain match e.g. *.example.com matches sub.example.com and example.com
            host_match = False
            if self.host_pattern.startswith("*."):
                root_domain = self.host_pattern[2:]
                host_match = target_host == root_domain or target_host.endswith(f".{root_domain}")
            elif "*" in self.host_pattern:
                host_match = fnmatch.fnmatch(target_host, self.host_pattern)
            else:
                host_match = target_host == self.host_pattern

            if not host_match:
                return False

            # If path pattern specified on host rule, check path
            if self.path_pattern and self.path_pattern != "/":
                return fnmatch.fnmatch(target_path, self.path_pattern) or target_path.startswith(self.path_pattern.rstrip("*"))

            return True

        return False

class ScopeManager:
    """Manages parsing of in-scope and out-of-scope rules with strict priority enforcement."""

    @staticmethod
    def parse_rules(rules_text: str) -> List[ScopeRule]:
        if not rules_text:
            return []
        lines = [line.strip() for line in rules_text.splitlines() if line.strip() and not line.strip().startswith("#")]
        return [ScopeRule(line) for line in lines]

    @classmethod
    def default_scope_for_url(cls, url: str) -> str:
        """
        Constructs an automatic allow-list rule when in-scope is not explicitly specified.
        Allows full URL attacks/scans against the specified target URL.
        """
        if not url:
            return ""
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        rules = [url.strip()]
        if host:
            rules.append(host)
            rules.append(f"*.{host}")
        if path and path != "/":
            rules.append(f"{path.rstrip('/')}/*")
            rules.append(f"{url.rstrip('/')}/*")
        return "\n".join(rules)

    @classmethod
    def evaluate_url(cls, url: str, in_scope_raw: str, out_of_scope_raw: str = "") -> Tuple[bool, str]:
        """
        Evaluates whether a URL is in scope.
        If in_scope_raw is omitted or empty, automatically defaults to the full target URL.
        Out-of-scope rules ALWAYS win over in-scope rules.
        """
        out_rules = cls.parse_rules(out_of_scope_raw)

        if not in_scope_raw or not in_scope_raw.strip():
            effective_in_scope = cls.default_scope_for_url(url)
            in_rules = cls.parse_rules(effective_in_scope)
            default_notice = " (auto-defaulted to full target URL)"
        else:
            in_rules = cls.parse_rules(in_scope_raw)
            default_notice = ""

        if not in_rules:
            return False, "No in-scope rules defined"

        # Check out-of-scope rules first (always wins)
        for rule in out_rules:
            if rule.matches(url):
                return False, f"URL matches out-of-scope rule: '{rule.raw}'"

        # Check in-scope rules
        for rule in in_rules:
            if rule.matches(url):
                return True, f"URL matches in-scope rule: '{rule.raw}'{default_notice}"

        return False, "URL does not match any in-scope rule"

    @classmethod
    def filter_urls(cls, urls: List[str], in_scope_raw: str, out_of_scope_raw: str = "") -> List[str]:
        """Filters a list of candidate URLs, keeping only those strictly in-scope."""
        allowed = []
        for u in urls:
            is_in, _ = cls.evaluate_url(u, in_scope_raw, out_of_scope_raw)
            if is_in:
                allowed.append(u)
        return allowed

    @classmethod
    def to_zap_regex(cls, rule_str: str) -> str:
        """Converts user-friendly rule (e.g. *.example.com, /api/*) into ZAP context regex."""
        rule = rule_str.strip()
        if not rule:
            return ""

        if rule.startswith("/"):
            # Path prefix
            escaped_path = re.escape(rule.rstrip("*"))
            return f"^https?://[^/]+{escaped_path}.*$"

        if "://" in rule:
            parsed = urlparse(rule)
            host = parsed.hostname or ""
            path = parsed.path or ""
        else:
            parsed = urlparse(f"http://{rule}")
            host = parsed.hostname or ""
            path = parsed.path or ""

        if host.startswith("*."):
            domain = re.escape(host[2:])
            host_regex = rf"(?:[a-zA-Z0-9-]+\.)*{domain}"
        elif "*" in host:
            host_regex = re.escape(host).replace(r"\*", r"[a-zA-Z0-9-]+")
        else:
            host_regex = re.escape(host)

        if path and path != "/":
            path_regex = re.escape(path.rstrip("*")) + ".*"
        else:
            path_regex = ".*"

        return f"^https?://{host_regex}(?::[0-9]+)?{path_regex}$"

    @classmethod
    def get_zap_context_regexes(cls, in_scope_raw: str, out_of_scope_raw: str = "") -> Tuple[List[str], List[str]]:
        """Returns include_regexes and exclude_regexes for ZAP context configuration."""
        includes = []
        for line in in_scope_raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                reg = cls.to_zap_regex(line)
                if reg:
                    includes.append(reg)

        excludes = []
        if out_of_scope_raw:
            for line in out_of_scope_raw.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    reg = cls.to_zap_regex(line)
                    if reg:
                        excludes.append(reg)

        return includes, excludes
