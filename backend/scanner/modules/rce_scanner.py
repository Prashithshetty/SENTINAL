



import re
import json
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, quote
from html.parser import HTMLParser
from dataclasses import dataclass, field

import httpx

from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)


@dataclass
class FormData:
    """Represents an HTML form with its fields and attributes."""
    action: str
    method: str = "GET"
    fields: Dict[str, str] = field(default_factory=dict)
    enctype: str = "application/x-www-form-urlencoded"


class FormParser(HTMLParser):
    """Robust HTML form parser using Python's built-in html.parser."""
    
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.in_form = False
        self.in_select = False
        self.in_textarea = False
        self.current_field_name = None
        
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        if tag == "form":
            self.in_form = True
            self.current_form = FormData(
                action=attrs_dict.get("action", ""),
                method=attrs_dict.get("method", "GET").upper(),
                enctype=attrs_dict.get("enctype", "application/x-www-form-urlencoded")
            )
            
        elif self.in_form:
            if tag == "input":
                name = attrs_dict.get("name")
                if name:
                    value = attrs_dict.get("value", "")
                    input_type = attrs_dict.get("type", "text")
                    # Skip submit buttons and hidden CSRF tokens (but include other hidden fields)
                    if input_type not in ["submit", "button", "image"]:
                        self.current_form.fields[name] = value
                        
            elif tag == "select":
                self.in_select = True
                self.current_field_name = attrs_dict.get("name")
                
            elif tag == "textarea":
                self.in_textarea = True
                self.current_field_name = attrs_dict.get("name")
                if self.current_field_name:
                    self.current_form.fields[self.current_field_name] = ""
                    
            elif tag == "option" and self.in_select:
                # Use first option as default value for select
                if self.current_field_name and self.current_field_name not in self.current_form.fields:
                    value = attrs_dict.get("value", "")
                    self.current_form.fields[self.current_field_name] = value
    
    def handle_endtag(self, tag):
        if tag == "form" and self.in_form:
            if self.current_form:
                self.forms.append(self.current_form)
            self.in_form = False
            self.current_form = None
        elif tag == "select":
            self.in_select = False
            self.current_field_name = None
        elif tag == "textarea":
            self.in_textarea = False
            self.current_field_name = None
    
    def handle_data(self, data):
        if self.in_textarea and self.current_field_name:
            self.current_form.fields[self.current_field_name] = data.strip()


class RCEScanner(BaseScannerModule):
    """Enhanced Remote Code Execution vector scanner with improved robustness and coverage."""

    # Constants for vulnerability templates
    SSTI_VULN_TEMPLATE = {
        "remediation": (
            "Do not render untrusted input in templates. Use context separation and auto-escaping. "
            "Avoid dynamic template evaluation of user input. Implement strict input validation. "
            "Use a safe template engine configuration and disable dangerous features."
        ),
        "references": [
            "https://portswigger.net/web-security/server-side-template-injection",
            "https://owasp.org/www-community/attacks/Server-Side_Template_Injection",
            "https://cwe.mitre.org/data/definitions/94.html",
            "https://cwe.mitre.org/data/definitions/917.html",
        ],
        "cwe_ids": ["CWE-94", "CWE-917"],
    }
    
    DEBUG_ENDPOINT_TEMPLATE = {
        "remediation": (
            "Disable and restrict debug/console endpoints in production. "
            "Ensure they require strong authentication and are not publicly accessible. "
            "Remove or protect development tools before deployment."
        ),
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
        ],
        "cwe_ids": ["CWE-215", "CWE-489"],
    }

    def __init__(self):
        super().__init__()
        self.name = "RCEScanner"
        self.description = "Enhanced RCE vector scanner with improved robustness and coverage"
        self.scan_type = ScanType.ACTIVE

        # Enhanced SSTI/EL payloads with better isolation
        self.ssti_payloads: List[Tuple[str, str, str]] = [
            # Format: (type, payload, expected_marker_if_eval)
            # Using markers to isolate payloads from original values
            ("jinja2", "test_start{{7*7}}test_end", "test_start49test_end"),
            ("twig", "test_start{{ 7*7 }}test_end", "test_start49test_end"),
            ("erb", "test_start<%= 7*7 %>test_end", "test_start49test_end"),
            ("ejs", "test_start<%= 7*7 %>test_end", "test_start49test_end"),
            ("handlebars", "test_start{{#with 7}}{{this}}{{/with}}test_end", "test_start7test_end"),
            ("mustache", "test_start{{#7}}{{.}}{{/7}}test_end", "test_start7test_end"),
            ("freemarker", "test_start${7*7}test_end", "test_start49test_end"),
            ("thymeleaf", "test_start[[${7*7}]]test_end", "test_start49test_end"),
            ("spel", "test_start#{7*7}test_end", "test_start49test_end"),
            ("ognl", "test_start%{7*7}test_end", "test_start49test_end"),
            ("velocity", "test_start#set($x=7*7)${x}test_end", "test_start49test_end"),
            # Simple reflection tests (low confidence)
            ("reflection", "SENTINEL${{RCE}}", "SENTINEL${{RCE}}"),
            ("reflection2", "{{SENTINEL}}", "{{SENTINEL}}"),
        ]

        # Extended template/EL engine error signatures
        self.engine_error_signatures = [
            # Python/Jinja2
            "jinja2.exceptions", "UndefinedError", "TemplateSyntaxError", "Jinja2",
            "jinja2.runtime", "jinja2.environment",
            # PHP/Twig/Smarty
            "Twig\\Error", "RuntimeException", "SmartyCompilerException", "Twig_Error",
            "Twig\\Runtime", "Smarty_Internal",
            # Java/Thymeleaf/Freemarker/SpEL/OGNL
            "org.thymeleaf", "thymeleaf", "freemarker.core", "freemarker.template",
            "org.springframework.expression", "SpEL", "ognl.OgnlException", "ognl",
            "velocity.exception", "org.apache.velocity",
            # Ruby ERB
            "ActionView::Template::Error", "ERB::Util", "SyntaxError",
            # Node/EJS/Handlebars/Mustache
            "ejs:", "EJS:", "Handlebars", "Mustache", "TypeError",
            # .NET Razor
            "System.Web.Razor", "RazorEngine",
            # Generic template hints
            "Template engine", "template rendering error", "template error",
            "TemplateException", "ParseException", "CompileException",
        ]

        # Extended debug/eval endpoints
        self.debug_endpoints = [
            "/debug", "/console", "/_console", "/_profiler", "/rails/info", 
            "/phpinfo", "/phpinfo.php", "/_debugbar", "/debug.php",
            "/actuator/env", "/actuator/beans", "/actuator", "/actuator/health",
            "/_debug_", "/test", "/eval", "/execute", "/shell",
            "/admin/console", "/system/console", "/web-console",
            "/.env", "/config", "/settings", "/api/debug",
        ]

        # Extended parameter names for testing
        self.probe_param_names = [
            "q", "search", "s", "query", "keyword",
            "name", "title", "message", "comment", "text",
            "template", "tpl", "view", "page", "file",
            "format", "lang", "locale", "language",
            "code", "eval", "expression", "expr", "formula",
            "render", "display", "output",
            "path", "content", "data", "value", "input",
            "filter", "sort", "order", "field",
        ]
        
        # Common headers to test for SSTI
        self.test_headers = [
            "User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP",
            "X-Original-URL", "X-Rewrite-URL", "X-Custom-Header",
            "Accept-Language", "Cookie",
        ]

    def validate_target(self, target: str) -> bool:
        """Validate if target is suitable for RCE testing (URL required)."""
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        try:
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False

    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform enhanced RCE vector scan."""
        started_at = datetime.utcnow()
        vulnerabilities: List[Vulnerability] = []
        errors: List[str] = []
        warnings: List[str] = []
        info: Dict[str, Any] = {
            "tested_parameters": [],
            "tested_headers": [],
            "vulnerable_parameters": [],
            "vulnerable_headers": [],
            "rce_types_found": [],
            "payloads_successful": [],
            "debug_endpoints_found": [],
            "engines_detected": [],
        }
        statistics: Dict[str, Any] = {
            "urls_tested": 0,
            "parameters_tested": 0,
            "headers_tested": 0,
            "payloads_tested": 0,
            "vulnerabilities_found": 0,
            "high_confidence": 0,
            "medium_confidence": 0,
            "low_confidence": 0,
        }

        try:
            # Normalize URL
            target_url = config.target
            if not target_url.startswith(("http://", "https://")):
                target_url = f"https://{target_url}"

            # Read custom params
            force_passive = bool(config.custom_params.get("rce_force_passive", False))
            max_forms = int(config.custom_params.get("rce_max_forms", 3))
            max_params_per_surface = int(config.custom_params.get("rce_max_params_per_surface", 10))
            test_json = bool(config.custom_params.get("rce_test_json", True))
            test_headers = bool(config.custom_params.get("rce_test_headers", True))

            # Get baseline response
            baseline = await self._get_baseline_response(target_url)
            
            # Check if baseline already contains error signatures
            baseline_has_errors = self._check_baseline_for_errors(baseline)
            if baseline_has_errors:
                warnings.append("Baseline response contains template error signatures - adjusting confidence levels")

            # Probe debug endpoints
            debug_vulns = await self._probe_debug_endpoints(target_url, config)
            vulnerabilities.extend(debug_vulns)
            for v in debug_vulns:
                if "endpoint" in v.evidence:
                    info["debug_endpoints_found"].append(v.evidence["endpoint"])

            # Passive fingerprinting
            passive_vulns = await self._passive_fingerprints(target_url, config, baseline_has_errors)
            vulnerabilities.extend(passive_vulns)

            # Active tests
            if not force_passive and config.scan_type != ScanType.PASSIVE:
                # URL parameter testing
                param_results = await self._test_url_parameters(
                    target_url, baseline, config, max_params_per_surface, baseline_has_errors
                )
                vulnerabilities.extend(param_results["vulnerabilities"])
                info["tested_parameters"].extend(param_results["tested_params"])
                statistics["parameters_tested"] += len(param_results["tested_params"])
                statistics["payloads_tested"] += param_results["payloads_tested"]

                # Header injection testing
                if test_headers:
                    header_results = await self._test_headers(
                        target_url, baseline, config, baseline_has_errors
                    )
                    vulnerabilities.extend(header_results["vulnerabilities"])
                    info["tested_headers"].extend(header_results["tested_headers"])
                    statistics["headers_tested"] += len(header_results["tested_headers"])
                    statistics["payloads_tested"] += header_results["payloads_tested"]

                # Form testing with robust parser
                form_results = await self._test_forms_enhanced(
                    target_url, config, max_forms, baseline_has_errors
                )
                vulnerabilities.extend(form_results["vulnerabilities"])
                info["tested_parameters"].extend(form_results["tested_fields"])
                statistics["parameters_tested"] += len(form_results["tested_fields"])
                statistics["payloads_tested"] += form_results["payloads_tested"]

                # POST parameter testing (form-encoded and JSON)
                post_results = await self._test_post_parameters_enhanced(
                    target_url, config, max_params_per_surface, test_json, baseline_has_errors
                )
                vulnerabilities.extend(post_results["vulnerabilities"])
                info["tested_parameters"].extend(post_results["tested_params"])
                statistics["parameters_tested"] += len(post_results["tested_params"])
                statistics["payloads_tested"] += post_results["payloads_tested"]

            # Collect vulnerability metadata
            for vuln in vulnerabilities:
                ev = vuln.evidence or {}
                if "parameter" in ev:
                    info["vulnerable_parameters"].append(ev["parameter"])
                if "header" in ev:
                    info["vulnerable_headers"].append(ev["header"])
                if "engine_guess" in ev and ev["engine_guess"]:
                    info["engines_detected"].append(ev["engine_guess"])

            # Categorize RCE types found
            rce_types = set()
            for vuln in vulnerabilities:
                name_lower = vuln.name.lower()
                if "ssti" in name_lower:
                    rce_types.add("SSTI")
                if any(x in name_lower for x in ["el", "spel", "ognl"]):
                    rce_types.add("Expression Language")
                if any(x in name_lower for x in ["debug", "console", "phpinfo"]):
                    rce_types.add("Debug Endpoint")
                if "template" in name_lower and "error" in name_lower:
                    rce_types.add("Template Engine Error")
            info["rce_types_found"] = list(rce_types)
            info["engines_detected"] = list(set(info["engines_detected"]))

            # Statistics
            statistics["vulnerabilities_found"] = len(vulnerabilities)
            statistics["urls_tested"] = 1

            # Confidence tallies
            for v in vulnerabilities:
                if v.confidence >= 0.85:
                    statistics["high_confidence"] += 1
                    if v.evidence.get("payload"):
                        info["payloads_successful"].append(v.evidence["payload"])
                elif v.confidence >= 0.6:
                    statistics["medium_confidence"] += 1
                else:
                    statistics["low_confidence"] += 1

        except Exception as e:
            errors.append(f"RCE scan failed: {str(e)}")

        completed_at = datetime.utcnow()
        return ScanResult(
            module_name=self.name,
            success=len(errors) == 0,
            started_at=started_at,
            completed_at=completed_at,
            vulnerabilities=vulnerabilities,
            errors=errors,
            warnings=warnings,
            info=info,
            statistics=statistics,
        )

    async def _get_baseline_response(self, url: str) -> Dict[str, Any]:
        """Get baseline response with encoding check."""
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
                start = time.time()
                resp = await client.get(url)
                elapsed_ms = (time.time() - start) * 1000.0
                
                # Check if response is text-based
                content_type = resp.headers.get("content-type", "").lower()
                is_text = any(t in content_type for t in ["text", "html", "xml", "json", "javascript"])
                
                return {
                    "status_code": resp.status_code,
                    "content_length": len(resp.content),
                    "response_time_ms": elapsed_ms,
                    "headers": dict(resp.headers),
                    "content_type": content_type,
                    "is_text": is_text,
                    "text_sample": resp.text[:500] if is_text and resp.text else "",
                }
        except Exception as e:
            return {
                "error": str(e),
                "status_code": 0,
                "content_length": 0,
                "response_time_ms": 0,
                "is_text": False
            }

    def _check_baseline_for_errors(self, baseline: Dict[str, Any]) -> bool:
        """Check if baseline already contains error signatures."""
        if not baseline.get("is_text") or not baseline.get("text_sample"):
            return False
        
        text_lower = baseline["text_sample"].lower()
        for sig in self.engine_error_signatures:
            if sig.lower() in text_lower:
                return True
        return False

    async def _passive_fingerprints(self, url: str, config: ScanConfig, 
                                   baseline_has_errors: bool) -> List[Vulnerability]:
        """Passive detection with baseline awareness."""
        vulns: List[Vulnerability] = []
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
                resp = await client.get(url)
                
                if not resp.text:
                    return vulns
                    
                text_lower = resp.text.lower()
                matched_signatures = []
                
                for sig in self.engine_error_signatures:
                    if sig.lower() in text_lower:
                        matched_signatures.append(sig)
                
                if matched_signatures:
                    # Adjust confidence if baseline already had errors
                    confidence = 0.5 if baseline_has_errors else 0.7
                    
                    vulns.append(
                        Vulnerability(
                            module=self.name,
                            name="Template Engine Error Fingerprints Detected",
                            description=(
                                "Response contains template engine error signatures indicating potential code evaluation surface. "
                                + ("Note: These signatures appear in the baseline response as well." if baseline_has_errors else "")
                            ),
                            severity=SeverityLevel.MEDIUM,
                            confidence=confidence,
                            affected_urls=[url],
                            evidence={
                                "indicators": matched_signatures[:10],
                                "response_snippet": resp.text[:500],
                                "baseline_has_errors": baseline_has_errors,
                            },
                            **self.SSTI_VULN_TEMPLATE
                        )
                    )
        except Exception:
            pass
        return vulns

    async def _passive_fingerprints_old(self, url: str, config: ScanConfig) -> List[Vulnerability]:
        """Passive detection: engine error banners and stack traces."""
        vulns: List[Vulnerability] = []
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
                resp = await client.get(url)
                text_lower = resp.text.lower() if resp.text else ""

                matched_signatures = []
                for sig in self.engine_error_signatures:
                    if sig.lower() in text_lower:
                        matched_signatures.append(sig)
                        # Report once with multiple indicators
                if matched_signatures:
                    vulns.append(
                        Vulnerability(
                            module=self.name,
                            name="Template Engine Error Fingerprints Detected",
                            description="Response contains template engine error signatures indicating potential code evaluation surface",
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.7,
                            affected_urls=[url],
                            evidence={
                                "indicators": matched_signatures[:10],
                                "response_snippet": resp.text[:500] if resp.text else "",
                            },
                            remediation=(
                                "Disable stack traces and detailed error pages in production. "
                                "Ensure template rendering does not evaluate untrusted input."
                            ),
                            references=[
                                "https://portswigger.net/web-security/server-side-template-injection",
                                "https://owasp.org/www-community/attacks/Server-Side_Template_Injection",
                            ],
                            cwe_ids=["CWE-94", "CWE-917"],
                        )
                    )
        except Exception:
            pass
        return vulns

    async def _probe_debug_endpoints(self, url: str, config: ScanConfig) -> List[Vulnerability]:
        """Probe a set of known debug/console endpoints without executing code."""
        vulns: List[Vulnerability] = []
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            # Use current path as root for urljoin
            base_with_path = f"{base}{parsed.path if parsed.path else '/'}"
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=8) as client:
                for ep in self.debug_endpoints[:10]:
                    test_url = urljoin(base_with_path, ep)
                    try:
                        resp = await client.get(test_url)
                        if resp.status_code in (200, 401, 403):  # visible or semi-exposed
                            txt = resp.text.lower() if resp.text else ""
                            indicators = []
                            for sig in ["debug", "console", "phpinfo()", "actuator", "beans", "profiler", "debugbar"]:
                                if sig in txt:
                                    indicators.append(sig)
                            if resp.status_code == 200 or indicators:
                                vulns.append(
                                    Vulnerability(
                                        module=self.name,
                                        name="Potential Debug/Console Endpoint Exposed",
                                        description="A debug or console-like endpoint is reachable and may aid RCE exploitation if misconfigured.",
                                        severity=SeverityLevel.MEDIUM,
                                        confidence=0.65 if resp.status_code != 200 else 0.8,
                                        affected_urls=[test_url],
                                        evidence={
                                            "endpoint": ep,
                                            "status_code": resp.status_code,
                                            "indicators": indicators,
                                            "response_snippet": resp.text[:400] if resp.text else "",
                                        },
                                        remediation=(
                                            "Disable and restrict debug/console endpoints in production. "
                                            "Ensure they require strong authentication and are not publicly accessible."
                                        ),
                                        references=[
                                            "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
                                        ],
                                        cwe_ids=["CWE-215"],
                                    )
                                )
                    except Exception:
                        pass
        except Exception:
            pass
        return vulns

    def _engine_guess_from_text(self, text: str) -> Optional[str]:
        """Attempt to guess template engine from text content."""
        mapping = {
            "jinja2": "Jinja2",
            "twig": "Twig",
            "freemarker": "FreeMarker",
            "thymeleaf": "Thymeleaf",
            "spring": "Spring",
            "spel": "SpringEL",
            "ognl": "OGNL",
            "ejs": "EJS",
            "handlebars": "Handlebars",
            "mustache": "Mustache",
            "erb": "ERB",
            "smarty": "Smarty",
        }
        low = text.lower()
        for k, v in mapping.items():
            if k in low:
                return v
        return None

    def _analyze_ssti_response(self, response_text: str, expected_marker: str) -> Dict[str, Any]:
        """Analyze if the response indicates evaluation of our sentinel expression."""
        evidence = {
            "is_vulnerable": False,
            "confidence": 0.0,
            "indicators": [],
            "engine_guess": None,
            "response_snippet": response_text[:500] if response_text else "",
        }
        if not response_text:
            return evidence

        # High-confidence check: sentinel evaluated to expected marker
        if expected_marker in response_text:
            evidence["is_vulnerable"] = True
            evidence["confidence"] = 0.95
            evidence["indicators"].append("sentinel_evaluated")
            engine_guess = self._engine_guess_from_text(response_text)
            if engine_guess:
                evidence["engine_guess"] = engine_guess
            return evidence

        # Engine error signatures (medium-high)
        low = response_text.lower()
        matched = [sig for sig in self.engine_error_signatures if sig.lower() in low]
        if matched:
            evidence["is_vulnerable"] = True
            evidence["confidence"] = 0.75
            evidence["indicators"].extend([f"engine_error:{m}" for m in matched[:5]])
            engine_guess = self._engine_guess_from_text(response_text)
            if engine_guess:
                evidence["engine_guess"] = engine_guess

        return evidence

    async def _test_url_parameters(self, url: str, baseline: Dict[str, Any],
                                   config: ScanConfig, max_params: int) -> Dict[str, Any]:
        """Test URL parameters with safe SSTI/EL probes."""
        vulnerabilities: List[Vulnerability] = []
        tested_params: List[str] = []
        payloads_tested = 0

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # If no existing params, probe a limited set of common names
        if not params:
            params = {p: ["test"] for p in self.probe_param_names[:max_params]}

        # Limit number of params tested
        params_items = list(params.items())[:max_params]

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
            for param_name, values in params_items:
                tested_params.append(param_name)
                original_value = values[0] if values else "test"

                for ptype, payload, expected in self.ssti_payloads[:6]:  # limit payloads per param
                    payloads_tested += 1
                    test_params = params.copy()
                    test_params[param_name] = [f"{original_value}{payload}"]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

                    try:
                        resp = await client.get(test_url)
                        analysis = self._analyze_ssti_response(resp.text, expected)

                        if analysis["is_vulnerable"]:
                            severity = SeverityLevel.CRITICAL if "sentinel_evaluated" in analysis["indicators"] else SeverityLevel.HIGH
                            confidence = analysis["confidence"]
                            name = f"SSTI in parameter '{param_name}'" if severity == SeverityLevel.CRITICAL else f"Template Engine Error indicating RCE surface in '{param_name}'"

                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=name,
                                    description=(
                                        "Parameter appears to be evaluated by a server-side template engine, "
                                        "indicating a potential Remote Code Execution vector."
                                    ),
                                    severity=severity,
                                    confidence=confidence,
                                    affected_urls=[url],
                                    evidence={
                                        "parameter": param_name,
                                        "payload": payload,
                                        "expected": expected,
                                        "indicators": analysis.get("indicators", []),
                                        "engine_guess": analysis.get("engine_guess"),
                                        "response_snippet": resp.text[:500] if resp.text else "",
                                        "method": "GET",
                                    },
                                    remediation=(
                                        "Do not render untrusted input in templates. Use context separation and auto-escaping. "
                                        "Avoid dynamic template evaluation of user input. Implement strict input validation."
                                    ),
                                    references=[
                                        "https://portswigger.net/web-security/server-side-template-injection",
                                        "https://owasp.org/www-community/attacks/Server-Side_Template_Injection",
                                        "https://cwe.mitre.org/data/definitions/94.html",
                                        "https://cwe.mitre.org/data/definitions/917.html",
                                    ],
                                    cwe_ids=["CWE-94", "CWE-917"],
                                )
                            )
                            # Stop further payloads for this parameter after a high-confidence hit
                            if severity == SeverityLevel.CRITICAL:
                                break

                    except Exception:
                        # Ignore individual request errors
                        pass

        return {"vulnerabilities": vulnerabilities, "tested_params": tested_params, "payloads_tested": payloads_tested}

    async def _test_forms(self, url: str, config: ScanConfig, max_forms: int) -> Dict[str, Any]:
        """Test forms by submitting safe SSTI payloads into non-sensitive fields."""
        vulnerabilities: List[Vulnerability] = []
        tested_fields: List[str] = []
        payloads_tested = 0

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
                resp = await client.get(url)
                html = resp.text or ""

                # Extract forms
                form_pattern = re.compile(r"<form[^>]>(.?)</form>", re.IGNORECASE | re.DOTALL)
                forms = form_pattern.findall(html)
                if not forms:
                    return {"vulnerabilities": [], "tested_fields": [], "payloads_tested": 0}

                forms = forms[:max_forms]

                for form_html in forms:
                    # Extract action and method
                    action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                    method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                    action = action_match.group(1) if action_match else url
                    method = (method_match.group(1).upper() if method_match else "POST")

                    if not action.startswith(("http://", "https://")):
                        action = urljoin(url, action)

                    # Extract inputs
                    input_pattern = re.compile(r'<input[^>]name=["\']([^"\']+)["\'][^>]>', re.IGNORECASE)
                    inputs = input_pattern.findall(form_html)

                    # Test subset of fields
                    for input_name in inputs[:8]:
                        lname = input_name.lower()
                        if lname in ["csrf", "token", "authenticity_token", "captcha", "password", "submit"]:
                            continue

                        tested_fields.append(input_name)
                        # Use a single sentinel payload for forms to limit side effects
                        payload_tuple = self.ssti_payloads[0]  # ("jinja2", "SENTINEL{{7*7}}RCE", "SENTINEL49RCE")
                        payloads_tested += 1

                        data = {n: "test" for n in inputs}
                        data[input_name] = f"test{payload_tuple[1]}"

                        try:
                            if method == "POST":
                                fresp = await client.post(action, data=data)
                            else:
                                fresp = await client.get(action, params=data)

                            analysis = self._analyze_ssti_response(fresp.text, payload_tuple[2])
                            if analysis["is_vulnerable"]:
                                severity = SeverityLevel.CRITICAL if "sentinel_evaluated" in analysis["indicators"] else SeverityLevel.HIGH
                                confidence = analysis["confidence"]
                                name = f"SSTI in form field '{input_name}'" if severity == SeverityLevel.CRITICAL else f"Template Engine Error indicating RCE surface in form field '{input_name}'"

                                vulnerabilities.append(
                                    Vulnerability(
                                        module=self.name,
                                        name=name,
                                        description=(
                                            "Form field appears to be evaluated by a server-side template engine, "
                                            "indicating a potential Remote Code Execution vector."
                                        ),
                                        severity=severity,
                                        confidence=confidence,
                                        affected_urls=[action],
                                        evidence={
                                            "field": input_name,
                                            "payload": payload_tuple[1],
                                            "expected": payload_tuple[2],
                                            "indicators": analysis.get("indicators", []),
                                            "engine_guess": analysis.get("engine_guess"),
                                            "response_snippet": fresp.text[:500] if fresp.text else "",
                                            "method": method,
                                        },
                                        remediation=(
                                            "Do not render untrusted input in templates. Use context separation and auto-escaping. "
                                            "Avoid dynamic template evaluation of user input. Implement strict input validation."
                                        ),
                                        references=[
                                            "https://portswigger.net/web-security/server-side-template-injection",
                                            "https://owasp.org/www-community/attacks/Server-Side_Template_Injection",
                                            "https://cwe.mitre.org/data/definitions/94.html",
                                            "https://cwe.mitre.org/data/definitions/917.html",
                                        ],
                                        cwe_ids=["CWE-94", "CWE-917"],
                                    )
                                )
                        except Exception:
                            pass

        except Exception:
            pass

        return {"vulnerabilities": vulnerabilities, "tested_fields": tested_fields, "payloads_tested": payloads_tested}

    async def _test_post_parameters(self, url: str, config: ScanConfig, max_params: int) -> Dict[str, Any]:
        """Lightweight POST parameter probing with safe SSTI payloads in common keys."""
        vulnerabilities: List[Vulnerability] = []
        tested_params: List[str] = []
        payloads_tested = 0

        common_post_keys = ["value", "query", "template", "expression", "content", "message"]
        keys = common_post_keys[:max_params]

        payload_tuple = self.ssti_payloads[1]  # ("twig", "SENTINEL{{ 7*7 }}RCE", "SENTINEL49RCE")

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
            for key in keys:
                tested_params.append(key)
                data = {key: f"test{payload_tuple[1]}"}
                payloads_tested += 1
                try:
                    resp = await client.post(url, data=data)
                    analysis = self._analyze_ssti_response(resp.text, payload_tuple[2])
                    if analysis["is_vulnerable"]:
                        severity = SeverityLevel.CRITICAL if "sentinel_evaluated" in analysis["indicators"] else SeverityLevel.HIGH
                        confidence = analysis["confidence"]
                        name = f"SSTI via POST parameter '{key}'" if severity == SeverityLevel.CRITICAL else f"Template Engine Error indicating RCE surface via POST '{key}'"

                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=name,
                                description=(
                                    "POST parameter appears to be evaluated by a server-side template engine, "
                                    "indicating a potential Remote Code Execution vector."
                                ),
                                severity=severity,
                                confidence=confidence,
                                affected_urls=[url],
                                evidence={
                                    "parameter": key,
                                    "payload": payload_tuple[1],
                                    "expected": payload_tuple[2],
                                    "indicators": analysis.get("indicators", []),
                                    "engine_guess": analysis.get("engine_guess"),
                                    "response_snippet": resp.text[:500] if resp.text else "",
                                    "method": "POST",
                                },
                                remediation=(
                                    "Do not render untrusted input in templates. Use context separation and auto-escaping. "
                                    "Avoid dynamic template evaluation of user input. Implement strict input validation."
                                ),
                                references=[
                                    "https://portswigger.net/web-security/server-side-template-injection",
                                    "https://owasp.org/www-community/attacks/Server-Side_Template_Injection",
                                    "https://cwe.mitre.org/data/definitions/94.html",
                                    "https://cwe.mitre.org/data/definitions/917.html",
                                ],
                                cwe_ids=["CWE-94", "CWE-917"],
                            )
                        )
                except Exception:
                    pass

        return {"vulnerabilities": vulnerabilities, "tested_params": tested_params, "payloads_tested": payloads_tested}

    async def _test_headers(self, url: str, baseline: Dict[str, Any], config: ScanConfig,
                           baseline_has_errors: bool) -> Dict[str, Any]:
        """Test HTTP headers for SSTI vulnerabilities."""
        vulnerabilities: List[Vulnerability] = []
        tested_headers: List[str] = []
        payloads_tested = 0

        # Use a simple payload for headers
        payload_tuple = self.ssti_payloads[0]

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
            for header_name in self.test_headers[:5]:  # Limit headers tested
                tested_headers.append(header_name)
                payloads_tested += 1
                
                headers = {header_name: payload_tuple[1]}
                
                try:
                    resp = await client.get(url, headers=headers)
                    analysis = self._analyze_ssti_response(resp.text, payload_tuple[2])
                    
                    if analysis["is_vulnerable"]:
                        # Adjust confidence if baseline has errors
                        if baseline_has_errors:
                            analysis["confidence"] *= 0.8
                            
                        severity = SeverityLevel.HIGH if "sentinel_evaluated" in analysis["indicators"] else SeverityLevel.MEDIUM
                        
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"SSTI via HTTP Header '{header_name}'",
                                description=(
                                    f"HTTP header '{header_name}' appears to be evaluated by a server-side template engine, "
                                    "indicating a potential Remote Code Execution vector through header injection."
                                ),
                                severity=severity,
                                confidence=analysis["confidence"],
                                affected_urls=[url],
                                evidence={
                                    "header": header_name,
                                    "payload": payload_tuple[1],
                                    "expected": payload_tuple[2],
                                    "indicators": analysis.get("indicators", []),
                                    "engine_guess": analysis.get("engine_guess"),
                                    "response_snippet": resp.text[:500] if resp.text else "",
                                },
                                **self.SSTI_VULN_TEMPLATE
                            )
                        )
                except Exception:
                    pass

        return {"vulnerabilities": vulnerabilities, "tested_headers": tested_headers, "payloads_tested": payloads_tested}

    async def _test_forms_enhanced(self, url: str, config: ScanConfig, max_forms: int,
                                  baseline_has_errors: bool) -> Dict[str, Any]:
        """Test forms using robust HTML parser."""
        vulnerabilities: List[Vulnerability] = []
        tested_fields: List[str] = []
        payloads_tested = 0

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
                resp = await client.get(url)
                html = resp.text or ""

                # Use the robust HTML parser
                parser = FormParser()
                parser.feed(html)
                forms = parser.forms[:max_forms]

                for form in forms:
                    action = form.action if form.action else url
                    if not action.startswith(("http://", "https://")):
                        action = urljoin(url, action)

                    # Test form fields
                    for field_name, field_value in list(form.fields.items())[:8]:
                        lname = field_name.lower()
                        if lname in ["csrf", "token", "authenticity_token", "captcha", "password", "submit"]:
                            continue

                        tested_fields.append(field_name)
                        payload_tuple = self.ssti_payloads[0]
                        payloads_tested += 1

                        # Prepare data with payload
                        data = form.fields.copy()
                        data[field_name] = payload_tuple[1]

                        try:
                            if form.method == "POST":
                                if form.enctype == "application/json":
                                    resp = await client.post(action, json=data)
                                else:
                                    resp = await client.post(action, data=data)
                            else:
                                resp = await client.get(action, params=data)

                            analysis = self._analyze_ssti_response(resp.text, payload_tuple[2])
                            
                            if analysis["is_vulnerable"]:
                                # Adjust confidence if baseline has errors
                                if baseline_has_errors:
                                    analysis["confidence"] *= 0.8
                                    
                                severity = SeverityLevel.CRITICAL if "sentinel_evaluated" in analysis["indicators"] else SeverityLevel.HIGH
                                
                                vulnerabilities.append(
                                    Vulnerability(
                                        module=self.name,
                                        name=f"SSTI in form field '{field_name}'",
                                        description=(
                                            "Form field appears to be evaluated by a server-side template engine, "
                                            "indicating a potential Remote Code Execution vector."
                                        ),
                                        severity=severity,
                                        confidence=analysis["confidence"],
                                        affected_urls=[action],
                                        evidence={
                                            "field": field_name,
                                            "payload": payload_tuple[1],
                                            "expected": payload_tuple[2],
                                            "indicators": analysis.get("indicators", []),
                                            "engine_guess": analysis.get("engine_guess"),
                                            "response_snippet": resp.text[:500] if resp.text else "",
                                            "method": form.method,
                                            "enctype": form.enctype,
                                        },
                                        **self.SSTI_VULN_TEMPLATE
                                    )
                                )
                        except Exception:
                            pass

        except Exception:
            pass

        return {"vulnerabilities": vulnerabilities, "tested_fields": tested_fields, "payloads_tested": payloads_tested}

    async def _test_post_parameters_enhanced(self, url: str, config: ScanConfig, max_params: int,
                                            test_json: bool, baseline_has_errors: bool) -> Dict[str, Any]:
        """Enhanced POST parameter testing with JSON support."""
        vulnerabilities: List[Vulnerability] = []
        tested_params: List[str] = []
        payloads_tested = 0

        common_post_keys = ["value", "query", "template", "expression", "content", "message", "data", "input"]
        keys = common_post_keys[:max_params]

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
            for key in keys:
                tested_params.append(key)
                
                # Test form-encoded
                payload_tuple = self.ssti_payloads[0]
                data = {key: payload_tuple[1]}
                payloads_tested += 1
                
                try:
                    resp = await client.post(url, data=data)
                    analysis = self._analyze_ssti_response(resp.text, payload_tuple[2])
                    
                    if analysis["is_vulnerable"]:
                        if baseline_has_errors:
                            analysis["confidence"] *= 0.8
                            
                        severity = SeverityLevel.CRITICAL if "sentinel_evaluated" in analysis["indicators"] else SeverityLevel.HIGH
                        
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"SSTI via POST parameter '{key}'",
                                description=(
                                    "POST parameter appears to be evaluated by a server-side template engine, "
                                    "indicating a potential Remote Code Execution vector."
                                ),
                                severity=severity,
                                confidence=analysis["confidence"],
                                affected_urls=[url],
                                evidence={
                                    "parameter": key,
                                    "payload": payload_tuple[1],
                                    "expected": payload_tuple[2],
                                    "indicators": analysis.get("indicators", []),
                                    "engine_guess": analysis.get("engine_guess"),
                                    "response_snippet": resp.text[:500] if resp.text else "",
                                    "method": "POST",
                                    "content_type": "application/x-www-form-urlencoded",
                                },
                                **self.SSTI_VULN_TEMPLATE
                            )
                        )
                except Exception:
                    pass

                # Test JSON if enabled
                if test_json:
                    json_data = {key: payload_tuple[1]}
                    payloads_tested += 1
                    
                    try:
                        resp = await client.post(url, json=json_data)
                        analysis = self._analyze_ssti_response(resp.text, payload_tuple[2])
                        
                        if analysis["is_vulnerable"]:
                            if baseline_has_errors:
                                analysis["confidence"] *= 0.8
                                
                            severity = SeverityLevel.CRITICAL if "sentinel_evaluated" in analysis["indicators"] else SeverityLevel.HIGH
                            
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"SSTI via JSON parameter '{key}'",
                                    description=(
                                        "JSON parameter appears to be evaluated by a server-side template engine, "
                                        "indicating a potential Remote Code Execution vector in API endpoint."
                                    ),
                                    severity=severity,
                                    confidence=analysis["confidence"],
                                    affected_urls=[url],
                                    evidence={
                                        "parameter": key,
                                        "payload": payload_tuple[1],
                                        "expected": payload_tuple[2],
                                        "indicators": analysis.get("indicators", []),
                                        "engine_guess": analysis.get("engine_guess"),
                                        "response_snippet": resp.text[:500] if resp.text else "",
                                        "method": "POST",
                                        "content_type": "application/json",
                                    },
                                    **self.SSTI_VULN_TEMPLATE
                                )
                            )
                    except Exception:
                        pass

        return {"vulnerabilities": vulnerabilities, "tested_params": tested_params, "payloads_tested": payloads_tested}

    def _engine_guess_from_payload(self, payload_type: str, text: str) -> Optional[str]:
        """Guess engine based on successful payload type and response text."""
        # Map payload types to likely engines
        payload_engine_map = {
            "jinja2": "Jinja2",
            "twig": "Twig",
            "erb": "ERB (Ruby)",
            "ejs": "EJS (Node.js)",
            "handlebars": "Handlebars",
            "mustache": "Mustache",
            "freemarker": "FreeMarker",
            "thymeleaf": "Thymeleaf",
            "spel": "Spring Expression Language",
            "ognl": "OGNL",
            "velocity": "Velocity",
        }
        
        # First check payload type
        if payload_type in payload_engine_map:
            return payload_engine_map[payload_type]
        
        # Fallback to text analysis
        return self._engine_guess_from_text(text)

    async def _test_url_parameters(self, url: str, baseline: Dict[str, Any],
                                   config: ScanConfig, max_params: int, baseline_has_errors: bool) -> Dict[str, Any]:
        """Test URL parameters with safe SSTI/EL probes and baseline awareness."""
        vulnerabilities: List[Vulnerability] = []
        tested_params: List[str] = []
        payloads_tested = 0

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # If no existing params, probe a limited set of common names
        if not params:
            params = {p: ["test"] for p in self.probe_param_names[:max_params]}

        # Limit number of params tested
        params_items = list(params.items())[:max_params]

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
            for param_name, values in params_items:
                tested_params.append(param_name)
                original_value = values[0] if values else ""

                for ptype, payload, expected in self.ssti_payloads[:6]:  # limit payloads per param
                    payloads_tested += 1
                    test_params = params.copy()
                    # Use improved payload isolation
                    test_params[param_name] = [payload]  # Don't concatenate with original value
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

                    try:
                        resp = await client.get(test_url)
                        analysis = self._analyze_ssti_response(resp.text, expected)

                        if analysis["is_vulnerable"]:
                            # Adjust confidence if baseline has errors
                            if baseline_has_errors:
                                analysis["confidence"] *= 0.8
                                
                            # Enhance engine guess with payload type
                            if not analysis.get("engine_guess"):
                                analysis["engine_guess"] = self._engine_guess_from_payload(ptype, resp.text)
                                
                            severity = SeverityLevel.CRITICAL if "sentinel_evaluated" in analysis["indicators"] else SeverityLevel.HIGH
                            confidence = analysis["confidence"]
                            name = f"SSTI in parameter '{param_name}'" if severity == SeverityLevel.CRITICAL else f"Template Engine Error indicating RCE surface in '{param_name}'"

                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=name,
                                    description=(
                                        "Parameter appears to be evaluated by a server-side template engine, "
                                        "indicating a potential Remote Code Execution vector."
                                    ),
                                    severity=severity,
                                    confidence=confidence,
                                    affected_urls=[url],
                                    evidence={
                                        "parameter": param_name,
                                        "payload": payload,
                                        "payload_type": ptype,
                                        "expected": expected,
                                        "indicators": analysis.get("indicators", []),
                                        "engine_guess": analysis.get("engine_guess"),
                                        "response_snippet": resp.text[:500] if resp.text else "",
                                        "method": "GET",
                                        "baseline_has_errors": baseline_has_errors,
                                    },
                                    **self.SSTI_VULN_TEMPLATE
                                )
                            )
                            # Stop further payloads for this parameter after a high-confidence hit
                            if severity == SeverityLevel.CRITICAL:
                                break

                    except Exception:
                        # Ignore individual request errors
                        pass

        return {"vulnerabilities": vulnerabilities, "tested_params": tested_params, "payloads_tested": payloads_tested}
