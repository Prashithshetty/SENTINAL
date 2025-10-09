"""RCE (Remote Code Execution) Scanner Module focused on safe, high-confidence detection.

This module targets common RCE vectors that manifest via:
- Server-Side Template Injection (SSTI)
- Expression Language Injection (EL/SpEL/OGNL)
- Exposed debug/eval endpoints and developer consoles

Design goals:
- Safe-by-default: non-destructive arithmetic/sentinel probes only (no OS commands, no file writes).
- High confidence: sentinel-based evaluation checks (e.g., SENTINEL{{7*7}}RCE -> SENTINEL49RCE).
- Evidence-rich findings: engine fingerprinting, stack traces, and content diffs.

Custom Params:
- rce_force_passive: bool; if True, only perform passive checks.
- rce_enable_oob: bool; if True and rce_canary_domain provided, may include benign OOB probes (placeholder).
- rce_canary_domain: str; collaborator domain for OOB confirmation (not used by default).
- rce_max_forms: int; limit number of forms to test (default: 3).
- rce_max_params_per_surface: int; limit number of params to test per surface (default: 10).

References:
- OWASP: https://owasp.org/www-community/attacks/Server-Side_Template_Injection
- PortSwigger: https://portswigger.net/web-security/server-side-template-injection
- CWE-94 (Code Injection), CWE-917 (Expression Language Injection)
"""

import re
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, quote

import httpx

from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)


class RCEScanner(BaseScannerModule):
    """Remote Code Execution vector scanner (SSTI/EL/SpEL/OGNL/debug endpoints)."""

    def __init__(self):
        super().__init__()
        self.name = "RCEScanner"
        self.description = "Detects Remote Code Execution vectors (SSTI/EL/SpEL/OGNL/debug/eval exposures)"
        self.scan_type = ScanType.ACTIVE

        # Safe SSTI/EL arithmetic payloads with sentinel markers to increase confidence
        # Format: (type, payload, expected_marker_if_eval)
        # If template engine evaluates the expression, we should see SENTINEL49RCE in output
        self.ssti_payloads: List[Tuple[str, str, str]] = [
            ("jinja2", "SENTINEL{{7*7}}RCE", "SENTINEL49RCE"),
            ("twig", "SENTINEL{{ 7*7 }}RCE", "SENTINEL49RCE"),
            ("erb", "SENTINEL<%= 7*7 %>RCE", "SENTINEL49RCE"),
            ("ejs", "SENTINEL<%= 7*7 %>RCE", "SENTINEL49RCE"),
            ("handlebars", "SENTINEL{{7*7}}RCE", "SENTINEL49RCE"),
            ("mustache", "SENTINEL{{7*7}}RCE", "SENTINEL49RCE"),
            ("freemarker", "SENTINEL${7*7}RCE", "SENTINEL49RCE"),
            ("thymeleaf", "SENTINEL[[${7*7}]]RCE", "SENTINEL49RCE"),
            ("spel", "SENTINEL#{7*7}RCE", "SENTINEL49RCE"),
            ("ognl", "SENTINEL%{7*7}RCE", "SENTINEL49RCE"),
        ]

        # Template/EL engine error signatures (used for passive and active analysis)
        self.engine_error_signatures = [
            # Python/Jinja2
            "jinja2.exceptions", "UndefinedError", "TemplateSyntaxError", "Jinja2",
            # PHP/Twig/Smarty
            "Twig\\Error", "RuntimeException", "SmartyCompilerException", "Twig_Error",
            # Java/Thymeleaf/Freemarker/SpEL/OGNL
            "org.thymeleaf", "thymeleaf", "freemarker.core", "freemarker.template",
            "org.springframework.expression", "SpEL", "ognl.OgnlException", "ognl",
            # Ruby ERB
            "ActionView::Template::Error", "ERB::Util",
            # Node/EJS/Handlebars/Mustache
            "ejs:", "EJS:", "Handlebars", "Mustache",
            # Generic template hints
            "Template engine", "template rendering error", "template error",
        ]

        # Debug/Eval/Console endpoints to probe (GET only)
        self.debug_endpoints = [
            "/debug", "/console", "/_console", "/_profiler", "/rails/info", "/phpinfo", "/_debugbar",
            "/actuator/env", "/actuator/beans", "/actuator", "/_debug_",
        ]

        # Likely parameter names where rendering/evaluation may occur
        self.probe_param_names = [
            "q", "search", "s", "name", "title", "message", "template", "view", "page",
            "format", "lang", "code", "eval", "expression", "render", "path", "content"
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
        """Perform RCE vector scan (safe, non-destructive)."""
        started_at = datetime.utcnow()
        vulnerabilities: List[Vulnerability] = []
        errors: List[str] = []
        warnings: List[str] = []
        info: Dict[str, Any] = {
            "tested_parameters": [],
            "vulnerable_parameters": [],
            "rce_types_found": [],
            "payloads_successful": [],
            "debug_endpoints_found": [],
        }
        statistics: Dict[str, Any] = {
            "urls_tested": 0,
            "parameters_tested": 0,
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
            force_passive: bool = bool(config.custom_params.get("rce_force_passive", False))
            max_forms: int = int(config.custom_params.get("rce_max_forms", 3))
            max_params_per_surface: int = int(config.custom_params.get("rce_max_params_per_surface", 10))

            # Get baseline response snapshot
            baseline = await self._get_baseline_response(target_url)

            # Probe known debug endpoints (safe GET requests)
            debug_vulns = await self._probe_debug_endpoints(target_url, config)
            if debug_vulns:
                vulnerabilities.extend(debug_vulns)
                for v in debug_vulns:
                    evidence = v.evidence or {}
                    if "endpoint" in evidence:
                        info["debug_endpoints_found"].append(evidence["endpoint"])

            # Passive engine fingerprinting (error banners, stack traces)
            passive_vulns = await self._passive_fingerprints(target_url, config)
            vulnerabilities.extend(passive_vulns)

            # Active tests only if not forced passive and scan type allows
            if not force_passive and config.scan_type != ScanType.PASSIVE:
                # URL parameter testing
                param_results = await self._test_url_parameters(
                    target_url, baseline, config, max_params_per_surface
                )
                vulnerabilities.extend(param_results["vulnerabilities"])
                info["tested_parameters"].extend(param_results["tested_params"])
                statistics["parameters_tested"] += len(param_results["tested_params"])
                statistics["payloads_tested"] += param_results["payloads_tested"]

                # Form testing
                form_results = await self._test_forms(
                    target_url, config, max_forms
                )
                vulnerabilities.extend(form_results["vulnerabilities"])
                info["tested_parameters"].extend(form_results["tested_fields"])
                statistics["parameters_tested"] += len(form_results["tested_fields"])
                statistics["payloads_tested"] += form_results["payloads_tested"]

                # Optional: POST parameter surface (lightweight)
                post_results = await self._test_post_parameters(
                    target_url, config, max_params_per_surface
                )
                vulnerabilities.extend(post_results["vulnerabilities"])
                info["tested_parameters"].extend(post_results["tested_params"])
                statistics["parameters_tested"] += len(post_results["tested_params"])
                statistics["payloads_tested"] += post_results["payloads_tested"]

            # Track vulnerable parameters and rce types
            for vuln in vulnerabilities:
                ev = vuln.evidence or {}
                if "parameter" in ev:
                    info["vulnerable_parameters"].append(ev["parameter"])

            rce_types = set()
            for vuln in vulnerabilities:
                name_lower = vuln.name.lower()
                if "ssti" in name_lower:
                    rce_types.add("SSTI")
                if "el" in name_lower or "spel" in name_lower or "ognl" in name_lower:
                    rce_types.add("EL/SpEL/OGNL")
                if "debug" in name_lower or "console" in name_lower or "phpinfo" in name_lower:
                    rce_types.add("DebugEndpoint")
                if "template" in name_lower and "error" in name_lower:
                    rce_types.add("TemplateEngineError")
            info["rce_types_found"] = list(rce_types)

            # Stats
            statistics["vulnerabilities_found"] = len(vulnerabilities)
            statistics["urls_tested"] = 1

            # Confidence tallies
            for v in vulnerabilities:
                if v.confidence >= 0.85:
                    statistics["high_confidence"] += 1
                    # Mark payloads successful (if any)
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
        """Get baseline response snapshot for comparison."""
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
                start = time.time()
                resp = await client.get(url)
                elapsed_ms = (time.time() - start) * 1000.0
                return {
                    "status_code": resp.status_code,
                    "content_length": len(resp.content),
                    "response_time_ms": elapsed_ms,
                    "headers": dict(resp.headers),
                    "text_sample": resp.text[:500] if resp.text else "",
                }
        except Exception as e:
            return {"error": str(e), "status_code": 0, "content_length": 0, "response_time_ms": 0}

    async def _passive_fingerprints(self, url: str, config: ScanConfig) -> List[Vulnerability]:
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