



import re
import json
import time
import asyncio
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, quote, urlunparse
from html.parser import HTMLParser
from dataclasses import dataclass, field
from collections import deque

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


@dataclass
class AttackSurface:
    """Represents an identified attack surface (form, parameter, endpoint)."""
    url: str
    surface_type: str  # 'form', 'url_param', 'js_endpoint', 'header'
    parameters: Dict[str, str] = field(default_factory=dict)
    method: str = "GET"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CrawlResult:
    """Results from the web crawling phase."""
    discovered_urls: Set[str] = field(default_factory=set)
    forms: List[FormData] = field(default_factory=list)
    url_parameters: Dict[str, List[str]] = field(default_factory=dict)
    js_files: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    attack_surfaces: List[AttackSurface] = field(default_factory=list)


class LinkExtractor(HTMLParser):
    """Extract all links from HTML content."""
    
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.js_files = set()
        
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        if tag == "a":
            href = attrs_dict.get("href")
            if href:
                absolute_url = urljoin(self.base_url, href)
                self.links.add(absolute_url)
                
        elif tag == "script":
            src = attrs_dict.get("src")
            if src:
                absolute_url = urljoin(self.base_url, src)
                self.js_files.add(absolute_url)
                
        elif tag == "link":
            href = attrs_dict.get("href")
            if href and href.endswith('.js'):
                absolute_url = urljoin(self.base_url, href)
                self.js_files.add(absolute_url)


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
    """
    Enhanced Remote Code Execution vector scanner with comprehensive web crawling,
    attack surface identification, fuzzing, and reporting capabilities.
    
    Implements a 4-phase approach:
    1. Discovery and Mapping - Crawl website to find all pages
    2. Identify Attack Surfaces - Find forms, parameters, JS endpoints
    3. Active Fuzzing and Testing - Inject payloads and analyze responses
    4. Logging and Reporting - Document all findings
    """

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
        self.description = "Comprehensive RCE scanner with crawling, attack surface mapping, and fuzzing"
        self.scan_type = ScanType.ACTIVE

        # Crawling configuration
        self.max_crawl_depth = 3
        self.max_pages_to_crawl = 50
        self.crawl_timeout = 30  # seconds per request
        
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
        
        # JavaScript patterns for finding hidden endpoints
        self.js_endpoint_patterns = [
            r'["\']/(api|admin|debug|console|eval|execute|shell)[^"\']*["\']',
            r'["\']https?://[^"\']+/api/[^"\']*["\']',
            r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
            r'url\s*[:=]\s*["\']([^"\']+)["\']',
            r'path\s*[:=]\s*["\']([^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\$\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
        ]
        
        # RCE payload categories for comprehensive fuzzing
        self.rce_payload_categories = {
            "command_injection": [
                "| whoami",
                "; whoami",
                "& whoami",
                "`whoami`",
                "$(whoami)",
                "\n whoami",
            ],
            "sql_injection": [
                "' OR 1=1--",
                "' OR '1'='1",
                "admin'--",
                "' UNION SELECT NULL--",
            ],
            "time_based": [
                "'; WAITFOR DELAY '0:0:5'--",
                "' OR SLEEP(5)--",
                "; sleep 5",
                "| sleep 5",
            ],
        }

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
        """
        Perform comprehensive 4-phase RCE vector scan:
        1. Discovery and Mapping - Crawl website
        2. Identify Attack Surfaces - Find forms, parameters, JS endpoints
        3. Active Fuzzing and Testing - Inject payloads
        4. Logging and Reporting - Document findings
        """
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
            "crawl_summary": {},
            "attack_surfaces_summary": {},
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
            "pages_crawled": 0,
            "attack_surfaces_identified": 0,
        }

        try:
            # Normalize URL
            target_url = config.target
            if not target_url.startswith(("http://", "https://")):
                target_url = f"https://{target_url}"

            # Read custom params
            force_passive = bool(config.custom_params.get("rce_force_passive", False))
            enable_crawling = bool(config.custom_params.get("rce_enable_crawling", True))
            enable_js_analysis = bool(config.custom_params.get("rce_enable_js_analysis", True))
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

            # ===== PHASE 1: DISCOVERY AND MAPPING =====
            crawl_result = CrawlResult()
            if enable_crawling and not force_passive:
                try:
                    crawl_result = await self._crawl_website(target_url, config)
                    statistics["pages_crawled"] = len(crawl_result.discovered_urls)
                    info["crawl_summary"] = {
                        "urls_discovered": len(crawl_result.discovered_urls),
                        "forms_found": len(crawl_result.forms),
                        "parameters_found": len(crawl_result.url_parameters),
                        "js_files_found": len(crawl_result.js_files),
                    }
                except Exception as e:
                    warnings.append(f"Crawling phase failed: {str(e)}")
                    # Continue with single URL testing
                    crawl_result.discovered_urls.add(target_url)
            else:
                # No crawling, just test the target URL
                crawl_result.discovered_urls.add(target_url)

            # ===== PHASE 2: JAVASCRIPT ANALYSIS =====
            if enable_js_analysis and crawl_result.js_files:
                try:
                    api_endpoints = await self._analyze_javascript_files(
                        list(crawl_result.js_files), 
                        target_url
                    )
                    crawl_result.api_endpoints = api_endpoints
                    info["crawl_summary"]["api_endpoints_discovered"] = len(api_endpoints)
                except Exception as e:
                    warnings.append(f"JavaScript analysis failed: {str(e)}")

            # ===== PHASE 2: IDENTIFY ATTACK SURFACES =====
            attack_surfaces = []
            if not force_passive:
                try:
                    attack_surfaces = self._identify_attack_surfaces(crawl_result, target_url)
                    statistics["attack_surfaces_identified"] = len(attack_surfaces)
                    
                    # Summarize attack surfaces by type
                    surface_types = {}
                    for surface in attack_surfaces:
                        stype = surface.surface_type
                        surface_types[stype] = surface_types.get(stype, 0) + 1
                    info["attack_surfaces_summary"] = surface_types
                except Exception as e:
                    warnings.append(f"Attack surface identification failed: {str(e)}")

            # Probe debug endpoints
            debug_vulns = await self._probe_debug_endpoints(target_url, config)
            vulnerabilities.extend(debug_vulns)
            for v in debug_vulns:
                if "endpoint" in v.evidence:
                    info["debug_endpoints_found"].append(v.evidence["endpoint"])

            # Passive fingerprinting
            passive_vulns = await self._passive_fingerprints(target_url, config, baseline_has_errors)
            vulnerabilities.extend(passive_vulns)

            # ===== PHASE 3: ACTIVE FUZZING AND TESTING =====
            if not force_passive and config.scan_type != ScanType.PASSIVE:
                # Test identified attack surfaces
                for surface in attack_surfaces[:20]:  # Limit to 20 surfaces
                    try:
                        surface_vulns = await self._fuzz_attack_surface(
                            surface, config, baseline_has_errors
                        )
                        vulnerabilities.extend(surface_vulns)
                        statistics["payloads_tested"] += len(surface.parameters) * 3  # Estimate
                    except Exception as e:
                        continue

                # Legacy testing methods (for backward compatibility)
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

            # ===== PHASE 4: LOGGING AND REPORTING =====
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
                if "command" in name_lower and "injection" in name_lower:
                    rce_types.add("Command Injection")
                if "time-based" in name_lower:
                    rce_types.add("Time-Based Injection")
            info["rce_types_found"] = list(rce_types)
            info["engines_detected"] = list(set(info["engines_detected"]))

            # Generate comprehensive report
            if attack_surfaces:
                try:
                    comprehensive_report = await self._generate_comprehensive_report(
                        crawl_result, attack_surfaces, vulnerabilities
                    )
                    info["comprehensive_report"] = comprehensive_report
                except Exception:
                    pass

            # Statistics
            statistics["vulnerabilities_found"] = len(vulnerabilities)
            statistics["urls_tested"] = len(crawl_result.discovered_urls)

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
"""
Complete implementation of the 4-phase RCE Scanner with:
- Phase 1: Web Crawling and Discovery
- Phase 2: Attack Surface Identification
- Phase 3: JavaScript Analysis
- Phase 4: Comprehensive Fuzzing and Testing

This file contains the additional methods to be added to rce_scanner.py
"""

# These methods should be added to the RCEScanner class in rce_scanner.py

async def _crawl_website(self, start_url: str, config: ScanConfig) -> CrawlResult:
    """
    Phase 1: Discovery and Mapping
    Crawl the website to discover all pages, forms, and parameters.
    """
    result = CrawlResult()
    visited = set()
    to_visit = deque([start_url])
    
    parsed_start = urlparse(start_url)
    base_domain = f"{parsed_start.scheme}://{parsed_start.netloc}"
    
    depth_map = {start_url: 0}
    pages_crawled = 0
    
    async with httpx.AsyncClient(
        verify=False, 
        follow_redirects=True, 
        timeout=self.crawl_timeout
    ) as client:
        while to_visit and pages_crawled < self.max_pages_to_crawl:
            current_url = to_visit.popleft()
            
            if current_url in visited:
                continue
                
            current_depth = depth_map.get(current_url, 0)
            if current_depth > self.max_crawl_depth:
                continue
            
            try:
                # Fetch the page
                resp = await client.get(current_url)
                if resp.status_code != 200:
                    continue
                
                visited.add(current_url)
                result.discovered_urls.add(current_url)
                pages_crawled += 1
                
                # Only process HTML content
                content_type = resp.headers.get("content-type", "").lower()
                if "text/html" not in content_type:
                    continue
                
                html = resp.text
                
                # Extract links
                link_extractor = LinkExtractor(current_url)
                link_extractor.feed(html)
                
                # Add discovered links to queue
                for link in link_extractor.links:
                    parsed_link = urlparse(link)
                    
                    # Only crawl same domain
                    if parsed_link.netloc != parsed_start.netloc:
                        continue
                    
                    # Remove fragments
                    clean_link = urlunparse((
                        parsed_link.scheme,
                        parsed_link.netloc,
                        parsed_link.path,
                        parsed_link.params,
                        parsed_link.query,
                        ""  # no fragment
                    ))
                    
                    if clean_link not in visited and clean_link not in depth_map:
                        depth_map[clean_link] = current_depth + 1
                        to_visit.append(clean_link)
                
                # Collect JavaScript files
                result.js_files.update(link_extractor.js_files)
                
                # Extract forms
                form_parser = FormParser()
                form_parser.feed(html)
                result.forms.extend(form_parser.forms)
                
                # Extract URL parameters
                parsed = urlparse(current_url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param_name, values in params.items():
                        if param_name not in result.url_parameters:
                            result.url_parameters[param_name] = []
                        result.url_parameters[param_name].extend(values)
                
            except Exception as e:
                # Log error but continue crawling
                continue
    
    return result


async def _analyze_javascript_files(self, js_files: List[str], base_url: str) -> List[str]:
    """
    Phase 2: JavaScript Analysis
    Analyze JavaScript files to find hidden API endpoints and parameters.
    """
    discovered_endpoints = []
    
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        for js_url in list(js_files)[:20]:  # Limit to 20 JS files
            try:
                resp = await client.get(js_url)
                if resp.status_code != 200:
                    continue
                
                js_content = resp.text
                
                # Search for endpoint patterns
                for pattern in self.js_endpoint_patterns:
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    for match in matches:
                        # Extract the URL from the match
                        if isinstance(match, tuple):
                            endpoint = match[0] if match else ""
                        else:
                            endpoint = match
                        
                        # Clean and validate endpoint
                        endpoint = endpoint.strip()
                        if not endpoint or len(endpoint) < 2:
                            continue
                        
                        # Make absolute URL
                        if endpoint.startswith('/'):
                            full_url = urljoin(base_url, endpoint)
                        elif endpoint.startswith('http'):
                            full_url = endpoint
                        else:
                            continue
                        
                        # Check if it's in scope
                        parsed_endpoint = urlparse(full_url)
                        parsed_base = urlparse(base_url)
                        if parsed_endpoint.netloc == parsed_base.netloc:
                            discovered_endpoints.append(full_url)
                
            except Exception:
                continue
    
    return list(set(discovered_endpoints))


def _identify_attack_surfaces(self, crawl_result: CrawlResult, base_url: str) -> List[AttackSurface]:
    """
    Phase 2: Identify Attack Surfaces
    Convert discovered elements into testable attack surfaces.
    """
    surfaces = []
    
    # 1. Forms as attack surfaces
    for form in crawl_result.forms:
        action = form.action if form.action else base_url
        if not action.startswith(('http://', 'https://')):
            action = urljoin(base_url, action)
        
        surface = AttackSurface(
            url=action,
            surface_type="form",
            parameters=form.fields,
            method=form.method,
            metadata={"enctype": form.enctype}
        )
        surfaces.append(surface)
    
    # 2. URL parameters as attack surfaces
    for url in crawl_result.discovered_urls:
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            param_dict = {k: v[0] if v else "" for k, v in params.items()}
            
            surface = AttackSurface(
                url=url,
                surface_type="url_param",
                parameters=param_dict,
                method="GET",
                metadata={}
            )
            surfaces.append(surface)
    
    # 3. API endpoints from JS as attack surfaces
    for endpoint in crawl_result.api_endpoints:
        surface = AttackSurface(
            url=endpoint,
            surface_type="js_endpoint",
            parameters={},
            method="GET",
            metadata={"source": "javascript"}
        )
        surfaces.append(surface)
    
    return surfaces


async def _fuzz_attack_surface(
    self, 
    surface: AttackSurface, 
    config: ScanConfig,
    baseline_has_errors: bool
) -> List[Vulnerability]:
    """
    Phase 3: Active Fuzzing
    Test an attack surface with various payloads.
    """
    vulnerabilities = []
    
    # Test with SSTI payloads
    ssti_vulns = await self._test_surface_ssti(surface, baseline_has_errors)
    vulnerabilities.extend(ssti_vulns)
    
    # Test with command injection payloads
    cmd_vulns = await self._test_surface_command_injection(surface)
    vulnerabilities.extend(cmd_vulns)
    
    # Test with time-based payloads
    time_vulns = await self._test_surface_time_based(surface)
    vulnerabilities.extend(time_vulns)
    
    return vulnerabilities


async def _test_surface_ssti(
    self, 
    surface: AttackSurface,
    baseline_has_errors: bool
) -> List[Vulnerability]:
    """Test attack surface for SSTI vulnerabilities."""
    vulnerabilities = []
    
    if not surface.parameters:
        # No parameters to test
        return vulnerabilities
    
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        for param_name in list(surface.parameters.keys())[:5]:  # Limit params tested
            for ptype, payload, expected in self.ssti_payloads[:3]:  # Limit payloads
                test_params = surface.parameters.copy()
                test_params[param_name] = payload
                
                try:
                    if surface.method == "POST":
                        if surface.metadata.get("enctype") == "application/json":
                            resp = await client.post(surface.url, json=test_params)
                        else:
                            resp = await client.post(surface.url, data=test_params)
                    else:
                        resp = await client.get(surface.url, params=test_params)
                    
                    analysis = self._analyze_ssti_response(resp.text, expected)
                    
                    if analysis["is_vulnerable"]:
                        if baseline_has_errors:
                            analysis["confidence"] *= 0.8
                        
                        severity = SeverityLevel.CRITICAL if "sentinel_evaluated" in analysis["indicators"] else SeverityLevel.HIGH
                        
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"SSTI in {surface.surface_type} parameter '{param_name}'",
                                description=(
                                    f"Parameter '{param_name}' in {surface.surface_type} appears to be evaluated "
                                    "by a server-side template engine, indicating a potential RCE vector."
                                ),
                                severity=severity,
                                confidence=analysis["confidence"],
                                affected_urls=[surface.url],
                                evidence={
                                    "surface_type": surface.surface_type,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "payload_type": ptype,
                                    "expected": expected,
                                    "indicators": analysis.get("indicators", []),
                                    "engine_guess": analysis.get("engine_guess"),
                                    "response_snippet": resp.text[:500] if resp.text else "",
                                    "method": surface.method,
                                },
                                **self.SSTI_VULN_TEMPLATE
                            )
                        )
                        break  # Stop testing this param after finding vuln
                
                except Exception:
                    continue
    
    return vulnerabilities


async def _test_surface_command_injection(self, surface: AttackSurface) -> List[Vulnerability]:
    """Test attack surface for command injection vulnerabilities."""
    vulnerabilities = []
    
    if not surface.parameters:
        return vulnerabilities
    
    # Command injection indicators in response
    cmd_indicators = [
        "root:", "bin/bash", "uid=", "gid=", "groups=",
        "Windows", "Volume Serial Number", "Directory of"
    ]
    
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        for param_name in list(surface.parameters.keys())[:3]:
            for payload in self.rce_payload_categories["command_injection"][:3]:
                test_params = surface.parameters.copy()
                test_params[param_name] = payload
                
                try:
                    if surface.method == "POST":
                        resp = await client.post(surface.url, data=test_params)
                    else:
                        resp = await client.get(surface.url, params=test_params)
                    
                    # Check for command execution indicators
                    response_text = resp.text.lower() if resp.text else ""
                    matched_indicators = [ind for ind in cmd_indicators if ind.lower() in response_text]
                    
                    if matched_indicators:
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"Potential Command Injection in {surface.surface_type} parameter '{param_name}'",
                                description=(
                                    f"Parameter '{param_name}' may be vulnerable to command injection. "
                                    "Response contains command execution indicators."
                                ),
                                severity=SeverityLevel.CRITICAL,
                                confidence=0.85,
                                affected_urls=[surface.url],
                                evidence={
                                    "surface_type": surface.surface_type,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "indicators": matched_indicators,
                                    "response_snippet": resp.text[:500] if resp.text else "",
                                    "method": surface.method,
                                },
                                remediation=(
                                    "Never pass user input directly to system commands. "
                                    "Use parameterized APIs, input validation, and sandboxing."
                                ),
                                references=[
                                    "https://owasp.org/www-community/attacks/Command_Injection",
                                    "https://cwe.mitre.org/data/definitions/78.html",
                                ],
                                cwe_ids=["CWE-78"],
                            )
                        )
                        break
                
                except Exception:
                    continue
    
    return vulnerabilities


async def _test_surface_time_based(self, surface: AttackSurface) -> List[Vulnerability]:
    """Test attack surface for time-based vulnerabilities."""
    vulnerabilities = []
    
    if not surface.parameters:
        return vulnerabilities
    
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        for param_name in list(surface.parameters.keys())[:2]:
            # Get baseline timing
            baseline_times = []
            for _ in range(2):
                try:
                    start = time.time()
                    if surface.method == "POST":
                        await client.post(surface.url, data=surface.parameters)
                    else:
                        await client.get(surface.url, params=surface.parameters)
                    baseline_times.append(time.time() - start)
                except Exception:
                    continue
            
            if not baseline_times:
                continue
            
            avg_baseline = sum(baseline_times) / len(baseline_times)
            
            # Test time-based payloads
            for payload in self.rce_payload_categories["time_based"][:2]:
                test_params = surface.parameters.copy()
                test_params[param_name] = payload
                
                try:
                    start = time.time()
                    if surface.method == "POST":
                        await client.post(surface.url, data=test_params)
                    else:
                        await client.get(surface.url, params=test_params)
                    elapsed = time.time() - start
                    
                    # Check if response was significantly delayed
                    if elapsed > (avg_baseline + 4.5):  # At least 4.5 seconds delay
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"Time-Based Injection in {surface.surface_type} parameter '{param_name}'",
                                description=(
                                    f"Parameter '{param_name}' exhibits time-based behavior indicating "
                                    "potential SQL injection or command injection vulnerability."
                                ),
                                severity=SeverityLevel.HIGH,
                                confidence=0.75,
                                affected_urls=[surface.url],
                                evidence={
                                    "surface_type": surface.surface_type,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "baseline_time": f"{avg_baseline:.2f}s",
                                    "delayed_time": f"{elapsed:.2f}s",
                                    "delay_difference": f"{elapsed - avg_baseline:.2f}s",
                                    "method": surface.method,
                                },
                                remediation=(
                                    "Use parameterized queries for databases. "
                                    "Validate and sanitize all user input. "
                                    "Implement proper error handling without exposing timing information."
                                ),
                                references=[
                                    "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                                    "https://cwe.mitre.org/data/definitions/89.html",
                                ],
                                cwe_ids=["CWE-89", "CWE-78"],
                            )
                        )
                        break
                
                except Exception:
                    continue
    
    return vulnerabilities


async def _generate_comprehensive_report(
    self,
    crawl_result: CrawlResult,
    attack_surfaces: List[AttackSurface],
    vulnerabilities: List[Vulnerability]
) -> Dict[str, Any]:
    """
    Phase 4: Generate comprehensive report with all findings.
    """
    report = {
        "discovery_phase": {
            "urls_discovered": len(crawl_result.discovered_urls),
            "forms_found": len(crawl_result.forms),
            "url_parameters_found": len(crawl_result.url_parameters),
            "js_files_analyzed": len(crawl_result.js_files),
            "api_endpoints_discovered": len(crawl_result.api_endpoints),
        },
        "attack_surface_phase": {
            "total_surfaces": len(attack_surfaces),
            "surface_types": {},
        },
        "testing_phase": {
            "vulnerabilities_found": len(vulnerabilities),
            "by_severity": {},
            "by_type": {},
        },
        "discovered_urls": list(crawl_result.discovered_urls)[:50],  # Limit for report size
        "api_endpoints": crawl_result.api_endpoints[:20],
    }
    
    # Count surface types
    for surface in attack_surfaces:
        stype = surface.surface_type
        report["attack_surface_phase"]["surface_types"][stype] = \
            report["attack_surface_phase"]["surface_types"].get(stype, 0) + 1
    
    # Count vulnerabilities by severity
    for vuln in vulnerabilities:
        severity = vuln.severity.value
        report["testing_phase"]["by_severity"][severity] = \
            report["testing_phase"]["by_severity"].get(severity, 0) + 1
        
        # Extract vulnerability type from name
        vuln_type = vuln.name.split()[0]  # First word usually indicates type
        report["testing_phase"]["by_type"][vuln_type] = \
            report["testing_phase"]["by_type"].get(vuln_type, 0) + 1
    
    return report
