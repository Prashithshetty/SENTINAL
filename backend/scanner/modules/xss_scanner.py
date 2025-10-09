"""Enhanced XSS Scanner with Playwright-based crawling and JavaScript analysis."""

import asyncio
import re
import time
import httpx
from typing import Dict, List, Any, Set, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse, urlencode
from bs4 import BeautifulSoup
import logging
import json
from playwright.async_api import async_playwright, Browser, Page, TimeoutError as PlaywrightTimeout

from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class XSSScanner(BaseScannerModule):
    """Advanced XSS Scanner with browser-based crawling and JS analysis."""
    
    def __init__(self):
        super().__init__()
        self.name = "XSSScanner"
        self.description = "Detects XSS vulnerabilities using browser automation and JS analysis"
        self.scan_type = ScanType.ACTIVE
        
        # Tracking sets
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.js_files: Set[str] = set()
        self.tested_params: Set[str] = set()
        
        # XSS payloads for testing
        self.xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg/onload=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            "'><img src=x onerror=alert('XSS')>",
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')">',
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            '<select onfocus=alert("XSS") autofocus>',
            '<textarea onfocus=alert("XSS") autofocus>',
            '<img src=x:alert(alt) onerror=eval(src) alt=XSS>',
            '"><img src=x onerror="alert(String.fromCharCode(88,83,83))">',
        ]
        
        # Dangerous JS patterns to look for
        self.dangerous_patterns = [
            # Direct DOM manipulation
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
            
            # Eval and similar
            r'\beval\s*\(',
            r'setTimeout\s*\(\s*["\']',
            r'setInterval\s*\(\s*["\']',
            r'Function\s*\(',
            
            # Location manipulation
            r'location\s*=',
            r'location\.href\s*=',
            r'location\.replace\s*\(',
            r'location\.assign\s*\(',
            
            # URL parameters without sanitization
            r'location\.search',
            r'location\.hash',
            r'document\.URL',
            r'document\.documentURI',
            r'document\.referrer',
            
            # jQuery dangerous methods
            r'\$\([^)]*\)\.html\s*\(',
            r'\$\([^)]*\)\.append\s*\(',
            r'\$\([^)]*\)\.prepend\s*\(',
            r'\$\([^)]*\)\.after\s*\(',
            r'\$\([^)]*\)\.before\s*\(',
            
            # Angular/React unsafe patterns
            r'dangerouslySetInnerHTML',
            r'\[innerHTML\]',
            r'v-html',
        ]
    
    def validate_target(self, target: str) -> bool:
        """Validate target URL."""
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        try:
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform comprehensive XSS scan."""
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        
        info = {
            'crawl_enabled': True,
            'urls_discovered': 0,
            'js_files_analyzed': 0,
            'forms_tested': 0,
            'parameters_tested': 0,
            'dangerous_js_patterns_found': 0
        }
        
        statistics = {
            'pages_crawled': 0,
            'urls_tested': 0,
            'vulnerabilities_found': 0
        }
        
        try:
            target_url = config.target
            if not target_url.startswith(('http://', 'https://')):
                target_url = f"https://{target_url}"
            
            print(f"\n{'='*70}")
            print(f"🔍 Starting Enhanced XSS Scan")
            print(f"{'='*70}")
            print(f"Target: {target_url}")
            print(f"Scan Type: {config.scan_type.value}")
            print(f"Max Depth: {config.max_depth}")
            print(f"{'='*70}\n")
            
            # Determine crawl depth based on scan type
            max_depth = self._get_max_depth(config)
            max_pages = self._get_max_pages(config)
            
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                
                try:
                    # Phase 1: Crawl and discover
                    print("📡 Phase 1: Crawling and Discovery")
                    print("-" * 70)
                    await self._crawl_website(browser, target_url, max_depth, max_pages)
                    
                    info['urls_discovered'] = len(self.discovered_urls)
                    statistics['pages_crawled'] = len(self.visited_urls)
                    print(f"✓ Discovered {len(self.discovered_urls)} URLs")
                    print(f"✓ Found {len(self.js_files)} JavaScript files\n")
                    
                    # Phase 2: Analyze JavaScript files
                    print("🔬 Phase 2: JavaScript Analysis")
                    print("-" * 70)
                    js_vulns = await self._analyze_javascript_files()
                    vulnerabilities.extend(js_vulns)
                    info['js_files_analyzed'] = len(self.js_files)
                    info['dangerous_js_patterns_found'] = len(js_vulns)
                    print(f"✓ Analyzed {len(self.js_files)} JS files")
                    print(f"✓ Found {len(js_vulns)} potential JS vulnerabilities\n")
                    
                    # Phase 3: Test for XSS
                    print("🎯 Phase 3: XSS Payload Testing")
                    print("-" * 70)
                    xss_vulns = await self._test_xss_vulnerabilities(browser, config)
                    vulnerabilities.extend(xss_vulns)
                    info['forms_tested'] = len(self.tested_params)
                    statistics['urls_tested'] = len(self.visited_urls)
                    print(f"✓ Tested {len(self.tested_params)} parameters")
                    print(f"✓ Found {len(xss_vulns)} confirmed XSS vulnerabilities\n")
                    
                finally:
                    await browser.close()
            
            statistics['vulnerabilities_found'] = len(vulnerabilities)
            
            print(f"{'='*70}")
            print(f"✅ Scan Complete!")
            print(f"{'='*70}")
            print(f"Total Vulnerabilities: {len(vulnerabilities)}")
            print(f"  - Critical: {sum(1 for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL)}")
            print(f"  - High: {sum(1 for v in vulnerabilities if v.severity == SeverityLevel.HIGH)}")
            print(f"  - Medium: {sum(1 for v in vulnerabilities if v.severity == SeverityLevel.MEDIUM)}")
            print(f"  - Low: {sum(1 for v in vulnerabilities if v.severity == SeverityLevel.LOW)}")
            print(f"{'='*70}\n")
            
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            errors.append(error_msg)
            logger.error(error_msg)
            import traceback
            traceback.print_exc()
        
        return ScanResult(
            module_name=self.name,
            success=len(errors) == 0,
            started_at=started_at,
            completed_at=datetime.utcnow(),
            vulnerabilities=vulnerabilities,
            errors=errors,
            warnings=[],
            info=info,
            statistics=statistics
        )
    
    def _get_max_depth(self, config: ScanConfig) -> int:
        """Get max crawl depth based on scan type."""
        if config.scan_type == ScanType.PASSIVE:
            return 1
        elif config.scan_type == ScanType.ACTIVE:
            return min(config.max_depth, 3)
        else:  # AGGRESSIVE
            return min(config.max_depth, 5)
    
    def _get_max_pages(self, config: ScanConfig) -> int:
        """Get max pages to crawl based on scan type."""
        if config.scan_type == ScanType.PASSIVE:
            return 10
        elif config.scan_type == ScanType.ACTIVE:
            return 50
        else:  # AGGRESSIVE
            return 100
    
    async def _crawl_website(self, browser: Browser, start_url: str, max_depth: int, max_pages: int):
        """Crawl website to discover URLs and JS files."""
        base_domain = urlparse(start_url).netloc
        to_visit = [(start_url, 0)]  # (url, depth)
        
        while to_visit and len(self.visited_urls) < max_pages:
            url, depth = to_visit.pop(0)
            
            if url in self.visited_urls or depth > max_depth:
                continue
            
            # Skip non-HTTP URLs
            if not url.startswith(('http://', 'https://')):
                continue
            
            # Stay on same domain
            if urlparse(url).netloc != base_domain:
                continue
            
            try:
                print(f"  Crawling [{len(self.visited_urls)+1}/{max_pages}]: {url[:80]}...")
                
                page = await browser.new_page()
                await page.goto(url, wait_until='networkidle', timeout=30000)
                
                self.visited_urls.add(url)
                
                # Extract JavaScript files
                js_urls = await page.evaluate("""
                    () => {
                        const scripts = Array.from(document.querySelectorAll('script[src]'));
                        return scripts.map(s => s.src);
                    }
                """)
                
                for js_url in js_urls:
                    if js_url and js_url.startswith(('http://', 'https://')):
                        self.js_files.add(js_url)
                
                # Extract links
                links = await page.evaluate("""
                    () => {
                        const links = Array.from(document.querySelectorAll('a[href]'));
                        return links.map(a => a.href);
                    }
                """)
                
                for link in links:
                    if link and link.startswith(('http://', 'https://')):
                        full_url = urljoin(url, link)
                        if full_url not in self.visited_urls and full_url not in [u for u, _ in to_visit]:
                            self.discovered_urls.add(full_url)
                            if depth < max_depth:
                                to_visit.append((full_url, depth + 1))
                
                # Extract forms and inputs
                forms = await page.evaluate("""
                    () => {
                        const forms = Array.from(document.querySelectorAll('form'));
                        return forms.map(form => ({
                            action: form.action,
                            method: form.method,
                            inputs: Array.from(form.querySelectorAll('input, textarea, select')).map(input => ({
                                name: input.name,
                                type: input.type,
                                id: input.id
                            }))
                        }));
                    }
                """)
                
                # Store forms for testing
                for form in forms:
                    if form.get('inputs'):
                        for inp in form['inputs']:
                            if inp.get('name'):
                                self.tested_params.add(f"{url}#{inp['name']}")
                
                await page.close()
                
                # Rate limiting
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.debug(f"Error crawling {url}: {e}")
                continue
    
    async def _analyze_javascript_files(self) -> List[Vulnerability]:
        """Analyze JavaScript files for dangerous patterns."""
        vulnerabilities = []
        
        async with httpx.AsyncClient(verify=False, timeout=15.0, follow_redirects=True) as client:
            for js_url in list(self.js_files)[:20]:  # Limit to first 20 JS files
                try:
                    print(f"  Analyzing: {js_url[:80]}...")
                    response = await client.get(js_url)
                    
                    if response.status_code == 200:
                        js_content = response.text
                        
                        # Check for dangerous patterns
                        found_patterns = []
                        for pattern in self.dangerous_patterns:
                            matches = re.finditer(pattern, js_content, re.IGNORECASE)
                            for match in matches:
                                # Get context around the match
                                start = max(0, match.start() - 50)
                                end = min(len(js_content), match.end() + 50)
                                context = js_content[start:end]
                                
                                found_patterns.append({
                                    'pattern': pattern,
                                    'match': match.group(),
                                    'context': context.strip()
                                })
                        
                        if found_patterns:
                            # Create vulnerability for dangerous JS patterns
                            vuln = Vulnerability(
                                module=self.name,
                                name=f"Potentially Unsafe JavaScript Pattern in {js_url.split('/')[-1]}",
                                description=f"Found {len(found_patterns)} potentially dangerous JavaScript patterns that could lead to XSS vulnerabilities if user input is not properly sanitized.",
                                severity=SeverityLevel.MEDIUM,
                                confidence=0.6,
                                affected_urls=[js_url],
                                evidence={
                                    'js_file': js_url,
                                    'patterns_found': len(found_patterns),
                                    'dangerous_patterns': found_patterns[:5]  # Limit to first 5
                                },
                                remediation="Review the JavaScript code to ensure all user input is properly sanitized before being used in DOM manipulation, eval(), or other dangerous operations. Use Content Security Policy to mitigate XSS risks.",
                                references=[
                                    "https://owasp.org/www-community/attacks/xss/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"
                                ],
                                cwe_ids=["CWE-79", "CWE-94"]
                            )
                            vulnerabilities.append(vuln)
                            print(f"    ⚠️  Found {len(found_patterns)} dangerous patterns")
                
                except Exception as e:
                    logger.debug(f"Error analyzing {js_url}: {e}")
        
        return vulnerabilities
    
    async def _test_xss_vulnerabilities(self, browser: Browser, config: ScanConfig) -> List[Vulnerability]:
        """Test discovered URLs and forms for XSS vulnerabilities."""
        vulnerabilities = []
        
        # Test URLs with query parameters
        urls_to_test = [url for url in self.discovered_urls if '?' in url or '#' in url]
        urls_to_test = urls_to_test[:30]  # Limit testing
        
        for url in urls_to_test:
            try:
                vulns = await self._test_url_for_xss(browser, url)
                vulnerabilities.extend(vulns)
            except Exception as e:
                logger.debug(f"Error testing {url}: {e}")
        
        # Test common endpoints
        base_url = config.target
        if not base_url.startswith(('http://', 'https://')):
            base_url = f"https://{base_url}"
        
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Common vulnerable endpoints
        test_endpoints = [
            '/search?q=',
            '/#/search?q=',
            '/api/Products/search?q=',
            '/rest/products/search?q=',
            '/profile?name=',
            '/user?id=',
        ]
        
        for endpoint in test_endpoints:
            test_url = f"{base}{endpoint}"
            try:
                vulns = await self._test_url_for_xss(browser, test_url)
                vulnerabilities.extend(vulns)
            except Exception as e:
                logger.debug(f"Error testing {test_url}: {e}")
        
        return vulnerabilities
    
    async def _test_url_for_xss(self, browser: Browser, url: str) -> List[Vulnerability]:
        """Test a specific URL for XSS vulnerabilities."""
        vulnerabilities = []
        
        # Parse URL to get parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # Try to add a test parameter
            separator = '&' if '?' in url else '?'
            params = {'q': ['test']}
            url = f"{url}{separator}q=test"
        
        # Test each parameter with XSS payloads
        for param_name in params.keys():
            for payload in self.xss_payloads[:5]:  # Test with first 5 payloads
                try:
                    # Create test URL with payload
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        parsed.fragment
                    ))
                    
                    print(f"  Testing: {test_url[:100]}...")
                    
                    # Test with browser
                    page = await browser.new_page()
                    
                    # Set up alert detection
                    alert_detected = False
                    
                    async def handle_dialog(dialog):
                        nonlocal alert_detected
                        alert_detected = True
                        await dialog.dismiss()
                    
                    page.on('dialog', handle_dialog)
                    
                    try:
                        await page.goto(test_url, wait_until='load', timeout=10000)
                        await asyncio.sleep(1)  # Wait for any delayed execution
                        
                        # Check if alert was triggered
                        if alert_detected:
                            print(f"    🚨 XSS CONFIRMED! Alert triggered")
                            
                            vuln = Vulnerability(
                                module=self.name,
                                name=f"Confirmed Cross-Site Scripting (XSS) in '{param_name}' parameter",
                                description=f"The application is vulnerable to XSS attacks. The parameter '{param_name}' accepts and executes malicious JavaScript code without proper sanitization.",
                                severity=SeverityLevel.HIGH,
                                confidence=0.95,
                                affected_urls=[url],
                                evidence={
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'poc_url': test_url,
                                    'alert_triggered': True
                                },
                                remediation="Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers. Consider using a web application firewall (WAF).",
                                references=[
                                    "https://owasp.org/www-community/attacks/xss/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                                ],
                                cwe_ids=["CWE-79"]
                            )
                            vulnerabilities.append(vuln)
                            await page.close()
                            break  # Found XSS, move to next parameter
                        
                        # Also check if payload is reflected in page content
                        content = await page.content()
                        if payload in content:
                            print(f"    ⚠️  Payload reflected in response")
                            
                            vuln = Vulnerability(
                                module=self.name,
                                name=f"Reflected XSS in '{param_name}' parameter",
                                description=f"The parameter '{param_name}' reflects user input without proper encoding. This could lead to XSS attacks.",
                                severity=SeverityLevel.MEDIUM,
                                confidence=0.75,
                                affected_urls=[url],
                                evidence={
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'poc_url': test_url,
                                    'reflected': True
                                },
                                remediation="Implement proper output encoding for all user input. Use Content Security Policy headers.",
                                references=["https://owasp.org/www-community/attacks/xss/"],
                                cwe_ids=["CWE-79"]
                            )
                            vulnerabilities.append(vuln)
                    
                    except PlaywrightTimeout:
                        logger.debug(f"Timeout testing {test_url}")
                    
                    await page.close()
                    
                except Exception as e:
                    logger.debug(f"Error testing payload on {url}: {e}")
        
        return vulnerabilities


# Example usage
async def main():
    """Test the scanner."""
    scanner = XSSScanner()
    config = ScanConfig(
        target="https://juice-shop.herokuapp.com",
        scan_type=ScanType.ACTIVE,
        max_depth=2,
        debug=True
    )
    
    result = await scanner.scan(config)
    
    print(f"\n{'='*70}")
    print(f"DETAILED RESULTS")
    print(f"{'='*70}\n")
    
    if result.vulnerabilities:
        for i, vuln in enumerate(result.vulnerabilities, 1):
            print(f"[{i}] {vuln.name}")
            print(f"    Severity: {vuln.severity.value.upper()}")
            print(f"    Confidence: {vuln.confidence:.0%}")
            if vuln.affected_urls:
                print(f"    URL: {vuln.affected_urls[0]}")
            if 'parameter' in vuln.evidence:
                print(f"    Parameter: {vuln.evidence['parameter']}")
            if 'payload' in vuln.evidence:
                print(f"    Payload: {vuln.evidence['payload'][:60]}...")
            if 'poc_url' in vuln.evidence:
                print(f"    PoC: {vuln.evidence['poc_url'][:80]}...")
            print()
    else:
        print("No vulnerabilities found.")

if __name__ == "__main__":
    asyncio.run(main())
