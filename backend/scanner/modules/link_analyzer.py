"""
Enhanced Link Analyzer with Web Crawling Capabilities - Industry Standard
Includes: Reputation APIs, Vulnerability Probes, Advanced Crawling, Security Analysis
"""
import validators
import whois
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, quote
from typing import Set, List, Dict, Any, Optional, Callable
import requests
from bs4 import BeautifulSoup
import re
import asyncio
from collections import deque
import hashlib
import json
from urllib.robotparser import RobotFileParser
import warnings

# Suppress SSL warnings for security testing
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class ReputationChecker:
    """Handles all reputation API checks"""
    
    def __init__(self, api_keys: Dict[str, str] = None):
        self.api_keys = api_keys or {}
        self.timeout = 10
        
    async def check_google_safe_browsing(self, url: str) -> Dict[str, Any]:
        """Check URL against Google Safe Browsing API"""
        if 'google_safe_browsing' not in self.api_keys:
            return {'checked': False, 'reason': 'API key not provided'}
        
        try:
            api_key = self.api_keys['google_safe_browsing']
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
            
            payload = {
                "client": {
                    "clientId": "sentinel-scanner",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(endpoint, json=payload, timeout=self.timeout)
            result = response.json()
            
            if 'matches' in result and result['matches']:
                return {
                    'checked': True,
                    'safe': False,
                    'threats': [match['threatType'] for match in result['matches']],
                    'risk_increase': 50
                }
            
            return {'checked': True, 'safe': True, 'threats': [], 'risk_increase': 0}
            
        except Exception as e:
            return {'checked': False, 'error': str(e)}
    
    async def check_virustotal(self, url: str) -> Dict[str, Any]:
        """Check URL against VirusTotal API"""
        if 'virustotal' not in self.api_keys:
            return {'checked': False, 'reason': 'API key not provided'}
        
        try:
            api_key = self.api_keys['virustotal']
            
            # VirusTotal v3 API
            headers = {'x-apikey': api_key}
            url_id = hashlib.sha256(url.encode()).hexdigest()
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            # First, try to get existing report
            response = requests.get(endpoint, headers=headers, timeout=self.timeout)
            
            if response.status_code == 404:
                # Submit URL for scanning
                scan_endpoint = "https://www.virustotal.com/api/v3/urls"
                scan_response = requests.post(
                    scan_endpoint,
                    headers=headers,
                    data={'url': url},
                    timeout=self.timeout
                )
                return {'checked': True, 'status': 'submitted_for_scan', 'risk_increase': 0}
            
            result = response.json()
            stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            total_scans = sum(stats.values()) if stats else 0
            
            risk_increase = 0
            if malicious_count > 0:
                risk_increase = min(malicious_count * 5, 40)
            elif suspicious_count > 0:
                risk_increase = min(suspicious_count * 2, 15)
            
            return {
                'checked': True,
                'safe': malicious_count == 0,
                'malicious_count': malicious_count,
                'suspicious_count': suspicious_count,
                'total_scans': total_scans,
                'risk_increase': risk_increase
            }
            
        except Exception as e:
            return {'checked': False, 'error': str(e)}
    
    async def check_urlscan(self, url: str) -> Dict[str, Any]:
        """Check URL against URLScan.io"""
        try:
            # First, search for existing scans
            search_endpoint = "https://urlscan.io/api/v1/search/"
            search_params = {
                'q': f'page.url:"{url}"'
            }
            
            headers = {'User-Agent': 'SENTINEL-Scanner/1.0'}
            if 'urlscan' in self.api_keys:
                headers['API-Key'] = self.api_keys['urlscan']
            
            # Search for existing scans
            search_response = requests.get(
                search_endpoint,
                params=search_params,
                headers=headers,
                timeout=self.timeout
            )
            
            search_result = search_response.json()
            
            # Check if URL has been scanned before
            if search_result.get('results') and len(search_result['results']) > 0:
                latest_scan = search_result['results'][0]
                verdicts = latest_scan.get('verdicts', {})
                
                # Analyze verdicts
                overall_malicious = verdicts.get('overall', {}).get('malicious', False)
                urlscan_malicious = verdicts.get('urlscan', {}).get('malicious', False)
                engines_malicious = verdicts.get('engines', {}).get('malicious', False)
                community_malicious = verdicts.get('community', {}).get('malicious', False)
                
                is_malicious = any([overall_malicious, urlscan_malicious, 
                                   engines_malicious, community_malicious])
                
                risk_increase = 0
                if overall_malicious:
                    risk_increase = 45
                elif urlscan_malicious or engines_malicious:
                    risk_increase = 30
                elif community_malicious:
                    risk_increase = 15
                
                return {
                    'checked': True,
                    'safe': not is_malicious,
                    'malicious': is_malicious,
                    'verdicts': verdicts,
                    'scan_id': latest_scan.get('_id'),
                    'result_url': latest_scan.get('result'),
                    'risk_increase': risk_increase
                }
            else:
                # Submit URL for scanning if API key is available
                if 'urlscan' in self.api_keys:
                    submit_endpoint = "https://urlscan.io/api/v1/scan/"
                    submit_data = {
                        'url': url,
                        'visibility': 'public'
                    }
                    
                    submit_response = requests.post(
                        submit_endpoint,
                        json=submit_data,
                        headers=headers,
                        timeout=self.timeout
                    )
                    
                    submit_result = submit_response.json()
                    
                    return {
                        'checked': True,
                        'status': 'submitted_for_scan',
                        'scan_id': submit_result.get('uuid'),
                        'result_url': submit_result.get('result'),
                        'risk_increase': 0
                    }
                else:
                    return {
                        'checked': True,
                        'status': 'no_existing_scan',
                        'message': 'No previous scan found. Provide API key to submit for scanning.',
                        'risk_increase': 0
                    }
            
        except Exception as e:
            return {'checked': False, 'error': str(e)}
    
    async def check_alienvault_otx(self, url: str) -> Dict[str, Any]:
        """Check URL against AlienVault OTX"""
        try:
            domain = urlparse(url).netloc
            
            # AlienVault OTX API
            endpoint = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
            
            headers = {}
            if 'alienvault_otx' in self.api_keys:
                headers['X-OTX-API-KEY'] = self.api_keys['alienvault_otx']
            
            response = requests.get(endpoint, headers=headers, timeout=self.timeout)
            result = response.json()
            
            pulse_count = result.get('pulse_info', {}).get('count', 0)
            
            # Check if domain appears in threat intelligence pulses
            risk_increase = 0
            if pulse_count > 0:
                # More pulses = higher risk
                risk_increase = min(pulse_count * 3, 35)
            
            return {
                'checked': True,
                'safe': pulse_count == 0,
                'pulse_count': pulse_count,
                'risk_increase': risk_increase
            }
            
        except Exception as e:
            return {'checked': False, 'error': str(e)}


class VulnerabilityProber:
    """Active vulnerability detection probes"""
    
    def __init__(self):
        self.timeout = 10
        
    async def check_open_redirect(self, url: str) -> Dict[str, Any]:
        """Check for open redirect vulnerabilities"""
        results = {
            'vulnerable': False,
            'tested_parameters': [],
            'vulnerable_parameters': [],
            'details': []
        }
        
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            # Common redirect parameters
            redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'redir', 
                             'destination', 'continue', 'return_to', 'callback']
            
            # Test payloads
            test_payloads = [
                'https://evil.com',
                '//evil.com',
                '///evil.com',
                'https://evil.com@legitimate.com',
                'javascript:alert(1)'
            ]
            
            for param in redirect_params:
                if param in query_params or not query_params:
                    results['tested_parameters'].append(param)
                    
                    for payload in test_payloads:
                        # Build test URL
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                        if query_params:
                            # Replace parameter value
                            test_params = query_params.copy()
                            test_params[param] = [payload]
                            test_url += '?' + '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                        else:
                            test_url += f"?{param}={quote(payload)}"
                        
                        try:
                            response = requests.get(
                                test_url,
                                allow_redirects=False,
                                timeout=self.timeout,
                                verify=False
                            )
                            
                            # Check if redirect location contains our payload
                            if response.status_code in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location', '')
                                if 'evil.com' in location or 'javascript:' in location.lower():
                                    results['vulnerable'] = True
                                    results['vulnerable_parameters'].append(param)
                                    results['details'].append({
                                        'parameter': param,
                                        'payload': payload,
                                        'redirect_to': location
                                    })
                                    break
                                    
                        except Exception:
                            continue
                            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    async def check_header_injection(self, url: str) -> Dict[str, Any]:
        """Check for HTTP header injection (CRLF) vulnerabilities"""
        results = {
            'vulnerable': False,
            'tested_parameters': [],
            'vulnerable_parameters': [],
            'details': []
        }
        
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            # CRLF injection payloads
            crlf_payloads = [
                '%0d%0aX-Injected-Header: injected',
                '%0aX-Injected-Header: injected',
                '%0dX-Injected-Header: injected',
                '\r\nX-Injected-Header: injected',
                '\nX-Injected-Header: injected',
                '%E5%98%8A%E5%98%8DX-Injected-Header: injected'
            ]
            
            for param_name, param_values in query_params.items():
                results['tested_parameters'].append(param_name)
                
                for payload in crlf_payloads:
                    # Build test URL
                    test_params = query_params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    test_url += '?' + '&'.join([f"{k}={v[0]}" for k, v in test_params.items()])
                    
                    try:
                        response = requests.get(
                            test_url,
                            timeout=self.timeout,
                            verify=False,
                            allow_redirects=False
                        )
                        
                        # Check if our injected header appears in response
                        if 'X-Injected-Header' in response.headers or \
                           'x-injected-header' in response.headers:
                            results['vulnerable'] = True
                            results['vulnerable_parameters'].append(param_name)
                            results['details'].append({
                                'parameter': param_name,
                                'payload': payload,
                                'injected_header': response.headers.get('X-Injected-Header', '')
                            })
                            break
                            
                    except Exception:
                        continue
                        
        except Exception as e:
            results['error'] = str(e)
        
        return results


class CSPAnalyzer:
    """Detailed Content Security Policy analysis"""
    
    @staticmethod
    def analyze_csp(csp_header: str) -> Dict[str, Any]:
        """Analyze CSP header for security issues"""
        results = {
            'has_csp': True,
            'directives': {},
            'issues': [],
            'risk_score': 0
        }
        
        if not csp_header:
            results['has_csp'] = False
            results['issues'].append("No CSP header present")
            results['risk_score'] = 15
            return results
        
        # Parse CSP directives
        directives = {}
        for directive in csp_header.split(';'):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            if parts:
                directives[parts[0]] = parts[1:] if len(parts) > 1 else []
        
        results['directives'] = directives
        
        # Check for unsafe directives
        unsafe_checks = {
            'default-src': ['*', 'unsafe-inline', 'unsafe-eval'],
            'script-src': ['*', 'unsafe-inline', 'unsafe-eval', 'data:'],
            'style-src': ['*', 'unsafe-inline'],
            'object-src': ['*'],
            'base-uri': ['*']
        }
        
        for directive, unsafe_values in unsafe_checks.items():
            if directive in directives:
                directive_values = directives[directive]
                for unsafe_val in unsafe_values:
                    if any(unsafe_val in val for val in directive_values):
                        results['issues'].append(
                            f"Unsafe '{unsafe_val}' in {directive}"
                        )
                        results['risk_score'] += 10 if unsafe_val == '*' else 5
        
        # Check for missing important directives
        important_directives = ['default-src', 'script-src', 'object-src', 'base-uri']
        for directive in important_directives:
            if directive not in directives:
                results['issues'].append(f"Missing important directive: {directive}")
                results['risk_score'] += 3
        
        # Check for deprecated directives
        deprecated = ['block-all-mixed-content', 'plugin-types', 'referrer']
        for directive in deprecated:
            if directive in directives:
                results['issues'].append(f"Using deprecated directive: {directive}")
        
        return results


class LinkAnalyzer:
    def __init__(self, api_keys: Dict[str, str] = None, 
                 integration_callbacks: Dict[str, Callable] = None):
        """
        Initialize LinkAnalyzer with API keys and integration callbacks.
        
        Args:
            api_keys: Dictionary of API keys for reputation services
            integration_callbacks: Dictionary of callbacks to other scanner modules
        """
        # Categorized TLDs for better risk assessment
        self.tld_categories = {
            'high_risk': ['.xyz', '.top', '.work', '.loan', '.click', '.pw', 
                         '.cc', '.tk', '.ml', '.ga', '.cf', '.gq'],
            'medium_risk': ['.info', '.biz', '.site', '.online', '.website', 
                           '.club', '.live', '.fun'],
            'low_risk': ['.com', '.org', '.net', '.edu', '.gov', '.mil']
        }
        
        # Initialize components
        self.reputation_checker = ReputationChecker(api_keys)
        self.vulnerability_prober = VulnerabilityProber()
        self.csp_analyzer = CSPAnalyzer()
        
        # Integration callbacks
        self.integration_callbacks = integration_callbacks or {}
        
        # Crawler state
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.urls_with_params: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self.robots_parser: Optional[RobotFileParser] = None
        
    def _can_fetch(self, url: str) -> bool:
        """Check if URL can be fetched according to robots.txt"""
        if not self.robots_parser:
            return True
        
        try:
            return self.robots_parser.can_fetch("SENTINEL-Crawler", url)
        except Exception:
            return True
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL to avoid duplicates"""
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

    async def crawl(self, start_url: str, max_depth: int = 3, max_urls: int = 50,
                   respect_robots: bool = False, use_js_rendering: bool = False,
                   integrate_with_scanners: bool = False) -> Dict[str, Any]:
        """
        Crawl a website starting from start_url and discover all URLs in the same domain.
        
        Args:
            start_url: Starting URL to crawl
            max_depth: Maximum depth to crawl (default: 3)
            max_urls: Maximum number of URLs to discover (default: 50)
            respect_robots: Whether to respect robots.txt (default: False)
            use_js_rendering: Use Pyppeteer for JS rendering (default: False)
            integrate_with_scanners: Pass URLs to other scanner modules (default: False)
            
        Returns:
            Dictionary containing discovered URLs, forms, and statistics
        """
        print(f"[*] Starting web crawler for: {start_url}")
        print(f"[*] Max depth: {max_depth}, Max URLs: {max_urls}")
        print(f"[*] Respect robots.txt: {respect_robots}, JS rendering: {use_js_rendering}")
        
        # Reset state
        self.visited_urls.clear()
        self.discovered_urls.clear()
        self.urls_with_params.clear()
        self.forms.clear()
        
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc
        
        # Parse robots.txt if needed
        if respect_robots:
            await self._parse_robots_txt(f"{parsed_start.scheme}://{base_domain}")
        
        # Queue structure: (url, depth)
        queue = deque([(start_url, 0)])
        self.discovered_urls.add(self._normalize_url(start_url))
        
        crawl_stats = {
            'pages_crawled': 0,
            'urls_discovered': 0,
            'forms_found': 0,
            'urls_with_parameters': 0,
            'blocked_by_robots': 0,
            'errors': [],
            'scanner_integrations': {}
        }
        
        while queue and len(self.visited_urls) < max_urls:
            current_url, depth = queue.popleft()
            normalized_url = self._normalize_url(current_url)
            
            # Skip if already visited or depth exceeded
            if normalized_url in self.visited_urls or depth > max_depth:
                continue
            
            # Check robots.txt
            if respect_robots and not self._can_fetch(current_url):
                crawl_stats['blocked_by_robots'] += 1
                print(f"[!] Blocked by robots.txt: {current_url}")
                continue
            
            print(f"[*] Crawling [{depth}/{max_depth}]: {current_url}")
            
            try:
                # Mark as visited
                self.visited_urls.add(normalized_url)
                crawl_stats['pages_crawled'] += 1
                
                # Fetch the page
                if use_js_rendering:
                    html_content = await self._fetch_with_js_rendering(current_url)
                else:
                    response = requests.get(
                        current_url,
                        headers={'User-Agent': 'SENTINEL-Crawler/1.0'},
                        timeout=10,
                        allow_redirects=True
                    )
                    
                    # Only process HTML content
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' not in content_type.lower():
                        continue
                    
                    html_content = response.content
                
                # Parse HTML
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Extract all links
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    absolute_url = urljoin(current_url, href)
                    
                    # Parse and validate URL
                    parsed_url = urlparse(absolute_url)
                    
                    # Only crawl URLs from the same domain
                    if parsed_url.netloc != base_domain:
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
                await asyncio.sleep(0.5)
                
            except requests.exceptions.RequestException as e:
                crawl_stats['errors'].append(f"Error crawling {current_url}: {str(e)}")
                print(f"[!] Error crawling {current_url}: {str(e)}")
            except Exception as e:
                crawl_stats['errors'].append(f"Unexpected error at {current_url}: {str(e)}")
                print(f"[!] Unexpected error at {current_url}: {str(e)}")
        
        # Integrate with other scanner modules if requested
        if integrate_with_scanners:
            crawl_stats['scanner_integrations'] = await self._integrate_with_scanners()
        
        print(f"[+] Crawling complete!")
        print(f"    - Pages crawled: {crawl_stats['pages_crawled']}")
        print(f"    - Total URLs discovered: {len(self.discovered_urls)}")
        print(f"    - URLs with parameters: {len(self.urls_with_params)}")
        print(f"    - Forms found: {len(self.forms)}")
        
        return {
            'start_url': start_url,
            'base_domain': base_domain,
            'discovered_urls': sorted(list(self.discovered_urls)),
            'urls_with_parameters': sorted(list(self.urls_with_params)),
            'forms': self.forms,
            'statistics': crawl_stats
        }
    
    async def _parse_robots_txt(self, base_url: str):
        """Parse robots.txt file for the domain"""
        try:
            self.robots_parser = RobotFileParser()
            robots_url = urljoin(base_url, '/robots.txt')
            self.robots_parser.set_url(robots_url)
            self.robots_parser.read()
            print(f"[+] Parsed robots.txt from {robots_url}")
        except Exception as e:
            print(f"[!] Could not parse robots.txt: {str(e)}")
            self.robots_parser = None
    
    async def _fetch_with_js_rendering(self, url: str) -> bytes:
        """
        Fetch page with JavaScript rendering using Pyppeteer.
        Note: Requires 'pyppeteer' package to be installed.
        """
        try:
            from pyppeteer import launch
            
            browser = await launch(headless=True, args=['--no-sandbox'])
            page = await browser.newPage()
            await page.goto(url, {'waitUntil': 'networkidle0', 'timeout': 30000})
            
            # Wait for any dynamic content
            await asyncio.sleep(2)
            
            content = await page.content()
            await browser.close()
            
            return content.encode('utf-8')
            
        except ImportError:
            print("[!] Pyppeteer not installed. Falling back to regular requests.")
            response = requests.get(url, headers={'User-Agent': 'SENTINEL-Crawler/1.0'}, timeout=10)
            return response.content
        except Exception as e:
            print(f"[!] JS rendering failed: {str(e)}. Falling back to regular requests.")
            response = requests.get(url, headers={'User-Agent': 'SENTINEL-Crawler/1.0'}, timeout=10)
            return response.content
    
    async def _integrate_with_scanners(self) -> Dict[str, Any]:
        """Integrate discovered URLs with other scanner modules"""
        integration_results = {}
        
        # Pass URLs with parameters to XSS scanner
        if 'xss_scanner' in self.integration_callbacks and self.urls_with_params:
            try:
                callback = self.integration_callbacks['xss_scanner']
                xss_results = await callback(list(self.urls_with_params))
                integration_results['xss_scanner'] = {
                    'urls_tested': len(self.urls_with_params),
                    'results': xss_results
                }
                print(f"[+] Integrated {len(self.urls_with_params)} URLs with XSS scanner")
            except Exception as e:
                integration_results['xss_scanner'] = {'error': str(e)}
        
        # Pass URLs with parameters to SQL injection scanner
        if 'sql_injection' in self.integration_callbacks and self.urls_with_params:
            try:
                callback = self.integration_callbacks['sql_injection']
                sql_results = await callback(list(self.urls_with_params))
                integration_results['sql_injection'] = {
                    'urls_tested': len(self.urls_with_params),
                    'results': sql_results
                }
                print(f"[+] Integrated {len(self.urls_with_params)} URLs with SQL injection scanner")
            except Exception as e:
                integration_results['sql_injection'] = {'error': str(e)}
        
        # Pass forms to all scanners
        if self.forms:
            for scanner_name, callback in self.integration_callbacks.items():
                if scanner_name not in integration_results:
                    try:
                        form_results = await callback(self.forms, data_type='forms')
                        integration_results[f'{scanner_name}_forms'] = {
                            'forms_tested': len(self.forms),
                            'results': form_results
                        }
                    except Exception as e:
                        integration_results[f'{scanner_name}_forms'] = {'error': str(e)}
        
        return integration_results
    
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

    async def analyze(self, url: str, check_vulnerabilities: bool = True,
                     check_reputation: bool = True) -> Dict[str, Any]:
        """
        Analyze URL for legitimacy and security concerns with enhanced checks.
        
        Args:
            url: URL to analyze
            check_vulnerabilities: Run active vulnerability probes
            check_reputation: Check reputation APIs
        """
        result = {
            'is_valid_url': False,
            'domain_age': None,
            'ssl_info': {
                'valid': False,
                'cert_chain': [],
                'issues': []
            },
            'domain_info': {},
            'reputation': {
                'score': 0,
                'sources': {}
            },
            'security_headers': {},
            'csp_analysis': {},
            'vulnerabilities': {},
            'redirect_chain': [],
            'risk_score': 0,
            'warnings': [],
            'confidence_level': 'unknown'
        }

        try:
            # Basic URL validation
            if not validators.url(url):
                result['warnings'].append("Invalid URL format")
                return result

            result['is_valid_url'] = True
            parsed_url = urlparse(url)
            domain = parsed_url.netloc

            # Check domain age
            try:
                w = whois.whois(domain)
                if w.creation_date:
                    creation_date = w.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    domain_age = (datetime.now() - creation_date).days
                    result['domain_age'] = domain_age
                    result['domain_info'] = {
                        'registrar': w.registrar,
                        'creation_date': str(w.creation_date),
                        'expiration_date': str(w.expiration_date),
                        'registered_to': w.name
                    }
                    
                    # Check if domain is too new (less than 30 days)
                    if domain_age < 30:
                        result['warnings'].append("Domain is very new")
                        result['risk_score'] += 20
            except Exception as e:
                result['warnings'].append(f"Could not verify domain age: {str(e)}")
                result['risk_score'] += 10

            # Enhanced TLD Check
            tld = '.' + domain.split('.')[-1].lower()
            if tld in self.tld_categories['high_risk']:
                result['warnings'].append(f"High-risk TLD detected: {tld}")
                result['risk_score'] += 25
            elif tld in self.tld_categories['medium_risk']:
                result['warnings'].append(f"Medium-risk TLD detected: {tld}")
                result['risk_score'] += 10
            elif tld not in self.tld_categories['low_risk']:
                result['warnings'].append(f"Uncommon TLD detected: {tld}")
                result['risk_score'] += 5

            # Enhanced SSL Certificate Validation
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        result['ssl_info']['valid'] = True
                        
                        # Validate certificate chain
                        cert_chain = self._validate_cert_chain(ssock)
                        result['ssl_info']['cert_chain'] = cert_chain
                        
                        # Check certificate strength
                        cipher = ssock.cipher()
                        if cipher[0] not in ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256']:
                            result['ssl_info']['issues'].append(f"Weak cipher suite: {cipher[0]}")
                            result['risk_score'] += 10
                        
                        # Check certificate expiration
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
                        days_until_expiry = (not_after - datetime.now()).days
                        if days_until_expiry < 30:
                            result['ssl_info']['issues'].append(f"Certificate expires in {days_until_expiry} days")
                            result['risk_score'] += 15
            except Exception as e:
                result['warnings'].append(f"SSL validation error: {str(e)}")
                result['risk_score'] += 30

            # Enhanced Website Access Check with Security Headers Analysis
            try:
                session = requests.Session()
                response = session.get(url, allow_redirects=True, timeout=10)
                
                # Analyze response headers
                security_headers = {
                    'Strict-Transport-Security': 'HSTS not enabled',
                    'Content-Security-Policy': 'CSP not configured',
                    'X-Content-Type-Options': 'MIME-type sniffing protection missing',
                    'X-Frame-Options': 'Clickjacking protection missing',
                    'Permissions-Policy': 'Permissions-Policy not configured',
                    'Cross-Origin-Opener-Policy': 'COOP not configured',
                    'Cross-Origin-Resource-Policy': 'CORP not configured',
                    'Cross-Origin-Embedder-Policy': 'COEP not configured'
                }
                
                for header, warning in security_headers.items():
                    header_value = None
                    for key in response.headers:
                        if key.lower() == header.lower():
                            header_value = response.headers[key]
                            result['security_headers'][header] = header_value
                            break
                    
                    if not header_value:
                        result['warnings'].append(warning)
                        result['risk_score'] += 5
                
                # Detailed CSP Analysis
                csp_header = result['security_headers'].get('Content-Security-Policy', '')
                if csp_header:
                    result['csp_analysis'] = self.csp_analyzer.analyze_csp(csp_header)
                    result['risk_score'] += result['csp_analysis']['risk_score']
                
                # Check for deprecated Feature-Policy (now Permissions-Policy)
                if 'Feature-Policy' in response.headers:
                    result['warnings'].append("Using deprecated Feature-Policy header")
                
                # Check Clear-Site-Data header (usually seen on logout)
                if 'Clear-Site-Data' in response.headers:
                    result['security_headers']['Clear-Site-Data'] = response.headers['Clear-Site-Data']

                # Analyze redirect chain
                if response.history:
                    result['redirect_chain'] = [
                        {'url': r.url, 'status_code': r.status_code} 
                        for r in response.history
                    ]
                    if len(response.history) > 2:
                        result['warnings'].append(f"Multiple redirects detected: {len(response.history)}")
                        result['risk_score'] += 15
                    
                    # Check for mixed content in redirects
                    for redirect in response.history:
                        if redirect.url.startswith('http://'):
                            result['warnings'].append("Mixed content: HTTP redirect in chain")
                            result['risk_score'] += 20
                            break
            except requests.exceptions.RequestException as e:
                result['warnings'].append(f"Could not access website: {str(e)}")
                result['risk_score'] += 25

            # Reputation Checks
            if check_reputation:
                print("[*] Running reputation checks...")
                result['reputation']['sources'] = await self._check_all_reputation_services(url)
                
                # Aggregate reputation risk
                for service, data in result['reputation']['sources'].items():
                    if data.get('checked') and not data.get('safe', True):
                        result['risk_score'] += data.get('risk_increase', 0)
                        result['warnings'].append(f"Flagged by {service}")
            
            # Vulnerability Probes
            if check_vulnerabilities:
                print("[*] Running vulnerability probes...")
                
                # Check for open redirect
                open_redirect_result = await self.vulnerability_prober.check_open_redirect(url)
                result['vulnerabilities']['open_redirect'] = open_redirect_result
                if open_redirect_result['vulnerable']:
                    result['warnings'].append("Open redirect vulnerability detected")
                    result['risk_score'] += 30
                
                # Check for header injection
                header_injection_result = await self.vulnerability_prober.check_header_injection(url)
                result['vulnerabilities']['header_injection'] = header_injection_result
                if header_injection_result['vulnerable']:
                    result['warnings'].append("HTTP header injection vulnerability detected")
                    result['risk_score'] += 35

            # Calculate confidence level based on available data
            confidence_factors = {
                'ssl_valid': result['ssl_info']['valid'],
                'domain_age_known': result['domain_age'] is not None,
                'no_critical_warnings': len([w for w in result['warnings'] if 'critical' in w.lower()]) == 0,
                'reputation_checked': len(result['reputation']['sources']) > 0
            }
            result['confidence_level'] = self._calculate_confidence_level(confidence_factors)

            # Calculate final risk assessment with weighted factors
            result['risk_level'] = self._calculate_risk_level(
                result['risk_score'],
                ssl_valid=result['ssl_info']['valid'],
                domain_age=result['domain_age'],
                redirect_count=len(result['redirect_chain'])
            )

        except Exception as e:
            result['warnings'].append(f"Analysis error: {str(e)}")
            result['risk_score'] = 100
            result['risk_level'] = "High"

        return result
    
    async def _check_all_reputation_services(self, url: str) -> Dict[str, Any]:
        """Check all reputation services concurrently"""
        results = {}
        
        # Run all checks concurrently
        tasks = [
            ('google_safe_browsing', self.reputation_checker.check_google_safe_browsing(url)),
            ('virustotal', self.reputation_checker.check_virustotal(url)),
            ('urlscan', self.reputation_checker.check_urlscan(url)),
            ('alienvault_otx', self.reputation_checker.check_alienvault_otx(url))
        ]
        
        # Wait for all tasks to complete
        for service_name, task in tasks:
            try:
                results[service_name] = await task
            except Exception as e:
                results[service_name] = {'checked': False, 'error': str(e)}
        
        return results

    def _validate_cert_chain(self, ssl_socket):
        """Validate the certificate chain"""
        cert_chain = []
        try:
            for cert in ssl_socket.get_peer_cert_chain():
                cert_info = {
                    'subject': dict(x[0] for x in cert.get_subject().get_components()),
                    'issuer': dict(x[0] for x in cert.get_issuer().get_components()),
                    'version': cert.get_version(),
                    'serial_number': cert.get_serial_number(),
                    'not_before': cert.get_notBefore(),
                    'not_after': cert.get_notAfter()
                }
                cert_chain.append(cert_info)
        except AttributeError:
            # Handle case where get_peer_cert_chain is not available
            pass
        return cert_chain

    def _calculate_confidence_level(self, factors):
        """Calculate confidence level of the analysis"""
        confidence_score = sum(1 for factor in factors.values() if factor)
        if confidence_score == len(factors):
            return "High"
        elif confidence_score >= len(factors) / 2:
            return "Medium"
        else:
            return "Low"

    def _calculate_risk_level(self, risk_score, **factors):
        """Calculate risk level with weighted factors"""
        # Apply weight adjustments based on factors
        if not factors.get('ssl_valid', True):
            risk_score *= 1.5
        
        if factors.get('domain_age', 0) and factors['domain_age'] < 30:
            risk_score *= 1.3
        
        if factors.get('redirect_count', 0) > 3:
            risk_score *= 1.2

        # Determine final risk level
        if risk_score < 20:
            return "Low"
        elif risk_score < 50:
            return "Medium"
        else:
            return "High"


# Example usage and integration
async def main():
    """Example usage of the enhanced LinkAnalyzer"""
    
    # API keys (replace with your actual keys)
    api_keys = {
        'google_safe_browsing': 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY',
        'virustotal': 'YOUR_VIRUSTOTAL_API_KEY',
        'urlscan': 'YOUR_URLSCAN_API_KEY',  # Optional for search, required for submissions
        'alienvault_otx': 'YOUR_ALIENVAULT_OTX_API_KEY'  # Optional
    }
    
    # Example integration callbacks (replace with actual scanner functions)
    async def xss_scanner_callback(urls, data_type='urls'):
        """Example XSS scanner integration"""
        print(f"[XSS Scanner] Testing {len(urls)} {data_type}")
        # Your XSS scanning logic here
        return {'tested': len(urls), 'vulnerable': 0}
    
    async def sql_injection_callback(urls, data_type='urls'):
        """Example SQL injection scanner integration"""
        print(f"[SQL Scanner] Testing {len(urls)} {data_type}")
        # Your SQL injection scanning logic here
        return {'tested': len(urls), 'vulnerable': 0}
    
    integration_callbacks = {
        'xss_scanner': xss_scanner_callback,
        'sql_injection': sql_injection_callback
    }
    
    # Initialize analyzer
    analyzer = LinkAnalyzer(api_keys=api_keys, integration_callbacks=integration_callbacks)
    
    # Example 1: Analyze a single URL
    print("\n" + "="*60)
    print("EXAMPLE 1: Single URL Analysis")
    print("="*60)
    url_to_analyze = "https://example.com"
    analysis_result = await analyzer.analyze(
        url_to_analyze,
        check_vulnerabilities=True,
        check_reputation=True
    )
    
    print(f"\nAnalysis Results for {url_to_analyze}:")
    print(f"Risk Level: {analysis_result['risk_level']}")
    print(f"Risk Score: {analysis_result['risk_score']}")
    print(f"Confidence: {analysis_result['confidence_level']}")
    print(f"Warnings: {len(analysis_result['warnings'])}")
    for warning in analysis_result['warnings']:
        print(f"  - {warning}")
    
    # Example 2: Crawl a website
    print("\n" + "="*60)
    print("EXAMPLE 2: Website Crawling")
    print("="*60)
    crawl_result = await analyzer.crawl(
        "https://example.com",
        max_depth=2,
        max_urls=20,
        respect_robots=False,
        use_js_rendering=False,
        integrate_with_scanners=True
    )
    
    print(f"\nCrawl Results:")
    print(f"Pages Crawled: {crawl_result['statistics']['pages_crawled']}")
    print(f"URLs Discovered: {len(crawl_result['discovered_urls'])}")
    print(f"URLs with Parameters: {len(crawl_result['urls_with_parameters'])}")
    print(f"Forms Found: {len(crawl_result['forms'])}")
    
    print("\n" + "="*60)
    print("Enhanced Link Analyzer - Ready for Production!")
    print("="*60)


if __name__ == "__main__":
    # Run the example
    asyncio.run(main())