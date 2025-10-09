"""SSRF (Server-Side Request Forgery) Scanner Module for detecting SSRF vulnerabilities."""

import asyncio
import httpx
import re
import hashlib
import time
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, quote, urljoin, urlunparse
from bs4 import BeautifulSoup
import random
import string

# Import browser automation - try playwright first, then pyppeteer
PYPPETEER_AVAILABLE = False
try:
    from playwright.async_api import async_playwright
    PYPPETEER_AVAILABLE = True
except ImportError:
    try:
        from pyppeteer import launch
        PYPPETEER_AVAILABLE = True
    except ImportError:
        pass

from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)

class SSRFScanner(BaseScannerModule):
    """Server-Side Request Forgery (SSRF) vulnerability scanner."""
    
    def __init__(self):
        super().__init__()
        self.name = "SSRFScanner"
        self.description = "Detects Server-Side Request Forgery (SSRF) vulnerabilities with intelligent discovery"
        self.scan_type = ScanType.ACTIVE
        
        # Store discovered API endpoints from browser
        self.discovered_endpoints = []
        self.captured_requests = []
        
        # Common SSRF parameter names
        self.ssrf_param_names = [
            'url', 'uri', 'target', 'dest', 'destination', 'redirect',
            'next', 'path', 'domain', 'image', 'img', 'src', 'source',
            'feed', 'callback', 'return', 'returnUrl', 'continue',
            'ref', 'reference', 'file', 'fetch', 'proxy', 'load',
            'preview', 'host', 'port', 'to', 'out', 'view', 'dir',
            'show', 'retrieve', 'display', 'get', 'grab', 'download',
            'redir', 'goto', 'forward', 'back', 'link', 'open'
        ]
        
        # SSRF payloads categorized by type
        self.ssrf_payloads = {
            'localhost': [
                'http://127.0.0.1/',
                'http://localhost/',
                'http://0.0.0.0/',
                'http://[::1]/',
                'http://127.1/',
                'http://127.0.1/',
                'http://2130706433/',  # Decimal IP for 127.0.0.1
                'http://0x7f000001/',   # Hex IP for 127.0.0.1
                'http://0177.0.0.1/',   # Octal IP
            ],
            
            'internal_network': [
                'http://192.168.0.1/',
                'http://192.168.1.1/',
                'http://10.0.0.1/',
                'http://10.0.0.2/',
                'http://172.16.0.1/',
                'http://172.17.0.1/',  # Common Docker internal
            ],
            
            'metadata_endpoints': [
                # AWS
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/user-data/',
                'http://169.254.169.254/latest/api/token',
                
                # GCP
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://169.254.169.254/computeMetadata/v1/',
                
                # Azure
                'http://169.254.169.254/metadata/instance?api-version=2021-01-01',
                'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01',
                
                # Digital Ocean
                'http://169.254.169.254/metadata/v1/',
                
                # Oracle Cloud
                'http://169.254.169.254/opc/v1/instance/',
                
                # Alibaba Cloud
                'http://100.100.100.200/latest/meta-data/',
            ],
            
            'protocols': [
                'file:///etc/passwd',
                'file:///c:/windows/win.ini',
                'gopher://127.0.0.1:25/',
                'dict://127.0.0.1:11211/',
                'ftp://127.0.0.1/',
                'sftp://127.0.0.1/',
            ],
            
            'dns_based': [
                # These would use a canary domain if provided
                'http://{random}.{canary_domain}/',
                'https://{random}.{canary_domain}/',
            ],
            
            'bypass_techniques': [
                # URL encoding bypasses
                'http://127.0.0.1%2f/',
                'http://127.0.0.1%252f/',
                
                # Alternative representations
                'http://0/',
                'http://localhost:80/',
                'http://[::ffff:127.0.0.1]/',
                
                # Redirect chains
                'http://google.com@127.0.0.1/',
                'http://127.0.0.1#@google.com/',
                
                # DNS rebinding (would need special setup)
                # 'http://spoofed.burpcollaborator.net/',
            ]
        }
        
        # Error signatures indicating SSRF
        self.ssrf_error_signatures = [
            # Connection errors
            'connection refused', 'econnrefused', 'connection reset',
            'connection reset by peer', 'connection timed out', 'timeout',
            'timed out', 'dial tcp', 'dial udp', 'no route to host',
            'network is unreachable', 'no such host', 'name or service not known',
            'getaddrinfo enotfound', 'getaddrinfo', 'socket hang up',
            'refused to connect', 'cannot assign requested address',
            'econnreset', 'etimedout', 'ehostunreach', 'enetunreach',
            'enotfound', 'eaddrnotavail', 'eisconn', 'ealready',
            
            # HTTP client errors
            'httperror', 'http error', 'invalid url', 'malformed url',
            'bad gateway', 'gateway timeout', 'service unavailable',
            'could not resolve host', 'couldn\'t resolve host',
            'couldn\'t connect to host', 'failed to connect',
            'connection failed', 'request failed', 'fetch failed',
            
            # Programming language specific
            'java.net.connectexception', 'java.net.unknownhostexception',
            'java.net.sockettimeoutexception', 'java.io.ioexception',
            'urllib.error.urlerror', 'requests.exceptions',
            'curl error', 'wget error', 'file_get_contents',
            
            # Cloud metadata indicators
            'metadata', 'meta-data', 'instance-id', 'ami-id',
            'placement/availability-zone', 'public-keys',
            'security-credentials', 'iam/security-credentials',
        ]
        
        # Headers to test for SSRF (opt-in)
        self.ssrf_headers = [
            'X-Original-URL', 'X-Forwarded-Host', 'X-Forwarded-For',
            'X-Forwarded-Scheme', 'X-Forwarded-Proto', 'X-Rewrite-URL',
            'Forwarded', 'X-Custom-IP-Authorization', 'X-Real-IP',
            'Referer', 'Origin', 'X-Originating-IP', 'X-Remote-IP',
            'X-Client-IP', 'X-Host', 'X-Forwarded-Server',
        ]
        
        # Common JSON/XML keys for body testing
        self.json_keys = [
            'url', 'uri', 'endpoint', 'webhook', 'callback',
            'target', 'source', 'image', 'imageUrl', 'avatarUrl',
            'profileUrl', 'link', 'href', 'src', 'action',
            'redirect', 'redirectUrl', 'returnUrl', 'nextUrl'
        ]
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is suitable for SSRF testing."""
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        except Exception as e:
            # Log parsing errors for debugging
            print(f"Error parsing target URL {target}: {e}")
            return False
    
    async def _time_request(self, client: httpx.AsyncClient, request_func, *args, **kwargs) -> Tuple[Any, float]:
        """
        Wrapper to accurately time individual async requests.
        
        Returns:
            Tuple of (response/exception, elapsed_time_ms)
        """
        start_time = time.time()
        try:
            response = await request_func(*args, **kwargs)
            elapsed = (time.time() - start_time) * 1000
            return response, elapsed
        except httpx.TimeoutError as e:
            # Use the actual configured timeout value
            elapsed = client.timeout.connect * 1000 if client.timeout.connect else 10000
            return e, elapsed
        except Exception as e:
            elapsed = (time.time() - start_time) * 1000
            return e, elapsed
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform SSRF vulnerability scan with intelligent discovery."""
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'tested_parameters': [],
            'vulnerable_parameters': [],
            'forms_tested': [],
            'ssrf_types_found': [],
            'payloads_successful': [],
            'dangerous_tests_performed': False,
            'header_injection_tested': False,
            'discovered_endpoints': [],
            'captured_requests': [],
            'browser_discovery_used': False,
        }
        statistics = {
            'urls_tested': 0,
            'parameters_tested': 0,
            'forms_tested': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0,
            'high_confidence': 0,
            'medium_confidence': 0,
            'low_confidence': 0,
            'endpoints_discovered': 0,
            'api_calls_captured': 0,
        }
        
        try:
            # Ensure URL has scheme
            target_url = config.target
            if not target_url.startswith(('http://', 'https://')):
                target_url = f"https://{target_url}"
            
            # Determine what tests to run based on config
            enable_dangerous = (
                config.scan_type == ScanType.AGGRESSIVE or
                config.custom_params.get('ssrf_enable_dangerous_tests', False)
            )
            
            enable_header_injection = config.custom_params.get('ssrf_header_injection', False)
            test_methods = config.custom_params.get('methods', ['GET'])
            canary_domain = config.custom_params.get('ssrf_canary_domain', '')
            use_browser_discovery = config.custom_params.get('ssrf_browser_discovery', True)
            
            if enable_dangerous:
                info['dangerous_tests_performed'] = True
                warnings.append("Dangerous SSRF tests enabled - testing cloud metadata endpoints")
            
            if enable_header_injection:
                info['header_injection_tested'] = True
            
            # Get baseline response for comparison
            baseline = await self._get_baseline_response(target_url)
            
            # ============================================================
            # PHASE 1: INTELLIGENT DISCOVERY 🕵️‍♂️
            # ============================================================
            if use_browser_discovery and PYPPETEER_AVAILABLE:
                print(f"\n[Phase 1] Starting intelligent discovery with headless browser...")
                info['browser_discovery_used'] = True
                
                discovery_results = await self._phase1_intelligent_discovery(
                    target_url, config
                )
                
                self.discovered_endpoints = discovery_results['endpoints']
                self.captured_requests = discovery_results['captured_requests']
                
                info['discovered_endpoints'] = [
                    {
                        'url': ep['url'],
                        'method': ep['method'],
                        'type': ep.get('type', 'unknown')
                    }
                    for ep in self.discovered_endpoints
                ]
                info['captured_requests'] = len(self.captured_requests)
                statistics['endpoints_discovered'] = len(self.discovered_endpoints)
                statistics['api_calls_captured'] = len(self.captured_requests)
                
                print(f"[Phase 1] Discovered {len(self.discovered_endpoints)} endpoints")
                print(f"[Phase 1] Captured {len(self.captured_requests)} API requests")
            elif use_browser_discovery and not PYPPETEER_AVAILABLE:
                warnings.append("Browser discovery requested but pyppeteer not available. Install with: pip install pyppeteer")
                errors.append("pyppeteer not installed - falling back to traditional scanning")
            
            # ============================================================
            # PHASE 2: CONTEXTUAL TESTING 🔬
            # ============================================================
            if self.captured_requests:
                print(f"\n[Phase 2] Starting contextual testing with {len(self.captured_requests)} captured requests...")
                
                contextual_results = await self._phase2_contextual_testing(
                    self.captured_requests, baseline, enable_dangerous, canary_domain, config
                )
                
                vulnerabilities.extend(contextual_results['vulnerabilities'])
                statistics['parameters_tested'] += contextual_results['parameters_tested']
                statistics['payloads_tested'] += contextual_results['payloads_tested']
                
                print(f"[Phase 2] Found {len(contextual_results['vulnerabilities'])} vulnerabilities")
            
            # ============================================================
            # PHASE 3: ADVANCED VERIFICATION ✅
            # ============================================================
            if canary_domain and vulnerabilities:
                print(f"\n[Phase 3] Starting advanced verification with canary domain...")
                
                verification_results = await self._phase3_advanced_verification(
                    vulnerabilities, canary_domain, config
                )
                
                # Add confirmed vulnerabilities
                vulnerabilities.extend(verification_results['confirmed_vulnerabilities'])
                
                print(f"[Phase 3] Confirmed {len(verification_results['confirmed_vulnerabilities'])} vulnerabilities via OOB")
            
            # Fallback to traditional scanning if no browser discovery
            if not self.captured_requests:
                print("\n[Fallback] Using traditional scanning methods...")
                
                if config.scan_type == ScanType.PASSIVE:
                    warnings.append("SSRF detection requires active scanning - passive mode limited")
                else:
                    # Traditional URL parameter testing
                    param_results = await self._test_url_parameters(
                        target_url, baseline, enable_dangerous, canary_domain, config
                    )
                    vulnerabilities.extend(param_results['vulnerabilities'])
                    info['tested_parameters'].extend(param_results['tested_params'])
                    statistics['parameters_tested'] = len(param_results['tested_params'])
                    
                    # Form discovery and testing
                    form_results = await self._discover_and_test_forms(
                        target_url, baseline, enable_dangerous, canary_domain, config
                    )
                    vulnerabilities.extend(form_results['vulnerabilities'])
                    info['forms_tested'] = form_results['forms_tested']
                    statistics['forms_tested'] = len(form_results['forms_tested'])
                    statistics['parameters_tested'] += form_results['parameters_tested']
                    
                    # Header injection testing
                    if enable_header_injection:
                        header_results = await self._test_header_injection(
                            target_url, baseline, enable_dangerous, config
                        )
                        vulnerabilities.extend(header_results)
                    
                    # Timing-based testing
                    timing_results = await self._test_timing_based_ssrf(
                        target_url, baseline, config
                    )
                    vulnerabilities.extend(timing_results)
            
            # Update statistics
            statistics['vulnerabilities_found'] = len(vulnerabilities)
            statistics['urls_tested'] = 1
            statistics['payloads_tested'] = statistics['parameters_tested'] * 10  # Approximate
            
            # Categorize vulnerabilities by confidence
            for vuln in vulnerabilities:
                if vuln.confidence >= 0.8:
                    statistics['high_confidence'] += 1
                elif vuln.confidence >= 0.5:
                    statistics['medium_confidence'] += 1
                else:
                    statistics['low_confidence'] += 1
                
                # Track vulnerable parameters
                if 'parameter' in vuln.evidence:
                    info['vulnerable_parameters'].append(vuln.evidence['parameter'])
            
            # Determine SSRF types found
            ssrf_types = set()
            for vuln in vulnerabilities:
                if 'metadata' in vuln.name.lower():
                    ssrf_types.add('Cloud Metadata SSRF')
                elif 'internal' in vuln.name.lower() or 'private' in vuln.name.lower():
                    ssrf_types.add('Internal Network SSRF')
                elif 'blind' in vuln.name.lower():
                    ssrf_types.add('Blind SSRF')
                elif 'header' in vuln.name.lower():
                    ssrf_types.add('Header-based SSRF')
                else:
                    ssrf_types.add('Classic SSRF')
            info['ssrf_types_found'] = list(ssrf_types)
            
        except Exception as e:
            errors.append(f"SSRF scan failed: {str(e)}")
        
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
    
    async def _get_baseline_response(self, url: str) -> Dict[str, Any]:
        """Get baseline response for comparison."""
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
                start_time = time.time()
                response = await client.get(url)
                elapsed = (time.time() - start_time) * 1000  # ms
                
                return {
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'response_time': elapsed,
                    'headers': dict(response.headers),
                    'text_sample': response.text[:500] if response.text else '',
                }
        except Exception as e:
            return {
                'status_code': 0,
                'content_length': 0,
                'response_time': 0,
                'error': str(e),
            }
    
    async def _test_url_parameters(self, url: str, baseline: Dict[str, Any],
                                   enable_dangerous: bool, canary_domain: str,
                                   config: ScanConfig) -> Dict[str, Any]:
        """Test existing URL parameters for SSRF vulnerabilities."""
        vulnerabilities = []
        tested_params = []
        
        # Parse URL for parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return {'vulnerabilities': [], 'tested_params': []}
        
        # Select payloads based on configuration
        payloads = self._select_payloads(enable_dangerous, canary_domain)
        
        # Get timeout value from config
        timeout_value = config.timeout if config.timeout else 10
        
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=timeout_value) as client:
            for param_name, param_values in params.items():
                tested_params.append(param_name)
                original_value = param_values[0] if param_values else ''
                
                # Create tasks for parallel execution with proper timing
                tasks = []
                task_info = []
                
                for payload_type, payload in payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                    
                    task_info.append({
                        'param_name': param_name,
                        'payload': payload,
                        'payload_type': payload_type,
                        'test_url': test_url
                    })
                    # Use the timing wrapper for accurate timing
                    tasks.append(self._time_request(client, client.get, test_url))
                
                # Execute all requests in parallel with proper timing
                try:
                    results = await asyncio.gather(*tasks, return_exceptions=False)
                    
                    # Process responses with accurate timing
                    for (response, elapsed), info in zip(results, task_info):
                        if isinstance(response, Exception):
                            # Handle exceptions from individual requests
                            if isinstance(response, httpx.TimeoutError):
                                # Timeout might indicate SSRF
                                if elapsed > baseline['response_time'] * 3:
                                    vuln = Vulnerability(
                                        module=self.name,
                                        name=f"Potential Blind SSRF in parameter '{info['param_name']}'",
                                        description=f"Parameter '{info['param_name']}' causes timeout with SSRF payload",
                                        severity=SeverityLevel.MEDIUM,
                                        confidence=0.5,
                                        affected_urls=[url],
                                        evidence={
                                            'parameter': info['param_name'],
                                            'payload': info['payload'],
                                            'method': 'GET',
                                            'timeout': True,
                                            'baseline_time': baseline['response_time'],
                                            'timeout_time': elapsed,
                                        },
                                        remediation="Validate and whitelist URLs before making server-side requests.",
                                        cwe_ids=["CWE-918"]
                                    )
                                    vulnerabilities.append(vuln)
                            continue
                        
                        # Analyze response for SSRF indicators with accurate timing from wrapper
                        ssrf_evidence = self._analyze_response_for_ssrf(
                            response, baseline, info['payload'], info['payload_type'], elapsed
                        )
                        
                        if ssrf_evidence['is_vulnerable']:
                            vuln = self._create_vulnerability(
                                info['param_name'], info['payload'], info['payload_type'], url,
                                ssrf_evidence, 'GET'
                            )
                            vulnerabilities.append(vuln)
                            
                            # Don't test more payloads for this param if found
                            if ssrf_evidence['confidence'] >= 0.8:
                                break
                                
                except Exception as e:
                    # Handle any unexpected errors in the gather operation
                    # Log the error for debugging purposes
                    print(f"Error in parallel request execution for parameter {param_name}: {e}")
                    pass
        
        return {
            'vulnerabilities': vulnerabilities,
            'tested_params': tested_params
        }
    
    async def _discover_and_test_parameters(self, url: str, baseline: Dict[str, Any],
                                           enable_dangerous: bool, canary_domain: str,
                                           config: ScanConfig) -> Dict[str, Any]:
        """Discover potential SSRF parameters and test them."""
        vulnerabilities = []
        tested_params = []
        
        # Parse base URL
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Select a subset of parameter names to test (configurable)
        max_params = config.custom_params.get('ssrf_max_params', 15)
        params_to_test = self.ssrf_param_names[:max_params]
        
        # Select payloads (configurable limit)
        max_payloads = config.custom_params.get('ssrf_max_payloads', 5)
        payloads = self._select_payloads(enable_dangerous, canary_domain)[:max_payloads]
        
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
            for param_name in params_to_test:
                tested_params.append(param_name)
                
                for payload_type, payload in payloads:
                    test_url = f"{base_url}?{param_name}={quote(payload)}"
                    
                    try:
                        start_time = time.time()
                        response = await client.get(test_url)
                        elapsed = (time.time() - start_time) * 1000
                        
                        # Analyze response
                        ssrf_evidence = self._analyze_response_for_ssrf(
                            response, baseline, payload, payload_type, elapsed
                        )
                        
                        if ssrf_evidence['is_vulnerable']:
                            vuln = self._create_vulnerability(
                                param_name, payload, payload_type, url,
                                ssrf_evidence, 'GET'
                            )
                            vulnerabilities.append(vuln)
                            break  # Found vulnerability, skip other payloads
                            
                    except (httpx.RequestError, httpx.TimeoutError, Exception) as e:
                        # Log specific errors for debugging
                        print(f"Request failed for parameter {param_name} with payload {payload}: {e}")
                        pass
        
        return {
            'vulnerabilities': vulnerabilities,
            'tested_params': tested_params
        }
    
    async def _discover_and_test_forms(self, url: str, baseline: Dict[str, Any],
                                      enable_dangerous: bool, canary_domain: str,
                                      config: ScanConfig) -> Dict[str, Any]:
        """Discover and test forms on the page for SSRF vulnerabilities."""
        vulnerabilities = []
        forms_tested = []
        parameters_tested = 0
        
        try:
            # Fetch the page content
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    return {
                        'vulnerabilities': [],
                        'forms_tested': [],
                        'parameters_tested': 0
                    }
                
                # Parse HTML content
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all forms on the page
                forms = soup.find_all('form')
                
                # Also look for AJAX endpoints and API calls in JavaScript
                scripts = soup.find_all('script')
                ajax_endpoints = self._extract_ajax_endpoints(scripts, url)
                
                # Select payloads for testing
                payloads = self._select_payloads(enable_dangerous, canary_domain)
                
                # Test each form
                for form_idx, form in enumerate(forms):
                    form_info = self._extract_form_info(form, url)
                    if not form_info:
                        continue
                    
                    forms_tested.append({
                        'action': form_info['action'],
                        'method': form_info['method'],
                        'inputs': len(form_info['inputs'])
                    })
                    
                    # Test each input field that might be vulnerable to SSRF
                    for input_field in form_info['inputs']:
                        input_name = input_field.get('name', '')
                        input_type = input_field.get('type', 'text')
                        
                        # Check if this input field name suggests SSRF potential
                        if self._is_potential_ssrf_param(input_name):
                            parameters_tested += 1
                            
                            # Test with each payload
                            for payload_type, payload in payloads:
                                # Prepare form data
                                form_data = self._prepare_form_data(form_info['inputs'], input_name, payload)
                                
                                try:
                                    start_time = time.time()
                                    
                                    # Submit the form with the payload
                                    if form_info['method'].upper() == 'POST':
                                        test_response = await client.post(
                                            form_info['action'],
                                            data=form_data,
                                            headers={'Referer': url}
                                        )
                                    else:
                                        test_response = await client.get(
                                            form_info['action'],
                                            params=form_data,
                                            headers={'Referer': url}
                                        )
                                    
                                    elapsed = (time.time() - start_time) * 1000
                                    
                                    # Analyze response for SSRF indicators
                                    ssrf_evidence = self._analyze_response_for_ssrf(
                                        test_response, baseline, payload, payload_type, elapsed
                                    )
                                    
                                    if ssrf_evidence['is_vulnerable']:
                                        vuln = Vulnerability(
                                            module=self.name,
                                            name=f"SSRF in form input '{input_name}'",
                                            description=f"Form input field '{input_name}' at {form_info['action']} is vulnerable to SSRF",
                                            severity=self._determine_severity(payload_type, ssrf_evidence),
                                            confidence=ssrf_evidence['confidence'],
                                            affected_urls=[url, form_info['action']],
                                            evidence={
                                                'form_action': form_info['action'],
                                                'form_method': form_info['method'],
                                                'parameter': input_name,
                                                'payload': payload,
                                                'payload_type': payload_type,
                                                'indicators': ssrf_evidence.get('indicators', []),
                                                'response_snippet': ssrf_evidence.get('response_snippet', '')[:500],
                                            },
                                            remediation=self._get_remediation(payload_type),
                                            references=[
                                                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
                                            ],
                                            cwe_ids=["CWE-918"]
                                        )
                                        vulnerabilities.append(vuln)
                                        break  # Don't test more payloads if vulnerable
                                        
                                except Exception as e:
                                    print(f"Error testing form input {input_name}: {e}")
                                    continue
                
                # Test discovered AJAX endpoints
                for endpoint in ajax_endpoints:
                    endpoint_results = await self._test_ajax_endpoint(
                        endpoint, baseline, enable_dangerous, canary_domain, config
                    )
                    vulnerabilities.extend(endpoint_results['vulnerabilities'])
                    parameters_tested += endpoint_results['parameters_tested']
                    
        except Exception as e:
            print(f"Error discovering and testing forms: {e}")
        
        return {
            'vulnerabilities': vulnerabilities,
            'forms_tested': forms_tested,
            'parameters_tested': parameters_tested
        }
    
    def _extract_form_info(self, form, base_url: str) -> Optional[Dict[str, Any]]:
        """Extract information from a form element."""
        try:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            
            # Resolve relative URLs
            if action:
                action = urljoin(base_url, action)
            else:
                action = base_url
            
            # Extract all input fields
            inputs = []
            
            # Find all input elements
            for input_elem in form.find_all(['input', 'textarea', 'select']):
                input_info = {
                    'name': input_elem.get('name', ''),
                    'type': input_elem.get('type', 'text'),
                    'value': input_elem.get('value', ''),
                    'required': input_elem.get('required') is not None
                }
                
                # For select elements, get the first option value
                if input_elem.name == 'select':
                    options = input_elem.find_all('option')
                    if options:
                        input_info['value'] = options[0].get('value', '')
                
                if input_info['name']:  # Only include inputs with names
                    inputs.append(input_info)
            
            return {
                'action': action,
                'method': method,
                'inputs': inputs
            }
            
        except Exception as e:
            print(f"Error extracting form info: {e}")
            return None
    
    def _is_potential_ssrf_param(self, param_name: str) -> bool:
        """Check if a parameter name suggests SSRF potential."""
        if not param_name:
            return False
        
        param_lower = param_name.lower()
        
        # Check against known SSRF parameter names
        for ssrf_param in self.ssrf_param_names:
            if ssrf_param in param_lower or param_lower in ssrf_param:
                return True
        
        # Check for URL-related keywords
        url_keywords = ['url', 'uri', 'link', 'src', 'source', 'path', 'file', 
                       'image', 'img', 'feed', 'proxy', 'redirect', 'callback']
        
        return any(keyword in param_lower for keyword in url_keywords)
    
    def _prepare_form_data(self, inputs: List[Dict], target_input: str, payload: str) -> Dict[str, str]:
        """Prepare form data with the SSRF payload."""
        form_data = {}
        
        for input_field in inputs:
            input_name = input_field.get('name', '')
            if not input_name:
                continue
            
            if input_name == target_input:
                # Insert our payload
                form_data[input_name] = payload
            else:
                # Use default or dummy values
                input_type = input_field.get('type', 'text')
                input_value = input_field.get('value', '')
                
                if input_value:
                    form_data[input_name] = input_value
                elif input_type == 'email':
                    form_data[input_name] = 'test@example.com'
                elif input_type == 'password':
                    form_data[input_name] = 'password123'
                elif input_type == 'number':
                    form_data[input_name] = '1'
                elif input_type == 'tel':
                    form_data[input_name] = '1234567890'
                elif input_type == 'date':
                    form_data[input_name] = '2024-01-01'
                else:
                    form_data[input_name] = 'test'
        
        return form_data
    
    def _extract_ajax_endpoints(self, scripts: List, base_url: str) -> List[Dict[str, Any]]:
        """Extract potential AJAX endpoints from JavaScript code."""
        endpoints = []
        
        # Patterns to find API endpoints
        patterns = [
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
            r'axios\.[get|post|put|delete]+\s*\(\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest.*open\s*\(\s*["\'][^"\']+["\']\s*,\s*["\']([^"\']+)["\']'
        ]
        
        for script in scripts:
            script_text = script.string if script.string else ''
            
            for pattern in patterns:
                matches = re.findall(pattern, script_text, re.IGNORECASE)
                for match in matches:
                    # Resolve relative URLs
                    endpoint_url = urljoin(base_url, match)
                    
                    # Check if it looks like an API endpoint that might accept URL parameters
                    if any(keyword in endpoint_url.lower() for keyword in ['api', 'ajax', 'fetch', 'proxy', 'load']):
                        endpoints.append({
                            'url': endpoint_url,
                            'source': 'javascript'
                        })
        
        return endpoints
    
    async def _test_ajax_endpoint(self, endpoint: Dict[str, Any], baseline: Dict[str, Any],
                                 enable_dangerous: bool, canary_domain: str,
                                 config: ScanConfig) -> Dict[str, Any]:
        """Test an AJAX endpoint for SSRF vulnerabilities."""
        vulnerabilities = []
        parameters_tested = 0
        
        # Similar to _test_post_parameters but for AJAX endpoints
        # This is a simplified version - you might want to expand this
        
        return {
            'vulnerabilities': vulnerabilities,
            'parameters_tested': parameters_tested
        }
    
    def _determine_severity(self, payload_type: str, evidence: Dict[str, Any]) -> SeverityLevel:
        """Determine severity based on payload type and evidence."""
        if payload_type == 'metadata' and evidence['confidence'] >= 0.9:
            return SeverityLevel.CRITICAL
        elif payload_type in ['localhost', 'internal'] and evidence['confidence'] >= 0.7:
            return SeverityLevel.HIGH
        elif 'timing' in str(evidence.get('indicators', [])):
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.HIGH if evidence['confidence'] >= 0.7 else SeverityLevel.MEDIUM
    
    async def _test_post_parameters(self, url: str, baseline: Dict[str, Any],
                                   enable_dangerous: bool, canary_domain: str,
                                   config: ScanConfig) -> Dict[str, Any]:
        """Test POST parameters for SSRF vulnerabilities."""
        vulnerabilities = []
        
        # Select common POST parameter names
        post_params = ['url', 'uri', 'target', 'redirect', 'callback', 'file']
        
        # Select payloads (configurable limit)
        max_post_payloads = config.custom_params.get('ssrf_max_post_payloads', 3)
        payloads = self._select_payloads(enable_dangerous, canary_domain)[:max_post_payloads]
        
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
            for param_name in post_params:
                for payload_type, payload in payloads:
                    data = {param_name: payload}
                    
                    try:
                        start_time = time.time()
                        response = await client.post(url, data=data)
                        elapsed = (time.time() - start_time) * 1000
                        
                        # Analyze response
                        ssrf_evidence = self._analyze_response_for_ssrf(
                            response, baseline, payload, payload_type, elapsed
                        )
                        
                        if ssrf_evidence['is_vulnerable']:
                            vuln = self._create_vulnerability(
                                param_name, payload, payload_type, url,
                                ssrf_evidence, 'POST'
                            )
                            vulnerabilities.append(vuln)
                            break
                            
                    except (httpx.RequestError, httpx.TimeoutError, Exception) as e:
                        # Log specific errors for debugging
                        print(f"POST request failed for parameter {param_name} with payload {payload}: {e}")
                        pass
        
        return {'vulnerabilities': vulnerabilities}
    
    async def _test_header_injection(self, url: str, baseline: Dict[str, Any],
                                    enable_dangerous: bool, config: ScanConfig) -> List[Vulnerability]:
        """Test header-based SSRF vulnerabilities."""
        vulnerabilities = []
        
        # Select headers to test
        headers_to_test = ['X-Forwarded-Host', 'X-Original-URL', 'Referer']
        
        # Use simple localhost payload for header testing
        payload = 'http://127.0.0.1/'
        
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
            for header_name in headers_to_test:
                headers = {header_name: payload}
                
                try:
                    start_time = time.time()
                    response = await client.get(url, headers=headers)
                    elapsed = (time.time() - start_time) * 1000
                    
                    # Check for SSRF indicators
                    response_text = response.text.lower() if response.text else ''
                    
                    for signature in self.ssrf_error_signatures[:10]:  # Check top signatures
                        if signature in response_text:
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"Header-based SSRF via '{header_name}'",
                                    description=f"Header '{header_name}' is vulnerable to SSRF",
                                    severity=SeverityLevel.HIGH,
                                    confidence=0.8,
                                    affected_urls=[url],
                                    evidence={
                                        'header': header_name,
                                        'payload': payload,
                                        'error_signature': signature,
                                        'response_snippet': response_text[:200],
                                    },
                                    remediation="Validate and sanitize header values. Don't use user-controlled headers for server-side requests.",
                                    cwe_ids=["CWE-918"]
                                )
                            )
                            break
                            
                except (httpx.RequestError, httpx.TimeoutError, Exception) as e:
                    # Log specific errors for debugging
                    print(f"Header injection request failed for header {header_name}: {e}")
                    pass
        
        return vulnerabilities
    
    async def _test_timing_based_ssrf(self, url: str, baseline: Dict[str, Any],
                                     config: ScanConfig) -> List[Vulnerability]:
        """Test for blind SSRF using timing attacks."""
        vulnerabilities = []
        
        # Parse URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return []
        
        # Timing payloads - these should cause delays
        timing_payloads = [
            'http://10.0.0.1:80/',  # Non-routable, should timeout
            'http://192.168.100.100:81/',  # Likely closed port
        ]
        
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=15) as client:
            for param_name in list(params.keys())[:2]:  # Test first 2 params
                baseline_time = baseline.get('response_time', 1000)
                
                for payload in timing_payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                    
                    try:
                        start_time = time.time()
                        response = await client.get(test_url)
                        elapsed = (time.time() - start_time) * 1000
                        
                        # Check if response time is significantly higher
                        if elapsed > baseline_time * 3 and elapsed > 3000:  # 3x baseline and > 3 seconds
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"Blind SSRF via timing in parameter '{param_name}'",
                                    description=f"Parameter '{param_name}' shows timing delays with internal network payloads",
                                    severity=SeverityLevel.MEDIUM,
                                    confidence=0.6,
                                    affected_urls=[url],
                                    evidence={
                                        'parameter': param_name,
                                        'payload': payload,
                                        'baseline_time_ms': baseline_time,
                                        'response_time_ms': elapsed,
                                        'time_difference_ms': elapsed - baseline_time,
                                    },
                                    remediation="Implement URL validation and whitelisting for server-side requests.",
                                    cwe_ids=["CWE-918"]
                                )
                            )
                            break
                            
                    except httpx.TimeoutError:
                        # Timeout is strong indicator
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"Blind SSRF (timeout) in parameter '{param_name}'",
                                description=f"Parameter '{param_name}' causes timeout with internal network payload",
                                severity=SeverityLevel.MEDIUM,
                                confidence=0.7,
                                affected_urls=[url],
                                evidence={
                                    'parameter': param_name,
                                    'payload': payload,
                                    'timeout': True,
                                },
                                remediation="Implement URL validation and whitelisting for server-side requests.",
                                cwe_ids=["CWE-918"]
                            )
                        )
                    except (httpx.RequestError, httpx.TimeoutError, Exception) as e:
                        # Log specific errors for debugging
                        print(f"Timing-based SSRF request failed for parameter {param_name}: {e}")
                        pass
        
        return vulnerabilities
    
    def _select_payloads(self, enable_dangerous: bool, canary_domain: str) -> List[Tuple[str, str]]:
        """Select appropriate payloads based on configuration."""
        payloads = []
        
        # Always include localhost payloads (configurable limit)
        localhost_limit = 3  # Default limit for localhost payloads
        for payload in self.ssrf_payloads['localhost'][:localhost_limit]:
            payloads.append(('localhost', payload))
        
        # Include internal network payloads (configurable limit)
        internal_limit = 2  # Default limit for internal network payloads
        for payload in self.ssrf_payloads['internal_network'][:internal_limit]:
            payloads.append(('internal', payload))
        
        # Include metadata endpoints if dangerous tests enabled (configurable limit)
        if enable_dangerous:
            metadata_limit = 3  # Default limit for metadata payloads
            for payload in self.ssrf_payloads['metadata_endpoints'][:metadata_limit]:
                payloads.append(('metadata', payload))
        
        # Include DNS-based payloads if canary domain provided
        if canary_domain:
            import random
            import string
            # Generate unique subdomain for OOB detection
            random_subdomain = ''.join(random.choices(string.ascii_lowercase, k=8))
            dns_payload = f'http://{random_subdomain}.{canary_domain}/'
            payloads.append(('dns_oob', dns_payload))
        
        # Include some bypass techniques (configurable limit)
        bypass_limit = 2  # Default limit for bypass techniques
        for payload in self.ssrf_payloads['bypass_techniques'][:bypass_limit]:
            payloads.append(('bypass', payload))
        
        return payloads
    
    async def _validate_oob_interaction(self, canary_domain: str, unique_subdomain: str, 
                                       timeout: int = 60) -> Dict[str, Any]:
        """
        Validate if an out-of-band interaction occurred with the canary domain.
        
        This method attempts to check if the target made a request to our canary domain.
        For a production implementation, this would integrate with a collaborator service.
        """
        validation_result = {
            'interaction_detected': False,
            'interaction_type': None,
            'timestamp': None,
            'details': {}
        }
        
        if not canary_domain:
            return validation_result
        
        try:
            # In a real implementation, this would query a collaborator service API
            # For now, we'll simulate the check with a simple HTTP request to see if
            # the canary domain is reachable (this is just a placeholder)
            
            # Example collaborator service integration (commented out):
            # collaborator_url = f"https://api.{canary_domain}/interactions"
            # async with httpx.AsyncClient() as client:
            #     response = await client.get(collaborator_url, params={
            #         'subdomain': unique_subdomain,
            #         'timeout': timeout
            #     })
            #     if response.status_code == 200:
            #         data = response.json()
            #         validation_result['interaction_detected'] = data.get('found', False)
            #         validation_result['interaction_type'] = data.get('type')
            #         validation_result['timestamp'] = data.get('timestamp')
            #         validation_result['details'] = data.get('details', {})
            
            # Placeholder: Simulate OOB check with a delay
            await asyncio.sleep(2)  # Simulate network delay
            
            # For demonstration purposes, we'll return a mock result
            # In production, this would be replaced with actual collaborator service integration
            validation_result['interaction_detected'] = False  # Default to False for safety
            validation_result['details'] = {
                'note': 'OOB validation placeholder - integrate with collaborator service',
                'canary_domain': canary_domain,
                'unique_subdomain': unique_subdomain
            }
            
        except Exception as e:
            print(f"Error validating OOB interaction: {e}")
            validation_result['details']['error'] = str(e)
        
        return validation_result
    
    async def _validate_oob_interactions(self, vulnerabilities: List[Vulnerability], 
                                        canary_domain: str, config: ScanConfig) -> List[Vulnerability]:
        """
        Validate out-of-band interactions for DNS-based SSRF payloads.
        
        This method checks if any of the discovered vulnerabilities involved
        DNS-based OOB payloads and validates if interactions occurred.
        """
        oob_vulnerabilities = []
        
        # Find vulnerabilities that used DNS OOB payloads
        dns_oob_vulns = [
            v for v in vulnerabilities 
            if v.evidence.get('payload_type') == 'dns_oob'
        ]
        
        for vuln in dns_oob_vulns:
            payload = vuln.evidence.get('payload', '')
            unique_subdomain = self._extract_subdomain_from_payload(payload)
            
            if unique_subdomain:
                # Wait a bit for potential OOB interaction
                await asyncio.sleep(3)
                
                # Validate the OOB interaction
                validation_result = await self._validate_oob_interaction(
                    canary_domain, unique_subdomain, timeout=60
                )
                
                if validation_result['interaction_detected']:
                    # Create a new vulnerability with confirmed OOB interaction
                    confirmed_vuln = Vulnerability(
                        module=self.name,
                        name=f"Confirmed Out-of-Band SSRF in parameter '{vuln.evidence['parameter']}'",
                        description=f"Parameter '{vuln.evidence['parameter']}' confirmed to make out-of-band requests via DNS lookup",
                        severity=SeverityLevel.CRITICAL,
                        confidence=1.0,  # Very high confidence for confirmed OOB
                        affected_urls=vuln.affected_urls,
                        evidence={
                            **vuln.evidence,
                            'oob_confirmed': True,
                            'oob_validation': validation_result,
                            'unique_subdomain': unique_subdomain,
                        },
                        remediation=vuln.remediation,
                        references=vuln.references,
                        cwe_ids=vuln.cwe_ids
                    )
                    oob_vulnerabilities.append(confirmed_vuln)
                else:
                    # Update the original vulnerability with OOB validation info
                    vuln.evidence['oob_attempted'] = True
                    vuln.evidence['oob_validation'] = validation_result
                    vuln.evidence['unique_subdomain'] = unique_subdomain
        
        return oob_vulnerabilities
    
    async def _phase1_intelligent_discovery(self, target_url: str, config: ScanConfig) -> Dict[str, Any]:
        """Phase 1: Intelligent Discovery using headless browser."""
        from .ssrf_scanner_phases import phase1_intelligent_discovery
        return await phase1_intelligent_discovery(target_url, config)
    
    async def _phase2_contextual_testing(self, captured_requests: List[Dict], baseline: Dict[str, Any],
                                        enable_dangerous: bool, canary_domain: str,
                                        config: ScanConfig) -> Dict[str, Any]:
        """Phase 2: Contextual Testing with captured API requests."""
        from .ssrf_scanner_phases import phase2_contextual_testing
        return await phase2_contextual_testing(
            captured_requests, baseline, enable_dangerous, canary_domain, config, self
        )
    
    async def _phase3_advanced_verification(self, vulnerabilities: List[Vulnerability],
                                           canary_domain: str, config: ScanConfig) -> Dict[str, Any]:
        """Phase 3: Advanced Verification with OOB detection."""
        from .ssrf_scanner_phases import phase3_advanced_verification
        return await phase3_advanced_verification(vulnerabilities, canary_domain, config)
    
    def _extract_subdomain_from_payload(self, payload: str) -> Optional[str]:
        """Extract the unique subdomain from a DNS OOB payload."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(payload)
            hostname = parsed.hostname
            if hostname and '.' in hostname:
                parts = hostname.split('.')
                if len(parts) >= 2:
                    return parts[0]  # Return the subdomain part
        except:
            pass
        return None
    
    def _analyze_response_for_ssrf(self, response: httpx.Response, baseline: Dict[str, Any],
                                   payload: str, payload_type: str, elapsed: float) -> Dict[str, Any]:
        """Analyze response for SSRF indicators."""
        evidence = {
            'is_vulnerable': False,
            'confidence': 0.0,
            'indicators': [],
            'response_snippet': '',
        }
        
        response_text = response.text.lower() if response.text else ''
        
        # Check for error signatures
        for signature in self.ssrf_error_signatures:
            if signature in response_text:
                evidence['is_vulnerable'] = True
                evidence['indicators'].append(f'error_signature:{signature}')
                evidence['response_snippet'] = response.text[:500]
                
                # High confidence for specific errors
                if any(err in signature for err in ['connection refused', 'econnrefused', 'timeout']):
                    evidence['confidence'] = 0.9
                elif 'metadata' in signature or 'instance-id' in signature:
                    evidence['confidence'] = 1.0  # Very high for metadata
                else:
                    evidence['confidence'] = 0.7
                break
        
        # Check for metadata content indicators
        if payload_type == 'metadata' and not evidence['is_vulnerable']:
            metadata_indicators = [
                'ami-id', 'instance-id', 'instance-type',
                'availability-zone', 'public-keys', 'security-credentials',
                'computemetadata', 'metadata.google.internal'
            ]
            
            for indicator in metadata_indicators:
                if indicator in response_text:
                    evidence['is_vulnerable'] = True
                    evidence['confidence'] = 1.0
                    evidence['indicators'].append(f'metadata_content:{indicator}')
                    evidence['response_snippet'] = response.text[:500]
                    break
        
        # Check for significant response differences
        if not evidence['is_vulnerable'] and baseline:
            # Status code change
            if response.status_code != baseline.get('status_code', 200):
                if response.status_code in [500, 502, 503, 504]:
                    evidence['indicators'].append(f'status_change:{response.status_code}')
                    if not evidence['is_vulnerable']:
                        evidence['is_vulnerable'] = True
                        evidence['confidence'] = 0.5
            
            # Response size anomaly
            baseline_length = baseline.get('content_length', 0)
            if baseline_length > 0:
                size_diff = abs(len(response.content) - baseline_length)
                if size_diff > baseline_length * 0.5:  # 50% difference
                    evidence['indicators'].append(f'size_anomaly:{size_diff}')
                    if not evidence['is_vulnerable'] and size_diff > 1000:
                        evidence['is_vulnerable'] = True
                        evidence['confidence'] = max(evidence['confidence'], 0.4)
            
            # Timing anomaly
            baseline_time = baseline.get('response_time', 1000)
            if elapsed > baseline_time * 2.5 and elapsed > 2000:  # 2.5x baseline and > 2 seconds
                evidence['indicators'].append(f'timing_anomaly:{elapsed}ms')
                if not evidence['is_vulnerable']:
                    evidence['is_vulnerable'] = True
                    evidence['confidence'] = max(evidence['confidence'], 0.5)
        
        # Check for localhost/internal IP in response
        if not evidence['is_vulnerable']:
            ip_patterns = [
                r'127\.0\.0\.1', r'localhost', r'0\.0\.0\.0',
                r'192\.168\.\d+\.\d+', r'10\.\d+\.\d+\.\d+',
                r'172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+',
                r'169\.254\.169\.254'
            ]
            
            for pattern in ip_patterns:
                if re.search(pattern, response_text):
                    evidence['is_vulnerable'] = True
                    evidence['confidence'] = 0.6
                    evidence['indicators'].append(f'ip_in_response:{pattern}')
                    evidence['response_snippet'] = response.text[:500]
                    break
        
        return evidence
    
    def _create_vulnerability(self, param_name: str, payload: str, payload_type: str,
                            url: str, evidence: Dict[str, Any], method: str) -> Vulnerability:
        """Create a vulnerability object based on evidence."""
        # Determine severity based on payload type and confidence
        severity = SeverityLevel.HIGH
        
        if payload_type == 'metadata' and evidence['confidence'] >= 0.9:
            severity = SeverityLevel.CRITICAL
            name = f"Cloud Metadata SSRF in parameter '{param_name}'"
            description = f"Parameter '{param_name}' allows access to cloud metadata endpoints"
        elif payload_type in ['localhost', 'internal'] and evidence['confidence'] >= 0.7:
            severity = SeverityLevel.HIGH
            name = f"Internal Network SSRF in parameter '{param_name}'"
            description = f"Parameter '{param_name}' allows access to internal network resources"
        elif 'timing' in str(evidence.get('indicators', [])):
            severity = SeverityLevel.MEDIUM
            name = f"Blind SSRF (timing-based) in parameter '{param_name}'"
            description = f"Parameter '{param_name}' shows timing delays indicating SSRF"
        else:
            name = f"SSRF in parameter '{param_name}'"
            description = f"Parameter '{param_name}' is vulnerable to Server-Side Request Forgery"
        
        # Adjust confidence based on evidence strength
        confidence = evidence['confidence']
        if len(evidence.get('indicators', [])) > 1:
            confidence = min(1.0, confidence * 1.1)  # Boost confidence for multiple indicators
        
        return Vulnerability(
            module=self.name,
            name=name,
            description=description,
            severity=severity,
            confidence=confidence,
            affected_urls=[url],
            evidence={
                'parameter': param_name,
                'payload': payload,
                'payload_type': payload_type,
                'method': method,
                'indicators': evidence.get('indicators', []),
                'response_snippet': evidence.get('response_snippet', '')[:500],
            },
            remediation=self._get_remediation(payload_type),
            references=[
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://portswigger.net/web-security/ssrf",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
            ],
            cwe_ids=["CWE-918"]
        )
    
    def _get_remediation(self, payload_type: str) -> str:
        """Get appropriate remediation advice based on SSRF type."""
        base_remediation = (
            "1. Implement strict input validation and URL whitelisting.\n"
            "2. Use a whitelist of allowed protocols (http/https only).\n"
            "3. Validate and sanitize URLs before making requests.\n"
            "4. Disable unnecessary URL schemas (file://, gopher://, etc.).\n"
            "5. Implement network segmentation to limit internal access."
        )
        
        if payload_type == 'metadata':
            return base_remediation + (
                "\n6. Block access to cloud metadata endpoints (169.254.169.254)."
                "\n7. Use IMDSv2 on AWS to require session tokens."
                "\n8. Implement proper IAM roles with minimal permissions."
            )
        elif payload_type in ['localhost', 'internal']:
            return base_remediation + (
                "\n6. Block requests to private IP ranges (RFC 1918)."
                "\n7. Block requests to localhost and loopback addresses."
                "\n8. Use a separate network for outbound requests."
            )
        else:
            return base_remediation