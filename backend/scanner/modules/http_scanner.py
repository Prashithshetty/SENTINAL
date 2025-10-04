"""HTTP Security Scanner Module for checking HTTP/HTTPS security configurations and headers."""

import asyncio
import httpx
import requests
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from urllib.parse import urlparse, urljoin
import re
from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)

class HTTPSecurityScanner(BaseScannerModule):
    """HTTP/HTTPS security configuration and header scanner with reduced false positives."""
    
    def __init__(self):
        super().__init__()
        self.name = "HTTPSecurityScanner"
        self.description = "Analyzes HTTP/HTTPS security headers and configurations with context awareness"
        self.scan_type = ScanType.PASSIVE
        
        # Application context detection patterns
        self.app_patterns = {
            'api': {
                'patterns': ['/api/', '/v1/', '/v2/', '/graphql', '.json', '/rest/'],
                'relevant_headers': ['strict-transport-security', 'x-content-type-options'],
                'skip_headers': ['x-frame-options']  # APIs don't need clickjacking protection
            },
            'static': {
                'patterns': ['.css', '.js', '.png', '.jpg', '.gif', '.svg', '.ico', '/static/'],
                'relevant_headers': ['cache-control'],
                'skip_headers': ['x-frame-options', 'content-security-policy']
            },
            'admin': {
                'patterns': ['/admin', '/dashboard', '/panel', '/console', '/manage'],
                'relevant_headers': ['all'],  # Admin panels need all security headers
                'severity_boost': True  # Increase severity for admin panels
            }
        }
        
        # Security headers to check
        self.security_headers = {
            'strict-transport-security': {
                'name': 'HTTP Strict Transport Security (HSTS)',
                'required': True,
                'severity': SeverityLevel.MEDIUM,
                'check_value': self._check_hsts_value
            },
            'x-frame-options': {
                'name': 'X-Frame-Options',
                'required': True,
                'severity': SeverityLevel.MEDIUM,
                'valid_values': ['DENY', 'SAMEORIGIN'],
            },
            'x-content-type-options': {
                'name': 'X-Content-Type-Options',
                'required': True,
                'severity': SeverityLevel.LOW,
                'valid_values': ['nosniff'],
            },
            'x-xss-protection': {
                'name': 'X-XSS-Protection',
                'required': False,  # Deprecated but still checked
                'severity': SeverityLevel.LOW,
                'valid_values': ['1; mode=block'],
            },
            'content-security-policy': {
                'name': 'Content Security Policy (CSP)',
                'required': True,
                'severity': SeverityLevel.HIGH,
                'check_value': self._check_csp_value
            },
            'referrer-policy': {
                'name': 'Referrer-Policy',
                'required': False,
                'severity': SeverityLevel.LOW,
                'valid_values': [
                    'no-referrer', 'no-referrer-when-downgrade', 
                    'origin', 'origin-when-cross-origin',
                    'same-origin', 'strict-origin',
                    'strict-origin-when-cross-origin'
                ],
            },
            'permissions-policy': {
                'name': 'Permissions-Policy',
                'required': False,
                'severity': SeverityLevel.LOW,
            },
            'x-permitted-cross-domain-policies': {
                'name': 'X-Permitted-Cross-Domain-Policies',
                'required': False,
                'severity': SeverityLevel.LOW,
                'valid_values': ['none', 'master-only', 'by-content-type', 'all'],
            },
        }
        
        # Cookie flags to check
        self.cookie_flags = {
            'httponly': {
                'name': 'HttpOnly',
                'description': 'Prevents JavaScript access to cookies',
                'severity': SeverityLevel.MEDIUM
            },
            'secure': {
                'name': 'Secure',
                'description': 'Ensures cookies are only sent over HTTPS',
                'severity': SeverityLevel.MEDIUM
            },
            'samesite': {
                'name': 'SameSite',
                'description': 'Prevents CSRF attacks',
                'severity': SeverityLevel.MEDIUM,
                'valid_values': ['Strict', 'Lax', 'None']
            }
        }
        
        # Common misconfigurations to check
        self.misconfigurations = [
            'server_version_disclosure',
            'x_powered_by_disclosure',
            'insecure_http_methods',
            'cors_misconfiguration',
            'mixed_content',
            'clickjacking_vulnerable',
            'cache_control_missing',
        ]
    
    def _detect_application_context(self, url: str, response_headers: Dict, response_text: str) -> Dict[str, Any]:
        """Detect the application context to determine which security headers are relevant."""
        context = {
            'type': 'web',  # default
            'is_api': False,
            'is_static': False,
            'is_admin': False,
            'is_auth': False,
            'is_sensitive': False,
            'technology_stack': []
        }
        
        # Check URL patterns
        url_lower = url.lower()
        for app_type, config in self.app_patterns.items():
            if any(pattern in url_lower for pattern in config['patterns']):
                context[f'is_{app_type}'] = True
                if app_type in ['admin', 'auth']:
                    context['is_sensitive'] = True
        
        # Check response headers for API indicators
        content_type = response_headers.get('content-type', '').lower()
        if 'application/json' in content_type or 'application/xml' in content_type:
            context['is_api'] = True
            context['type'] = 'api'
        
        # Check for static content
        if any(ext in url_lower for ext in ['.css', '.js', '.png', '.jpg', '.gif', '.svg']):
            context['is_static'] = True
            context['type'] = 'static'
        
        return context
    
    def _calculate_confidence(self, evidence: Dict[str, Any], context: Dict[str, Any]) -> float:
        """Calculate confidence score based on evidence and context."""
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on evidence
        if evidence:
            if 'header_value' in evidence:
                confidence += 0.2
            if context.get('is_sensitive'):
                confidence += 0.2
        
        # Decrease confidence for certain contexts
        if context.get('is_static'):
            confidence *= 0.5  # Static files are less critical
        if context.get('is_api'):
            confidence *= 0.8  # APIs have different security requirements
        
        return min(confidence, 1.0)
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is a valid HTTP/HTTPS URL."""
        if not target.startswith(('http://', 'https://')):
            # Try adding https://
            target = f"https://{target}"
        
        try:
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform HTTP security scan."""
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'headers': {},
            'cookies': [],
            'server_info': {},
            'redirects': [],
            'methods_allowed': [],
        }
        statistics = {
            'headers_checked': 0,
            'missing_headers': 0,
            'weak_headers': 0,
            'cookies_analyzed': 0,
            'insecure_cookies': 0,
            'misconfigurations_found': 0,
        }
        
        try:
            # Ensure URL has scheme
            target_url = config.target
            if not target_url.startswith(('http://', 'https://')):
                target_url = f"https://{target_url}"
            
            # Perform HTTP request
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=httpx.Timeout(config.timeout)
            ) as client:
                
                # Main request
                response = await client.get(target_url)
                
                # Store response headers
                info['headers'] = dict(response.headers)
                statistics['headers_checked'] = len(self.security_headers)
                
                # Check security headers
                header_vulns = self._check_security_headers(response.headers, target_url)
                vulnerabilities.extend(header_vulns)
                statistics['missing_headers'] = len([v for v in header_vulns if 'Missing' in v.name])
                statistics['weak_headers'] = len([v for v in header_vulns if 'Weak' in v.name or 'Misconfigured' in v.name])
                
                # Check cookies
                if 'set-cookie' in response.headers:
                    cookie_vulns, cookie_info = self._analyze_cookies(response.headers.get_list('set-cookie'), target_url)
                    vulnerabilities.extend(cookie_vulns)
                    info['cookies'] = cookie_info
                    statistics['cookies_analyzed'] = len(cookie_info)
                    statistics['insecure_cookies'] = len(cookie_vulns)
                
                # Check server information disclosure
                server_vulns = self._check_server_disclosure(response.headers, target_url)
                vulnerabilities.extend(server_vulns)
                
                # Check for HTTP to HTTPS redirect
                if target_url.startswith('http://'):
                    redirect_vulns = await self._check_https_redirect(client, target_url)
                    vulnerabilities.extend(redirect_vulns)
                
                # Check for mixed content (if HTTPS)
                if target_url.startswith('https://'):
                    mixed_content_vulns = await self._check_mixed_content(client, target_url, response.text)
                    vulnerabilities.extend(mixed_content_vulns)
                
                # Check allowed HTTP methods
                if config.scan_type in [ScanType.ACTIVE, ScanType.AGGRESSIVE]:
                    methods_vulns, allowed_methods = await self._check_http_methods(client, target_url)
                    vulnerabilities.extend(methods_vulns)
                    info['methods_allowed'] = allowed_methods
                
                # Check CORS configuration
                cors_vulns = await self._check_cors_configuration(client, target_url)
                vulnerabilities.extend(cors_vulns)
                
                # Check for clickjacking vulnerability
                clickjacking_vulns = self._check_clickjacking(response.headers, target_url)
                vulnerabilities.extend(clickjacking_vulns)
                
                # Check cache control
                cache_vulns = self._check_cache_control(response.headers, target_url)
                vulnerabilities.extend(cache_vulns)
                
                # Count misconfigurations
                statistics['misconfigurations_found'] = len([
                    v for v in vulnerabilities 
                    if any(misc in v.name.lower() for misc in ['misconfigur', 'disclosure', 'missing'])
                ])
                
        except httpx.TimeoutException:
            errors.append(f"HTTP request timed out for {config.target}")
        except Exception as e:
            errors.append(f"HTTP scan failed: {str(e)}")
        
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
    
    def _check_security_headers(self, headers: httpx.Headers, target_url: str) -> List[Vulnerability]:
        """Check for missing or misconfigured security headers."""
        vulnerabilities = []
        
        for header_key, header_config in self.security_headers.items():
            header_value = headers.get(header_key)
            
            if not header_value:
                # Header is missing
                if header_config.get('required', False):
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name=f"Missing Security Header: {header_config['name']}",
                            description=f"The {header_config['name']} header is not set",
                            severity=header_config.get('severity', SeverityLevel.LOW),
                            confidence=1.0,
                            affected_urls=[target_url],
                            remediation=self._get_header_remediation(header_key),
                            references=self._get_header_references(header_key)
                        )
                    )
            else:
                # Header is present, check value
                if 'check_value' in header_config:
                    # Custom value checker
                    vuln = header_config['check_value'](header_value, target_url)
                    if vuln:
                        vulnerabilities.append(vuln)
                elif 'valid_values' in header_config:
                    # Check against valid values
                    if not any(valid in header_value for valid in header_config['valid_values']):
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"Weak {header_config['name']} Configuration",
                                description=f"The {header_config['name']} header has a weak value: {header_value}",
                                severity=SeverityLevel.LOW,
                                confidence=0.8,
                                affected_urls=[target_url],
                                evidence={'header_value': header_value},
                                remediation=self._get_header_remediation(header_key),
                            )
                        )
        
        return vulnerabilities
    
    def _check_hsts_value(self, value: str, target_url: str) -> Optional[Vulnerability]:
        """Check HSTS header value for weaknesses."""
        # Parse max-age
        max_age_match = re.search(r'max-age=(\d+)', value)
        if not max_age_match:
            return Vulnerability(
                module=self.name,
                name="Invalid HSTS Header",
                description="HSTS header is missing max-age directive",
                severity=SeverityLevel.MEDIUM,
                confidence=1.0,
                affected_urls=[target_url],
                evidence={'header_value': value},
                remediation="Add max-age directive to HSTS header",
            )
        
        max_age = int(max_age_match.group(1))
        if max_age < 31536000:  # Less than 1 year
            return Vulnerability(
                module=self.name,
                name="Weak HSTS Configuration",
                description=f"HSTS max-age is too short ({max_age} seconds)",
                severity=SeverityLevel.LOW,
                confidence=0.9,
                affected_urls=[target_url],
                evidence={'max_age': max_age},
                remediation="Set HSTS max-age to at least 31536000 (1 year)",
            )
        
        # Check for includeSubDomains
        if 'includeSubDomains' not in value:
            return Vulnerability(
                module=self.name,
                name="HSTS Missing includeSubDomains",
                description="HSTS header should include subdomains for complete protection",
                severity=SeverityLevel.LOW,
                confidence=0.7,
                affected_urls=[target_url],
                evidence={'header_value': value},
                remediation="Add includeSubDomains directive to HSTS header",
            )
        
        return None
    
    def _check_csp_value(self, value: str, target_url: str) -> Optional[Vulnerability]:
        """Check Content Security Policy for weaknesses."""
        weaknesses = []
        
        # Check for unsafe directives
        if "'unsafe-inline'" in value:
            weaknesses.append("Uses 'unsafe-inline' which allows inline scripts")
        if "'unsafe-eval'" in value:
            weaknesses.append("Uses 'unsafe-eval' which allows eval()")
        if '*' in value and 'default-src' in value:
            weaknesses.append("Uses wildcard (*) in default-src")
        
        # Check for missing directives
        important_directives = ['default-src', 'script-src', 'style-src']
        for directive in important_directives:
            if directive not in value:
                weaknesses.append(f"Missing {directive} directive")
        
        if weaknesses:
            return Vulnerability(
                module=self.name,
                name="Weak Content Security Policy",
                description=f"CSP has weaknesses: {'; '.join(weaknesses)}",
                severity=SeverityLevel.MEDIUM,
                confidence=0.8,
                affected_urls=[target_url],
                evidence={'csp_value': value, 'weaknesses': weaknesses},
                remediation="Strengthen CSP by removing unsafe directives and adding missing ones",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"]
            )
        
        return None
    
    def _analyze_cookies(self, cookies: List[str], target_url: str) -> tuple:
        """Analyze cookies for security flags."""
        vulnerabilities = []
        cookie_info = []
        
        for cookie_str in cookies:
            cookie_data = self._parse_cookie(cookie_str)
            cookie_info.append(cookie_data)
            
            # Check for missing security flags
            missing_flags = []
            
            if not cookie_data.get('httponly', False):
                missing_flags.append('HttpOnly')
            
            if target_url.startswith('https://') and not cookie_data.get('secure', False):
                missing_flags.append('Secure')
            
            if not cookie_data.get('samesite'):
                missing_flags.append('SameSite')
            
            if missing_flags:
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name=f"Insecure Cookie: {cookie_data['name']}",
                        description=f"Cookie '{cookie_data['name']}' is missing security flags: {', '.join(missing_flags)}",
                        severity=SeverityLevel.MEDIUM,
                        confidence=0.9,
                        affected_urls=[target_url],
                        evidence={'cookie': cookie_data, 'missing_flags': missing_flags},
                        remediation=f"Add {', '.join(missing_flags)} flags to the cookie",
                    )
                )
        
        return vulnerabilities, cookie_info
    
    def _parse_cookie(self, cookie_str: str) -> Dict[str, Any]:
        """Parse cookie string to extract attributes."""
        parts = cookie_str.split(';')
        cookie_data = {}
        
        # First part is name=value
        if '=' in parts[0]:
            name, value = parts[0].split('=', 1)
            cookie_data['name'] = name.strip()
            cookie_data['value'] = value.strip()
        
        # Parse attributes
        for part in parts[1:]:
            part = part.strip().lower()
            if '=' in part:
                key, val = part.split('=', 1)
                cookie_data[key] = val
            else:
                # Boolean attributes
                cookie_data[part] = True
        
        return cookie_data
    
    def _check_server_disclosure(self, headers: httpx.Headers, target_url: str) -> List[Vulnerability]:
        """Check for server information disclosure."""
        vulnerabilities = []
        
        # Check Server header
        server_header = headers.get('server')
        if server_header:
            # Check if version is disclosed
            if re.search(r'\d+\.\d+', server_header):
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name="Server Version Disclosure",
                        description=f"Server header discloses version information: {server_header}",
                        severity=SeverityLevel.LOW,
                        confidence=0.9,
                        affected_urls=[target_url],
                        evidence={'server_header': server_header},
                        remediation="Remove version information from Server header",
                    )
                )
        
        # Check X-Powered-By header
        powered_by = headers.get('x-powered-by')
        if powered_by:
            vulnerabilities.append(
                Vulnerability(
                    module=self.name,
                    name="Technology Disclosure via X-Powered-By",
                    description=f"X-Powered-By header discloses technology: {powered_by}",
                    severity=SeverityLevel.LOW,
                    confidence=1.0,
                    affected_urls=[target_url],
                    evidence={'x_powered_by': powered_by},
                    remediation="Remove X-Powered-By header",
                )
            )
        
        # Check X-AspNet-Version header
        aspnet_version = headers.get('x-aspnet-version')
        if aspnet_version:
            vulnerabilities.append(
                Vulnerability(
                    module=self.name,
                    name="ASP.NET Version Disclosure",
                    description=f"X-AspNet-Version header discloses version: {aspnet_version}",
                    severity=SeverityLevel.LOW,
                    confidence=1.0,
                    affected_urls=[target_url],
                    evidence={'x_aspnet_version': aspnet_version},
                    remediation="Remove X-AspNet-Version header",
                )
            )
        
        return vulnerabilities
    
    async def _check_https_redirect(self, client: httpx.AsyncClient, http_url: str) -> List[Vulnerability]:
        """Check if HTTP properly redirects to HTTPS."""
        vulnerabilities = []
        
        try:
            # Make request without following redirects
            response = await client.get(http_url, follow_redirects=False)
            
            if response.status_code not in [301, 302, 303, 307, 308]:
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name="Missing HTTP to HTTPS Redirect",
                        description="HTTP does not redirect to HTTPS",
                        severity=SeverityLevel.MEDIUM,
                        confidence=1.0,
                        affected_urls=[http_url],
                        remediation="Configure server to redirect all HTTP traffic to HTTPS",
                    )
                )
            elif response.status_code in [302, 303, 307]:
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name="Temporary HTTP to HTTPS Redirect",
                        description="HTTP uses temporary redirect instead of permanent",
                        severity=SeverityLevel.LOW,
                        confidence=0.9,
                        affected_urls=[http_url],
                        evidence={'status_code': response.status_code},
                        remediation="Use permanent redirect (301 or 308) for HTTP to HTTPS",
                    )
                )
        except:
            pass
        
        return vulnerabilities
    
    async def _check_mixed_content(self, client: httpx.AsyncClient, url: str, html_content: str) -> List[Vulnerability]:
        """Check for mixed content (HTTP resources on HTTPS page)."""
        vulnerabilities = []
        mixed_content = []
        
        # Check for HTTP URLs in HTML
        http_pattern = re.compile(r'(src|href|action)=["\']http://[^"\']+["\']', re.IGNORECASE)
        matches = http_pattern.findall(html_content)
        
        if matches:
            mixed_content.extend(matches)
        
        # Check for protocol-relative URLs that might load over HTTP
        protocol_relative = re.compile(r'(src|href|action)=["\']//', re.IGNORECASE)
        if protocol_relative.search(html_content):
            mixed_content.append("Protocol-relative URLs detected")
        
        if mixed_content:
            vulnerabilities.append(
                Vulnerability(
                    module=self.name,
                    name="Mixed Content",
                    description="HTTPS page loads resources over HTTP",
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.8,
                    affected_urls=[url],
                    evidence={'mixed_content_count': len(mixed_content)},
                    remediation="Load all resources over HTTPS",
                    references=["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"]
                )
            )
        
        return vulnerabilities
    
    async def _check_http_methods(self, client: httpx.AsyncClient, url: str) -> tuple:
        """Check allowed HTTP methods."""
        vulnerabilities = []
        allowed_methods = []
        
        try:
            # Send OPTIONS request
            response = await client.options(url)
            
            if 'allow' in response.headers:
                allowed_methods = [m.strip() for m in response.headers['allow'].split(',')]
                
                # Check for dangerous methods
                dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                found_dangerous = [m for m in dangerous_methods if m in allowed_methods]
                
                if found_dangerous:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Dangerous HTTP Methods Enabled",
                            description=f"Server allows dangerous HTTP methods: {', '.join(found_dangerous)}",
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.9,
                            affected_urls=[url],
                            evidence={'methods': found_dangerous},
                            remediation="Disable unnecessary HTTP methods",
                        )
                    )
                
                # Check for TRACE (XST vulnerability)
                if 'TRACE' in allowed_methods:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Cross-Site Tracing (XST) Vulnerability",
                            description="TRACE method is enabled, allowing XST attacks",
                            severity=SeverityLevel.MEDIUM,
                            confidence=1.0,
                            affected_urls=[url],
                            remediation="Disable TRACE method",
                            cwe_ids=["CWE-693"]
                        )
                    )
        except:
            pass
        
        return vulnerabilities, allowed_methods
    
    async def _check_cors_configuration(self, client: httpx.AsyncClient, url: str) -> List[Vulnerability]:
        """Check for CORS misconfigurations."""
        vulnerabilities = []
        
        try:
            # Send request with Origin header
            headers = {'Origin': 'https://evil.com'}
            response = await client.get(url, headers=headers)
            
            acao = response.headers.get('access-control-allow-origin')
            acac = response.headers.get('access-control-allow-credentials')
            
            if acao:
                # Check for wildcard with credentials
                if acao == '*' and acac == 'true':
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="CORS Misconfiguration: Wildcard with Credentials",
                            description="CORS allows any origin with credentials",
                            severity=SeverityLevel.HIGH,
                            confidence=1.0,
                            affected_urls=[url],
                            evidence={'acao': acao, 'acac': acac},
                            remediation="Don't use wildcard (*) with credentials",
                            cwe_ids=["CWE-942"]
                        )
                    )
                # Check if reflects any origin
                elif acao == 'https://evil.com':
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="CORS Misconfiguration: Reflects Any Origin",
                            description="CORS reflects any origin header",
                            severity=SeverityLevel.HIGH if acac == 'true' else SeverityLevel.MEDIUM,
                            confidence=1.0,
                            affected_urls=[url],
                            evidence={'reflected_origin': acao},
                            remediation="Whitelist allowed origins instead of reflecting Origin header",
                            cwe_ids=["CWE-942"]
                        )
                    )
                # Check for null origin
                elif acao == 'null':
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="CORS Misconfiguration: Null Origin Allowed",
                            description="CORS allows null origin",
                            severity=SeverityLevel.MEDIUM,
                            confidence=1.0,
                            affected_urls=[url],
                            remediation="Don't allow null origin",
                        )
                    )
        except:
            pass
        
        return vulnerabilities
    
    def _check_clickjacking(self, headers: httpx.Headers, url: str) -> List[Vulnerability]:
        """Check for clickjacking vulnerability."""
        vulnerabilities = []
        
        x_frame = headers.get('x-frame-options')
        csp = headers.get('content-security-policy')
        
        # Check if any protection exists
        has_xfo = x_frame and x_frame.upper() in ['DENY', 'SAMEORIGIN']
        has_csp_frame = csp and 'frame-ancestors' in csp
        
        if not has_xfo and not has_csp_frame:
            vulnerabilities.append(
                Vulnerability(
                    module=self.name,
                    name="Clickjacking Vulnerability",
                    description="No clickjacking protection (missing X-Frame-Options and CSP frame-ancestors)",
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.9,
                    affected_urls=[url],
                    remediation="Add X-Frame-Options: DENY or SAMEORIGIN header, or use CSP frame-ancestors",
                    cwe_ids=["CWE-1021"]
                )
            )
        
        return vulnerabilities
    
    def _check_cache_control(self, headers: httpx.Headers, url: str) -> List[Vulnerability]:
        """Check for cache control issues."""
        vulnerabilities = []
        
        cache_control = headers.get('cache-control')
        pragma = headers.get('pragma')
        
        # Check if caching sensitive content
        if not cache_control or 'no-store' not in cache_control:
            # This might be a login page or contain sensitive data
            if any(sensitive in url.lower() for sensitive in ['login', 'admin', 'account', 'profile']):
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name="Missing Cache Control for Sensitive Page",
                        description="Sensitive page may be cached by browsers or proxies",
                        severity=SeverityLevel.MEDIUM,
                        confidence=0.7,
                        affected_urls=[url],
                        evidence={'cache_control': cache_control},
                        remediation="Add Cache-Control: no-store, no-cache for sensitive pages",
                    )
                )
        
        return vulnerabilities
    
    def _get_header_remediation(self, header: str) -> str:
        """Get remediation advice for specific headers."""
        remediations = {
            'strict-transport-security': "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            'x-frame-options': "Add X-Frame-Options: DENY or SAMEORIGIN",
            'x-content-type-options': "Add X-Content-Type-Options: nosniff",
            'x-xss-protection': "Add X-XSS-Protection: 1; mode=block (though modern browsers have this by default)",
            'content-security-policy': "Implement a Content Security Policy appropriate for your application",
            'referrer-policy': "Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer",
            'permissions-policy': "Add Permissions-Policy header to control browser features",
        }
        return remediations.get(header, f"Configure {header} header appropriately")
    
    def _get_header_references(self, header: str) -> List[str]:
        """Get references for specific headers."""
        references = {
            'strict-transport-security': [
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                "https://hstspreload.org/"
            ],
            'content-security-policy': [
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                "https://csp-evaluator.withgoogle.com/"
            ],
            'x-frame-options': [
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
            ],
        }
        return references.get(header, ["https://owasp.org/www-project-secure-headers/"])
