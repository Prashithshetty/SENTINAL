"""Authenticated Scanner Module for testing vulnerabilities behind authentication."""

import asyncio
import httpx
import re
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)

class AuthenticatedScanner(BaseScannerModule):
    """Scanner for testing vulnerabilities in authenticated areas of web applications."""
    
    def __init__(self):
        super().__init__()
        self.name = "AuthenticatedScanner"
        self.description = "Performs vulnerability scanning on authenticated areas of web applications"
        self.scan_type = ScanType.ACTIVE
        
        # Common login form selectors
        self.login_selectors = {
            'username_fields': [
                'input[name="username"]',
                'input[name="user"]',
                'input[name="email"]',
                'input[name="login"]',
                'input[name="uid"]',
                'input[type="email"]',
                'input[id*="user"]',
                'input[id*="email"]',
                'input[id*="login"]',
            ],
            'password_fields': [
                'input[name="password"]',
                'input[name="pass"]',
                'input[name="pwd"]',
                'input[type="password"]',
                'input[id*="pass"]',
            ],
            'submit_buttons': [
                'button[type="submit"]',
                'input[type="submit"]',
                'button[id*="login"]',
                'button[id*="submit"]',
                'input[value*="Login"]',
                'input[value*="Sign in"]',
                'button:contains("Login")',
                'button:contains("Sign in")',
            ],
        }
        
        # Post-authentication vulnerability checks
        self.auth_checks = [
            'broken_access_control',
            'session_management',
            'csrf_protection',
            'privilege_escalation',
            'idor',
            'authenticated_xss',
            'authenticated_sqli',
        ]
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is suitable for authenticated scanning."""
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    def requires_auth(self) -> bool:
        """This module requires authentication credentials."""
        return True
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform authenticated vulnerability scan."""
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'login_successful': False,
            'authenticated_pages': [],
            'session_info': {},
            'vulnerabilities_found': [],
        }
        statistics = {
            'pages_scanned': 0,
            'forms_tested': 0,
            'access_control_tests': 0,
            'total_vulnerabilities': 0,
        }
        
        # Check if authentication credentials are provided
        if not config.auth or 'username' not in config.auth or 'password' not in config.auth:
            errors.append("Authentication credentials not provided")
            return ScanResult(
                module_name=self.name,
                success=False,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                vulnerabilities=vulnerabilities,
                errors=errors,
                warnings=warnings,
                info=info,
                statistics=statistics
            )
        
        try:
            # Ensure URL has scheme
            target_url = config.target
            if not target_url.startswith(('http://', 'https://')):
                target_url = f"https://{target_url}"
            
            # 1. Perform login
            session_data = await self._perform_login(
                target_url,
                config.auth['username'],
                config.auth['password'],
                config.auth.get('login_url'),
                config.auth.get('login_type', 'auto')
            )
            
            if not session_data:
                errors.append("Failed to authenticate")
                return ScanResult(
                    module_name=self.name,
                    success=False,
                    started_at=started_at,
                    completed_at=datetime.utcnow(),
                    vulnerabilities=vulnerabilities,
                    errors=errors,
                    warnings=warnings,
                    info=info,
                    statistics=statistics
                )
            
            info['login_successful'] = True
            info['session_info'] = session_data
            
            # 2. Test for broken access control
            access_vulns = await self._test_broken_access_control(target_url, session_data)
            vulnerabilities.extend(access_vulns)
            statistics['access_control_tests'] = len(access_vulns)
            
            # 3. Test session management
            session_vulns = await self._test_session_management(target_url, session_data)
            vulnerabilities.extend(session_vulns)
            
            # 4. Test for CSRF protection
            csrf_vulns = await self._test_csrf_protection(target_url, session_data)
            vulnerabilities.extend(csrf_vulns)
            
            # 5. Test for IDOR vulnerabilities
            idor_vulns = await self._test_idor(target_url, session_data)
            vulnerabilities.extend(idor_vulns)
            
            # 6. Test for authenticated XSS
            xss_vulns = await self._test_authenticated_xss(target_url, session_data)
            vulnerabilities.extend(xss_vulns)
            
            # 7. Test for authenticated SQL injection
            sqli_vulns = await self._test_authenticated_sqli(target_url, session_data)
            vulnerabilities.extend(sqli_vulns)
            
            # 8. Test for privilege escalation
            priv_vulns = await self._test_privilege_escalation(target_url, session_data)
            vulnerabilities.extend(priv_vulns)
            
            # 9. Spider authenticated area
            pages = await self._spider_authenticated_area(target_url, session_data)
            info['authenticated_pages'] = pages
            statistics['pages_scanned'] = len(pages)
            
            # Update statistics
            statistics['total_vulnerabilities'] = len(vulnerabilities)
            
            for vuln in vulnerabilities:
                vuln_type = vuln.name.split(':')[0] if ':' in vuln.name else vuln.name
                info['vulnerabilities_found'].append(vuln_type)
            
        except Exception as e:
            errors.append(f"Authenticated scan failed: {str(e)}")
        
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
    
    async def _perform_login(self, url: str, username: str, password: str, 
                            login_url: Optional[str] = None, 
                            login_type: str = 'auto') -> Optional[Dict[str, Any]]:
        """Perform login and return session data."""
        session_data = {}
        
        try:
            if login_type == 'selenium' or login_type == 'auto':
                # Use Selenium for JavaScript-heavy sites
                session_data = await self._selenium_login(url, username, password, login_url)
            
            if not session_data and login_type in ['http', 'auto']:
                # Fallback to HTTP-based login
                session_data = await self._http_login(url, username, password, login_url)
            
        except Exception as e:
            return None
        
        return session_data
    
    async def _selenium_login(self, url: str, username: str, password: str, 
                             login_url: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Perform login using Selenium."""
        driver = None
        try:
            # Setup Chrome options
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
            
            # Create driver
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(30)
            
            # Navigate to login page
            if login_url:
                driver.get(login_url)
            else:
                # Try to find login page
                driver.get(url)
                login_links = driver.find_elements(By.PARTIAL_LINK_TEXT, 'Login') + \
                             driver.find_elements(By.PARTIAL_LINK_TEXT, 'Sign in') + \
                             driver.find_elements(By.PARTIAL_LINK_TEXT, 'Log in')
                
                if login_links:
                    login_links[0].click()
                    await asyncio.sleep(2)
            
            # Find and fill login form
            username_field = None
            password_field = None
            submit_button = None
            
            # Find username field
            for selector in self.login_selectors['username_fields']:
                try:
                    username_field = driver.find_element(By.CSS_SELECTOR, selector)
                    break
                except:
                    pass
            
            # Find password field
            for selector in self.login_selectors['password_fields']:
                try:
                    password_field = driver.find_element(By.CSS_SELECTOR, selector)
                    break
                except:
                    pass
            
            # Find submit button
            for selector in self.login_selectors['submit_buttons']:
                try:
                    submit_button = driver.find_element(By.CSS_SELECTOR, selector)
                    break
                except:
                    pass
            
            if username_field and password_field:
                username_field.clear()
                username_field.send_keys(username)
                password_field.clear()
                password_field.send_keys(password)
                
                if submit_button:
                    submit_button.click()
                else:
                    password_field.submit()
                
                # Wait for login to complete
                await asyncio.sleep(3)
                
                # Get cookies
                cookies = driver.get_cookies()
                
                # Convert to session data
                session_data = {
                    'cookies': {cookie['name']: cookie['value'] for cookie in cookies},
                    'authenticated_url': driver.current_url,
                    'method': 'selenium',
                }
                
                # Check if login was successful (URL changed or specific element present)
                if driver.current_url != url and driver.current_url != login_url:
                    return session_data
                
                # Check for common post-login indicators
                post_login_indicators = ['logout', 'dashboard', 'profile', 'account', 'welcome']
                page_source = driver.page_source.lower()
                
                if any(indicator in page_source for indicator in post_login_indicators):
                    return session_data
            
        except Exception as e:
            pass
        finally:
            if driver:
                driver.quit()
        
        return None
    
    async def _http_login(self, url: str, username: str, password: str, 
                         login_url: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Perform login using HTTP requests."""
        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            try:
                # Get login page to find form
                if not login_url:
                    # Try common login URLs
                    login_paths = ['/login', '/signin', '/auth/login', '/user/login', '/account/login']
                    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                    
                    for path in login_paths:
                        test_url = urljoin(base_url, path)
                        response = await client.get(test_url)
                        if response.status_code == 200:
                            login_url = test_url
                            break
                
                if not login_url:
                    login_url = url
                
                # Get login page
                response = await client.get(login_url)
                
                # Extract CSRF token if present
                csrf_token = None
                csrf_patterns = [
                    r'<input[^>]*name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
                    r'<input[^>]*name=["\']_csrf["\'][^>]*value=["\']([^"\']+)["\']',
                    r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
                ]
                
                for pattern in csrf_patterns:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        csrf_token = match.group(1)
                        break
                
                # Prepare login data
                login_data = {
                    'username': username,
                    'password': password,
                }
                
                # Add CSRF token if found
                if csrf_token:
                    login_data['csrf_token'] = csrf_token
                
                # Try alternative field names
                if 'username' not in response.text.lower():
                    login_data['email'] = username
                    del login_data['username']
                
                # Perform login
                response = await client.post(login_url, data=login_data)
                
                # Check if login was successful
                if response.status_code == 200:
                    # Check for login indicators
                    if any(indicator in response.text.lower() for indicator in ['logout', 'dashboard', 'profile']):
                        # Get cookies
                        cookies = {k: v for k, v in response.cookies.items()}
                        
                        return {
                            'cookies': cookies,
                            'authenticated_url': str(response.url),
                            'method': 'http',
                            'csrf_token': csrf_token,
                        }
                
            except:
                pass
        
        return None
    
    async def _test_broken_access_control(self, url: str, session_data: Dict[str, Any]) -> List[Vulnerability]:
        """Test for broken access control vulnerabilities."""
        vulnerabilities = []
        
        # Common admin/restricted paths to test
        restricted_paths = [
            '/admin', '/administrator', '/admin/dashboard',
            '/user/1', '/user/admin', '/profile/1',
            '/api/users', '/api/admin',
            '/settings', '/config', '/system',
            '/backup', '/database', '/logs',
        ]
        
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        
        async with httpx.AsyncClient(verify=False, cookies=session_data.get('cookies', {})) as client:
            for path in restricted_paths:
                test_url = urljoin(base_url, path)
                
                try:
                    response = await client.get(test_url)
                    
                    # Check if we can access admin/restricted areas
                    if response.status_code == 200:
                        # Check for admin indicators
                        admin_indicators = ['admin panel', 'administration', 'user management', 'system settings']
                        if any(indicator in response.text.lower() for indicator in admin_indicators):
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"Broken Access Control: {path}",
                                    description=f"Unauthorized access to restricted area: {path}",
                                    severity=SeverityLevel.HIGH,
                                    confidence=0.9,
                                    affected_urls=[test_url],
                                    evidence={
                                        'path': path,
                                        'status_code': response.status_code,
                                    },
                                    remediation="Implement proper access control checks for all restricted resources.",
                                    cwe_ids=["CWE-284", "CWE-639"]
                                )
                            )
                except:
                    pass
        
        # Test for IDOR by trying to access other users' resources
        idor_patterns = [
            '/user/{id}', '/profile/{id}', '/account/{id}',
            '/api/user/{id}', '/api/profile/{id}',
            '/order/{id}', '/invoice/{id}', '/document/{id}',
        ]
        
        for pattern in idor_patterns:
            for test_id in ['1', '2', '100', '999', 'admin']:
                test_url = urljoin(base_url, pattern.format(id=test_id))
                
                try:
                    async with httpx.AsyncClient(verify=False, cookies=session_data.get('cookies', {})) as client:
                        response = await client.get(test_url)
                        
                        if response.status_code == 200:
                            # Check if we're accessing another user's data
                            if 'user' in response.text.lower() or 'profile' in response.text.lower():
                                vulnerabilities.append(
                                    Vulnerability(
                                        module=self.name,
                                        name=f"IDOR Vulnerability: {pattern}",
                                        description="Insecure Direct Object Reference allows access to other users' data",
                                        severity=SeverityLevel.HIGH,
                                        confidence=0.8,
                                        affected_urls=[test_url],
                                        evidence={
                                            'pattern': pattern,
                                            'test_id': test_id,
                                        },
                                        remediation="Implement proper authorization checks for all object references.",
                                        cwe_ids=["CWE-639", "CWE-284"]
                                    )
                                )
                                break
                except:
                    pass
        
        return vulnerabilities
    
    async def _test_session_management(self, url: str, session_data: Dict[str, Any]) -> List[Vulnerability]:
        """Test for session management vulnerabilities."""
        vulnerabilities = []
        
        # Check session cookie security
        cookies = session_data.get('cookies', {})
        
        for cookie_name, cookie_value in cookies.items():
            # Check for session-related cookies
            if any(x in cookie_name.lower() for x in ['session', 'sess', 'sid', 'auth']):
                # Check if session ID is predictable
                if len(cookie_value) < 32:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Weak Session ID",
                            description=f"Session ID '{cookie_name}' appears to be weak or predictable",
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.7,
                            affected_urls=[url],
                            evidence={
                                'cookie_name': cookie_name,
                                'length': len(cookie_value),
                            },
                            remediation="Use cryptographically secure random session IDs with sufficient entropy.",
                            cwe_ids=["CWE-331", "CWE-6"]
                        )
                    )
                
                # Check for session fixation
                # Try to set a custom session ID and see if it's accepted
                async with httpx.AsyncClient(verify=False) as client:
                    custom_session = {'test_session': 'fixated_session_id'}
                    response = await client.get(url, cookies=custom_session)
                    
                    if 'test_session' in response.cookies:
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="Session Fixation",
                                description="Application accepts externally set session IDs",
                                severity=SeverityLevel.HIGH,
                                confidence=0.8,
                                affected_urls=[url],
                                evidence={'test_performed': 'session_fixation'},
                                remediation="Regenerate session IDs after successful authentication.",
                                cwe_ids=["CWE-384"]
                            )
                        )
        
        # Test concurrent sessions
        # Try to use the same session from different user agents
        async with httpx.AsyncClient(verify=False, cookies=cookies) as client:
            # First request with normal user agent
            response1 = await client.get(url, headers={'User-Agent': 'Mozilla/5.0'})
            
            # Second request with different user agent
            response2 = await client.get(url, headers={'User-Agent': 'Bot/1.0'})
            
            if response1.status_code == 200 and response2.status_code == 200:
                warnings = ["Multiple concurrent sessions allowed with same credentials"]
        
        return vulnerabilities
    
    async def _test_csrf_protection(self, url: str, session_data: Dict[str, Any]) -> List[Vulnerability]:
        """Test for CSRF protection."""
        vulnerabilities = []
        
        async with httpx.AsyncClient(verify=False, cookies=session_data.get('cookies', {})) as client:
            # Get a page with forms
            response = await client.get(url)
            
            # Find forms
            forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)
            
            for form in forms:
                # Check if form has CSRF token
                has_csrf = any(pattern in form.lower() for pattern in ['csrf', '_token', 'authenticity_token'])
                
                # Check if it's a state-changing form
                is_state_changing = any(x in form.lower() for x in ['post', 'put', 'delete', 'patch'])
                
                if is_state_changing and not has_csrf:
                    # Extract form action
                    action_match = re.search(r'action=["\']([^"\']+)["\']', form, re.IGNORECASE)
                    form_action = action_match.group(1) if action_match else 'unknown'
                    
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name=f"Missing CSRF Protection: {form_action}",
                            description="Form lacks CSRF token protection",
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.8,
                            affected_urls=[url],
                            evidence={
                                'form_action': form_action,
                                'method': 'POST' if 'post' in form.lower() else 'unknown',
                            },
                            remediation="Implement CSRF tokens for all state-changing operations.",
                            cwe_ids=["CWE-352"]
                        )
                    )
        
        return vulnerabilities
    
    async def _test_idor(self, url: str, session_data: Dict[str, Any]) -> List[Vulnerability]:
        """Test for Insecure Direct Object References."""
        vulnerabilities = []
        
        # This is covered in broken access control, but we can do additional tests
        # Look for numeric IDs in URLs and try to increment/decrement them
        
        async with httpx.AsyncClient(verify=False, cookies=session_data.get('cookies', {})) as client:
            response = await client.get(url)
            
            # Find URLs with numeric IDs
            id_patterns = [
                r'href=["\'][^"\']*[?&]id=(\d+)',
                r'href=["\'][^"\']*[?&]user=(\d+)',
                r'href=["\'][^"\']*[?&]uid=(\d+)',
                r'href=["\'][^"\']*[?&]profile=(\d+)',
            ]
            
            for pattern in id_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                
                for match in matches[:3]:  # Limit to 3 tests per pattern
                    original_id = int(match)
                    test_ids = [original_id + 1, original_id - 1, 1, 999]
                    
                    for test_id in test_ids:
                        if test_id != original_id and test_id > 0:
                            # Build test URL
                            test_url = re.sub(
                                f'id={original_id}',
                                f'id={test_id}',
                                url
                            )
                            
                            try:
                                test_response = await client.get(test_url)
                                
                                if test_response.status_code == 200:
                                    # Check if we're seeing different data
                                    if test_response.text != response.text:
                                        vulnerabilities.append(
                                            Vulnerability(
                                                module=self.name,
                                                name="IDOR: Direct Object Reference",
                                                description="Can access resources by manipulating ID parameters",
                                                severity=SeverityLevel.HIGH,
                                                confidence=0.7,
                                                affected_urls=[test_url],
                                                evidence={
                                                    'original_id': original_id,
                                                    'test_id': test_id,
                                                    'parameter': 'id',
                                                },
                                                remediation="Implement proper authorization checks for all object access.",
                                                cwe_ids=["CWE-639"]
                                            )
                                        )
                                        break
                            except:
                                pass
        
        return vulnerabilities
    
    async def _test_authenticated_xss(self, url: str, session_data: Dict[str, Any]) -> List[Vulnerability]:
        """Test for XSS in authenticated areas."""
        vulnerabilities = []
        
        # XSS payloads
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "';alert(1);//",
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
        ]
        
        async with httpx.AsyncClient(verify=False, cookies=session_data.get('cookies', {})) as client:
            # Get forms in authenticated area
            response = await client.get(url)
            
            # Find input fields
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
            
            for input_name in inputs[:5]:  # Limit to 5 inputs
                for payload in xss_payloads[:2]:  # Limit payloads
                    # Submit form with XSS payload
                    test_data = {input_name: payload}
                    
                    try:
                        test_response = await client.post(url, data=test_data)
                        
                        # Check if payload is reflected
                        if payload in test_response.text:
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"Authenticated XSS: {input_name}",
                                    description="Cross-site scripting vulnerability in authenticated area",
                                    severity=SeverityLevel.HIGH,
                                    confidence=0.8,
                                    affected_urls=[url],
                                    evidence={
                                        'parameter': input_name,
                                        'payload': payload,
                                    },
                                    remediation="Properly encode all user input before displaying.",
                                    cwe_ids=["CWE-79"]
                                )
                            )
                            break
                    except:
                        pass
        
        return vulnerabilities
    
    async def _test_authenticated_sqli(self, url: str, session_data: Dict[str, Any]) -> List[Vulnerability]:
        """Test for SQL injection in authenticated areas."""
        vulnerabilities = []
        
        # SQL injection payloads
        sqli_payloads = [
            "' OR '1'='1",
            "1' AND '1'='2",
            "' OR 1=1--",
            "1 UNION SELECT NULL--",
            "'; DROP TABLE users--",
        ]
        
        # Error patterns indicating SQL injection
        error_patterns = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_',
            r'MySqlException',
            r'PostgreSQL.*ERROR',
            r'ORA-\d{5}',
            r'SQLite error',
        ]
        
        async with httpx.AsyncClient(verify=False, cookies=session_data.get('cookies', {})) as client:
            response = await client.get(url)
            
            # Find form inputs and URL parameters
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
            
            for input_name in inputs[:5]:  # Limit testing
                for payload in sqli_payloads[:2]:  # Limit payloads
                    test_data = {input_name: payload}
                    
                    try:
                        test_response = await client.post(url, data=test_data)
                        
                        # Check for SQL errors
                        for pattern in error_patterns:
                            if re.search(pattern, test_response.text, re.IGNORECASE):
                                vulnerabilities.append(
                                    Vulnerability(
                                        module=self.name,
                                        name=f"Authenticated SQL Injection: {input_name}",
                                        description="SQL injection vulnerability in authenticated area",
                                        severity=SeverityLevel.CRITICAL,
                                        confidence=0.9,
                                        affected_urls=[url],
                                        evidence={
                                            'parameter': input_name,
                                            'payload': payload,
                                            'error_pattern': pattern,
                                        },
                                        remediation="Use parameterized queries and input validation.",
                                        cwe_ids=["CWE-89"]
                                    )
                                )
                                break
                    except:
                        pass
        
        return vulnerabilities
    
    async def _test_privilege_escalation(self, url: str, session_data: Dict[str, Any]) -> List[Vulnerability]:
        """Test for privilege escalation vulnerabilities."""
        vulnerabilities = []
        
        # Try to access admin functions
        admin_functions = [
            '/admin/users/delete',
            '/admin/settings',
            '/api/admin/users',
            '/user/role/admin',
            '/privilege/elevate',
        ]
        
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        
        async with httpx.AsyncClient(verify=False, cookies=session_data.get('cookies', {})) as client:
            for function in admin_functions:
                test_url = urljoin(base_url, function)
                
                try:
                    # Try GET request
                    response = await client.get(test_url)
                    
                    if response.status_code == 200:
                        # Check if we have admin access
                        admin_indicators = ['delete user', 'admin panel', 'role management', 'system configuration']
                        if any(indicator in response.text.lower() for indicator in admin_indicators):
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"Privilege Escalation: {function}",
                                    description="Regular user can access administrative functions",
                                    severity=SeverityLevel.CRITICAL,
                                    confidence=0.9,
                                    affected_urls=[test_url],
                                    evidence={
                                        'function': function,
                                        'status_code': response.status_code,
                                    },
                                    remediation="Implement proper role-based access control (RBAC).",
                                    cwe_ids=["CWE-269", "CWE-250"]
                                )
                            )
                    
                    # Try POST request to modify privileges
                    elif function.endswith('/elevate'):
                        test_data = {'role': 'admin', 'privilege': 'all'}
                        response = await client.post(test_url, json=test_data)
                        
                        if response.status_code in [200, 201]:
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name="Privilege Escalation via API",
                                    description="Can elevate privileges through unprotected API endpoint",
                                    severity=SeverityLevel.CRITICAL,
                                    confidence=0.95,
                                    affected_urls=[test_url],
                                    evidence={
                                        'endpoint': function,
                                        'method': 'POST',
                                    },
                                    remediation="Secure all privilege modification endpoints.",
                                    cwe_ids=["CWE-269"]
                                )
                            )
                except:
                    pass
        
        return vulnerabilities
    
    async def _spider_authenticated_area(self, url: str, session_data: Dict[str, Any]) -> List[str]:
        """Spider the authenticated area to discover pages."""
        discovered_pages = set()
        to_visit = {url}
        visited = set()
        base_domain = urlparse(url).netloc
        
        async with httpx.AsyncClient(verify=False, cookies=session_data.get('cookies', {})) as client:
            while to_visit and len(discovered_pages) < 50:  # Limit to 50 pages
                current_url = to_visit.pop()
                
                if current_url in visited:
                    continue
                
                visited.add(current_url)
                
                try:
                    response = await client.get(current_url, timeout=10)
                    
                    if response.status_code == 200:
                        discovered_pages.add(current_url)
                        
                        # Extract links
                        links = re.findall(r'href=["\']([^"\']+)["\']', response.text)
                        
                        for link in links:
                            # Convert relative to absolute URL
                            absolute_url = urljoin(current_url, link)
                            
                            # Only follow links on same domain
                            if urlparse(absolute_url).netloc == base_domain:
                                if absolute_url not in visited and absolute_url not in to_visit:
                                    # Skip logout links
                                    if 'logout' not in absolute_url.lower():
                                        to_visit.add(absolute_url)
                except:
                    pass
        
        return list(discovered_pages)
