"""SQL Injection Scanner Module for detecting SQL injection vulnerabilities."""

import asyncio
import subprocess
import json
import tempfile
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
import re
import httpx
from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)

class SQLInjectionScanner(BaseScannerModule):
    """SQL Injection vulnerability scanner."""
    
    def __init__(self):
        super().__init__()
        self.name = "SQLInjectionScanner"
        self.description = "Detects SQL injection vulnerabilities in web applications"
        self.scan_type = ScanType.ACTIVE
        
        # SQL injection payloads for manual testing
        self.test_payloads = [
            # Basic SQL injection
            "'", '"', "' OR '1'='1", '" OR "1"="1',
            "' OR '1'='1' --", "' OR '1'='1' #",
            "admin' --", "admin' #", "admin'/*",
            "' or 1=1--", "' or 1=1#", "' or 1=1/*",
            "') or '1'='1--", "') or ('1'='1--",
            
            # Time-based blind SQL injection
            "' AND SLEEP(5)--", "' AND SLEEP(5)#",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND 1=(SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() AND SLEEP(5))--",
            
            # Boolean-based blind SQL injection
            "' AND '1'='1", "' AND '1'='2",
            "' AND 1=1--", "' AND 1=2--",
            
            # Union-based SQL injection
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT 1,2,3--", "' UNION ALL SELECT NULL--",
            
            # Error-based SQL injection
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT DATABASE()),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE()),0x7e))--",
            
            # Second-order SQL injection indicators
            "admin'||'", "admin' + '",
            
            # NoSQL injection
            "{'$ne': null}", "{'$gt': ''}",
            "[$ne]=1", "[$gt]=",
        ]
        
        # Error patterns indicating SQL injection
        self.sql_error_patterns = [
            # MySQL
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc\.exceptions",
            
            # PostgreSQL
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"org\.postgresql\.util\.PSQLException",
            
            # MS SQL Server
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_.*",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"System\.Data\.SqlClient\.SqlException",
            r"(?s)Exception.*\WRoadhouse\.Cms\.",
            
            # Oracle
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_.*",
            r"Warning.*\Wora_.*",
            r"oracle\.jdbc\.driver",
            
            # SQLite
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_.*",
            r"Warning.*SQLite3::",
            
            # Generic SQL errors
            r"SQL error",
            r"sql syntax",
            r"syntax error",
            r"database error",
            r"column .* does not exist",
            r"table .* does not exist",
            r"Incorrect syntax near",
            r"Unclosed quotation mark",
        ]
        
        # SQLMap configuration options
        self.sqlmap_options = {
            'basic': [
                '--batch',  # Non-interactive mode
                '--random-agent',  # Random user agent
                '--level=1',  # Basic test level
                '--risk=1',  # Low risk
                '--timeout=10',
                '--retries=2',
            ],
            'thorough': [
                '--batch',
                '--random-agent',
                '--level=3',  # More comprehensive
                '--risk=2',  # Medium risk
                '--timeout=15',
                '--retries=3',
                '--tamper=space2comment',  # Basic evasion
                '--threads=4',
            ],
            'aggressive': [
                '--batch',
                '--random-agent',
                '--level=5',  # Maximum test level
                '--risk=3',  # High risk
                '--timeout=20',
                '--retries=3',
                '--tamper=space2comment,between',
                '--threads=8',
                '--crawl=2',  # Crawl depth
                '--forms',  # Test forms
            ]
        }
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is suitable for SQL injection testing."""
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            parsed = urlparse(target)
            # Check if URL has parameters or is a form endpoint
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform SQL injection scan."""
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'tested_parameters': [],
            'vulnerable_parameters': [],
            'injection_types': [],
            'database_type': None,
        }
        statistics = {
            'urls_tested': 0,
            'parameters_tested': 0,
            'vulnerabilities_found': 0,
            'injection_points': 0,
        }
        
        try:
            # Ensure URL has scheme
            target_url = config.target
            if not target_url.startswith(('http://', 'https://')):
                target_url = f"https://{target_url}"
            
            # Determine scan approach based on scan type
            if config.scan_type == ScanType.PASSIVE:
                # Only check for obvious SQL errors in normal responses
                passive_vulns = await self._passive_sql_check(target_url)
                vulnerabilities.extend(passive_vulns)
            else:
                # Active scanning with payloads
                
                # 1. Quick manual payload testing
                manual_results = await self._manual_sql_injection_test(target_url, config)
                vulnerabilities.extend(manual_results['vulnerabilities'])
                info['tested_parameters'].extend(manual_results['tested_params'])
                statistics['parameters_tested'] = len(manual_results['tested_params'])
                
                # 2. If SQLMap is available and scan is AGGRESSIVE, use it
                if config.scan_type == ScanType.AGGRESSIVE and self._is_sqlmap_available():
                    sqlmap_results = await self._run_sqlmap_scan(target_url, config)
                    if sqlmap_results:
                        vulnerabilities.extend(sqlmap_results['vulnerabilities'])
                        info['vulnerable_parameters'].extend(sqlmap_results.get('vulnerable_params', []))
                        info['database_type'] = sqlmap_results.get('database_type')
                        statistics['injection_points'] = len(sqlmap_results.get('vulnerable_params', []))
                
                # 3. Test for blind SQL injection
                blind_results = await self._test_blind_sql_injection(target_url, config)
                vulnerabilities.extend(blind_results)
                
                # 4. Test forms if present
                form_results = await self._test_form_sql_injection(target_url, config)
                vulnerabilities.extend(form_results)
            
            statistics['vulnerabilities_found'] = len(vulnerabilities)
            statistics['urls_tested'] = 1  # Can be expanded for crawling
            
            # Determine injection types found
            injection_types = set()
            for vuln in vulnerabilities:
                if 'error-based' in vuln.name.lower():
                    injection_types.add('Error-based')
                elif 'blind' in vuln.name.lower():
                    injection_types.add('Blind')
                elif 'time' in vuln.name.lower():
                    injection_types.add('Time-based')
                elif 'union' in vuln.name.lower():
                    injection_types.add('Union-based')
            info['injection_types'] = list(injection_types)
            
        except Exception as e:
            errors.append(f"SQL injection scan failed: {str(e)}")
        
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
    
    async def _passive_sql_check(self, url: str) -> List[Vulnerability]:
        """Check for SQL errors in normal responses without injection attempts."""
        vulnerabilities = []
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(url)
                
                # Check for SQL errors in response
                for pattern in self.sql_error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="SQL Error Disclosure",
                                description="Application exposes SQL error messages in responses",
                                severity=SeverityLevel.MEDIUM,
                                confidence=0.7,
                                affected_urls=[url],
                                evidence={'error_pattern': pattern},
                                remediation="Implement proper error handling and avoid exposing database errors to users",
                                cwe_ids=["CWE-209"]
                            )
                        )
                        break
        except:
            pass
        
        return vulnerabilities
    
    async def _manual_sql_injection_test(self, url: str, config: ScanConfig) -> Dict[str, Any]:
        """Manually test for SQL injection using payloads with improved verification."""
        vulnerabilities = []
        tested_params = []
        
        # Parse URL for parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # Try to find common parameter names if no params in URL
            common_params = ['id', 'user', 'username', 'email', 'search', 'q', 'query', 'page', 'cat', 'category']
            params = {param: ['1'] for param in common_params[:3]}  # Test top 3
        
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            # Get baseline response for comparison
            baseline_response = await client.get(url)
            baseline_length = len(baseline_response.text)
            baseline_status = baseline_response.status_code
            
            # Extract baseline content patterns for better comparison
            baseline_patterns = self._extract_content_patterns(baseline_response.text)
            
            for param_name, param_values in params.items():
                tested_params.append(param_name)
                original_value = param_values[0] if param_values else '1'
                
                # Test each payload
                for payload in self.test_payloads[:10]:  # Limit payloads for efficiency
                    # Create test URL with payload
                    test_params = params.copy()
                    test_params[param_name] = [original_value + payload]
                    
                    # Rebuild URL with payload
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                    
                    try:
                        response = await client.get(test_url, timeout=15)
                        
                        # Enhanced SQL error detection with confidence scoring
                        sql_error_confidence = self._detect_sql_errors(response.text, baseline_response.text)
                        
                        if sql_error_confidence > 0.7:
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"SQL Injection (Error-based) in {param_name}",
                                    description=f"Parameter '{param_name}' appears vulnerable to SQL injection",
                                    severity=SeverityLevel.CRITICAL if sql_error_confidence > 0.9 else SeverityLevel.HIGH,
                                    confidence=sql_error_confidence,
                                    affected_urls=[url],
                                    evidence={
                                        'parameter': param_name,
                                        'payload': payload,
                                        'error_detected': True,
                                        'status_code': response.status_code,
                                    },
                                    remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
                                    references=[
                                        "https://owasp.org/www-community/attacks/SQL_Injection",
                                        "https://cwe.mitre.org/data/definitions/89.html"
                                    ],
                                    cwe_ids=["CWE-89"]
                                )
                            )
                            break
                        
                        # Enhanced boolean-based blind SQL injection detection
                        if "' AND '1'='1" in payload:
                            # Test true condition
                            true_length = len(response.text)
                            true_patterns = self._extract_content_patterns(response.text)
                            
                            # Test false condition
                            false_payload = original_value + "' AND '1'='2"
                            test_params[param_name] = [false_payload]
                            false_query = urlencode(test_params, doseq=True)
                            false_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{false_query}"
                            
                            false_response = await client.get(false_url, timeout=15)
                            false_length = len(false_response.text)
                            false_patterns = self._extract_content_patterns(false_response.text)
                            
                            # Calculate difference with multiple factors
                            length_diff = abs(true_length - false_length)
                            pattern_diff = self._calculate_pattern_difference(true_patterns, false_patterns)
                            
                            # More sophisticated blind SQL detection
                            if length_diff > 100 or pattern_diff > 0.3:
                                # Verify it's not just normal variation
                                baseline_diff = abs(baseline_length - true_length)
                                if length_diff > baseline_diff * 2:
                                    confidence = min(0.85, 0.5 + (length_diff / 1000) + pattern_diff)
                                    
                                    vulnerabilities.append(
                                        Vulnerability(
                                            module=self.name,
                                            name=f"Blind SQL Injection in {param_name}",
                                            description=f"Parameter '{param_name}' shows signs of blind SQL injection",
                                            severity=SeverityLevel.HIGH,
                                            confidence=confidence,
                                            affected_urls=[url],
                                            evidence={
                                                'parameter': param_name,
                                                'response_diff': length_diff,
                                                'pattern_diff': pattern_diff,
                                            },
                                            remediation="Use parameterized queries. Implement input validation and sanitization.",
                                            cwe_ids=["CWE-89"]
                                        )
                                    )
                                    break
                        
                    except asyncio.TimeoutError:
                        # Enhanced time-based SQL injection detection
                        if 'SLEEP' in payload or 'WAITFOR' in payload:
                            # Verify with a second request to reduce false positives
                            try:
                                verification_response = await client.get(test_url, timeout=15)
                                # If it times out again, more likely to be real
                                confidence = 0.4  # Low confidence for single timeout
                            except asyncio.TimeoutError:
                                confidence = 0.75  # Higher confidence for repeated timeout
                                
                                vulnerabilities.append(
                                    Vulnerability(
                                        module=self.name,
                                        name=f"Time-based SQL Injection in {param_name}",
                                        description=f"Parameter '{param_name}' may be vulnerable to time-based SQL injection",
                                        severity=SeverityLevel.HIGH,
                                        confidence=confidence,
                                        affected_urls=[url],
                                        evidence={
                                            'parameter': param_name,
                                            'payload': payload,
                                            'timeout_occurred': True,
                                            'verified': confidence > 0.7,
                                        },
                                        remediation="Use parameterized queries. Never trust user input.",
                                        cwe_ids=["CWE-89"]
                                    )
                                )
                    except:
                        pass
        
        return {
            'vulnerabilities': vulnerabilities,
            'tested_params': tested_params
        }
    
    def _detect_sql_errors(self, response_text: str, baseline_text: str) -> float:
        """Detect SQL errors with confidence scoring."""
        confidence = 0.0
        
        # Check if error patterns exist in baseline (reduces confidence)
        baseline_has_errors = any(
            re.search(pattern, baseline_text, re.IGNORECASE) 
            for pattern in self.sql_error_patterns[:5]  # Check common patterns
        )
        
        # Check for SQL error patterns
        for pattern in self.sql_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                # Found SQL error pattern
                if baseline_has_errors:
                    confidence = max(confidence, 0.3)  # Low confidence if baseline has errors
                else:
                    # Check specificity of error
                    if 'syntax' in pattern.lower() or 'ORA-' in pattern or 'MySQL' in pattern:
                        confidence = max(confidence, 0.95)  # High confidence for specific errors
                    else:
                        confidence = max(confidence, 0.8)  # Medium-high for generic errors
                
                # Check if error is in a typical error message format
                if re.search(r'(error|exception|warning).*?(sql|database|query)', response_text, re.IGNORECASE):
                    confidence = min(1.0, confidence + 0.1)
        
        return confidence
    
    def _extract_content_patterns(self, text: str) -> Dict[str, int]:
        """Extract content patterns for comparison."""
        patterns = {
            'total_length': len(text),
            'num_tags': len(re.findall(r'<[^>]+>', text)),
            'num_words': len(text.split()),
            'num_lines': len(text.splitlines()),
            'has_table': 1 if '<table' in text.lower() else 0,
            'has_form': 1 if '<form' in text.lower() else 0,
        }
        return patterns
    
    def _calculate_pattern_difference(self, patterns1: Dict[str, int], patterns2: Dict[str, int]) -> float:
        """Calculate the difference between two pattern sets."""
        if not patterns1 or not patterns2:
            return 0.0
        
        total_diff = 0.0
        for key in patterns1:
            if key in patterns2:
                if patterns1[key] > 0:
                    diff = abs(patterns1[key] - patterns2[key]) / patterns1[key]
                    total_diff += diff
        
        return total_diff / len(patterns1)
    
    async def _test_blind_sql_injection(self, url: str, config: ScanConfig) -> List[Vulnerability]:
        """Test specifically for blind SQL injection vulnerabilities."""
        vulnerabilities = []
        
        if config.scan_type != ScanType.AGGRESSIVE:
            return vulnerabilities
        
        # Time-based blind SQL injection test
        time_payloads = [
            ("MySQL", "' AND SLEEP(5)--"),
            ("MSSQL", "'; WAITFOR DELAY '00:00:05'--"),
            ("PostgreSQL", "'; SELECT pg_sleep(5)--"),
            ("Oracle", "' AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)--"),
        ]
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if params:
            async with httpx.AsyncClient(verify=False) as client:
                for param_name in params:
                    for db_type, payload in time_payloads:
                        test_params = params.copy()
                        test_params[param_name] = [params[param_name][0] + payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                        
                        try:
                            start_time = datetime.now()
                            response = await client.get(test_url, timeout=10)
                            elapsed = (datetime.now() - start_time).total_seconds()
                            
                            # If response took more than 4 seconds, likely vulnerable
                            if elapsed > 4:
                                vulnerabilities.append(
                                    Vulnerability(
                                        module=self.name,
                                        name=f"Time-based Blind SQL Injection ({db_type})",
                                        description=f"Parameter '{param_name}' is vulnerable to time-based blind SQL injection",
                                        severity=SeverityLevel.HIGH,
                                        confidence=0.85,
                                        affected_urls=[url],
                                        evidence={
                                            'parameter': param_name,
                                            'database_type': db_type,
                                            'delay_observed': elapsed,
                                        },
                                        remediation="Use parameterized queries. Implement proper input validation.",
                                        cwe_ids=["CWE-89"]
                                    )
                                )
                                break
                        except:
                            pass
        
        return vulnerabilities
    
    async def _test_form_sql_injection(self, url: str, config: ScanConfig) -> List[Vulnerability]:
        """Test forms for SQL injection vulnerabilities."""
        vulnerabilities = []
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(url)
                
                # Find forms in the page
                form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
                forms = form_pattern.findall(response.text)
                
                for form_html in forms[:3]:  # Test up to 3 forms
                    # Extract form action
                    action_match = re.search(r'action=["\']([^"\']*)["\']', form_html)
                    action = action_match.group(1) if action_match else url
                    
                    # Make action absolute
                    if not action.startswith(('http://', 'https://')):
                        from urllib.parse import urljoin
                        action = urljoin(url, action)
                    
                    # Extract input fields
                    input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
                    inputs = input_pattern.findall(form_html)
                    
                    # Test each input with SQL payloads
                    for input_name in inputs:
                        for payload in self.test_payloads[:5]:  # Test limited payloads
                            form_data = {input_name: payload}
                            
                            try:
                                # Determine method (default to POST)
                                method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                                method = method_match.group(1).upper() if method_match else 'POST'
                                
                                if method == 'POST':
                                    test_response = await client.post(action, data=form_data)
                                else:
                                    test_response = await client.get(action, params=form_data)
                                
                                # Check for SQL errors
                                for pattern in self.sql_error_patterns:
                                    if re.search(pattern, test_response.text, re.IGNORECASE):
                                        vulnerabilities.append(
                                            Vulnerability(
                                                module=self.name,
                                                name=f"SQL Injection in Form Field '{input_name}'",
                                                description=f"Form field '{input_name}' is vulnerable to SQL injection",
                                                severity=SeverityLevel.CRITICAL,
                                                confidence=0.9,
                                                affected_urls=[action],
                                                evidence={
                                                    'form_action': action,
                                                    'field': input_name,
                                                    'method': method,
                                                    'payload': payload,
                                                },
                                                remediation="Use parameterized queries. Validate and sanitize all form inputs.",
                                                cwe_ids=["CWE-89"]
                                            )
                                        )
                                        break
                            except:
                                pass
        except:
            pass
        
        return vulnerabilities
    
    def _is_sqlmap_available(self) -> bool:
        """Check if SQLMap is available on the system."""
        try:
            result = subprocess.run(['sqlmap', '--version'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    async def _run_sqlmap_scan(self, url: str, config: ScanConfig) -> Optional[Dict[str, Any]]:
        """Run SQLMap for comprehensive SQL injection testing."""
        try:
            # Determine SQLMap options based on scan type
            if config.scan_type == ScanType.ACTIVE:
                options = self.sqlmap_options['basic']
            elif config.scan_type == ScanType.AGGRESSIVE:
                options = self.sqlmap_options['aggressive']
            else:
                options = self.sqlmap_options['thorough']
            
            # Create temporary output directory
            with tempfile.TemporaryDirectory() as temp_dir:
                output_dir = os.path.join(temp_dir, 'sqlmap_output')
                
                # Build SQLMap command
                cmd = ['sqlmap', '-u', url] + options + [f'--output-dir={output_dir}']
                
                # Run SQLMap
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=config.timeout
                )
                
                # Parse SQLMap output
                vulnerabilities = []
                vulnerable_params = []
                database_type = None
                
                if 'vulnerable' in result.stdout.lower():
                    # Extract vulnerability information
                    param_pattern = re.compile(r"Parameter: ([^\s]+)")
                    params = param_pattern.findall(result.stdout)
                    vulnerable_params.extend(params)
                    
                    # Extract database type
                    db_pattern = re.compile(r"back-end DBMS: ([^\n]+)")
                    db_match = db_pattern.search(result.stdout)
                    if db_match:
                        database_type = db_match.group(1).strip()
                    
                    # Create vulnerability report
                    for param in params:
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"SQL Injection (SQLMap Confirmed) in {param}",
                                description=f"SQLMap confirmed SQL injection vulnerability in parameter '{param}'",
                                severity=SeverityLevel.CRITICAL,
                                confidence=1.0,
                                affected_urls=[url],
                                evidence={
                                    'parameter': param,
                                    'database_type': database_type,
                                    'tool': 'SQLMap',
                                },
                                remediation="Immediately fix by using parameterized queries. Never concatenate user input into SQL.",
                                references=[
                                    "https://owasp.org/www-community/attacks/SQL_Injection",
                                    "https://sqlmap.org/"
                                ],
                                cwe_ids=["CWE-89"]
                            )
                        )
                
                return {
                    'vulnerabilities': vulnerabilities,
                    'vulnerable_params': vulnerable_params,
                    'database_type': database_type
                }
                
        except subprocess.TimeoutExpired:
            # SQLMap timed out
            pass
        except Exception:
            pass
        
        return None
