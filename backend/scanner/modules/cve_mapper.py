"""CVE Mapper Module for identifying known vulnerabilities based on detected software versions."""

import asyncio
import httpx
import re
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from packaging import version
from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)

class CVEMapper(BaseScannerModule):
    """CVE (Common Vulnerabilities and Exposures) mapper and vulnerability database scanner."""
    
    def __init__(self):
        super().__init__()
        self.name = "CVEMapper"
        self.description = "Maps detected software versions to known CVEs and vulnerabilities"
        self.scan_type = ScanType.PASSIVE
        
        # Common software version patterns
        self.version_patterns = {
            # Web Servers
            'apache': r'Apache/?([\d.]+)',
            'nginx': r'nginx/?([\d.]+)',
            'iis': r'IIS/?([\d.]+)',
            'tomcat': r'Tomcat/?([\d.]+)',
            'lighttpd': r'lighttpd/?([\d.]+)',
            
            # Programming Languages/Runtimes
            'php': r'PHP/?([\d.]+)',
            'python': r'Python/?([\d.]+)',
            'ruby': r'Ruby/?([\d.]+)',
            'java': r'Java/?([\d.]+)',
            'node': r'Node\.js/?([\d.]+)',
            'dotnet': r'\.NET/?([\d.]+)',
            
            # Frameworks
            'django': r'Django/?([\d.]+)',
            'flask': r'Flask/?([\d.]+)',
            'rails': r'Rails/?([\d.]+)',
            'laravel': r'Laravel/?([\d.]+)',
            'spring': r'Spring/?([\d.]+)',
            'express': r'Express/?([\d.]+)',
            'wordpress': r'WordPress/?([\d.]+)',
            'drupal': r'Drupal/?([\d.]+)',
            'joomla': r'Joomla/?([\d.]+)',
            
            # Databases
            'mysql': r'MySQL/?([\d.]+)',
            'mariadb': r'MariaDB/?([\d.]+)',
            'postgresql': r'PostgreSQL/?([\d.]+)',
            'mongodb': r'MongoDB/?([\d.]+)',
            'redis': r'Redis/?([\d.]+)',
            'elasticsearch': r'Elasticsearch/?([\d.]+)',
            
            # Application Servers
            'openssl': r'OpenSSL/?([\d.]+[a-z]?)',
            'openssh': r'OpenSSH[_/]?([\d.]+)',
            'jquery': r'jQuery/?([\d.]+)',
            'bootstrap': r'Bootstrap/?([\d.]+)',
        }
        
        # Known vulnerable versions database (simplified - in production, use NVD API)
        self.vulnerable_versions = {
            'apache': [
                {
                    'versions': ['2.4.0', '2.4.48'],
                    'cve': 'CVE-2021-41773',
                    'description': 'Path traversal and remote code execution vulnerability',
                    'severity': SeverityLevel.CRITICAL,
                    'cvss': 9.8,
                },
                {
                    'versions': ['2.4.0', '2.4.46'],
                    'cve': 'CVE-2021-40438',
                    'description': 'SSRF vulnerability via mod_proxy',
                    'severity': SeverityLevel.HIGH,
                    'cvss': 7.5,
                },
            ],
            'nginx': [
                {
                    'versions': ['0.6.18', '1.20.0'],
                    'cve': 'CVE-2021-23017',
                    'description': 'DNS resolver vulnerability',
                    'severity': SeverityLevel.HIGH,
                    'cvss': 7.5,
                },
            ],
            'php': [
                {
                    'versions': ['7.0.0', '7.4.29'],
                    'cve': 'CVE-2022-31625',
                    'description': 'Uninitialized array in pg_query_params()',
                    'severity': SeverityLevel.HIGH,
                    'cvss': 7.5,
                },
                {
                    'versions': ['5.0.0', '5.6.40'],
                    'cve': 'Multiple',
                    'description': 'PHP 5.x is end-of-life with multiple unpatched vulnerabilities',
                    'severity': SeverityLevel.CRITICAL,
                    'cvss': 9.0,
                },
            ],
            'wordpress': [
                {
                    'versions': ['0.0.0', '5.8.2'],
                    'cve': 'CVE-2022-21661',
                    'description': 'SQL Injection vulnerability',
                    'severity': SeverityLevel.HIGH,
                    'cvss': 7.5,
                },
                {
                    'versions': ['3.7.0', '5.7.1'],
                    'cve': 'CVE-2021-29447',
                    'description': 'XXE vulnerability in Media Library',
                    'severity': SeverityLevel.HIGH,
                    'cvss': 7.5,
                },
            ],
            'openssl': [
                {
                    'versions': ['1.0.0', '1.0.1f'],
                    'cve': 'CVE-2014-0160',
                    'description': 'Heartbleed - Information disclosure vulnerability',
                    'severity': SeverityLevel.CRITICAL,
                    'cvss': 9.8,
                },
                {
                    'versions': ['1.0.0', '1.0.2h'],
                    'cve': 'CVE-2016-2107',
                    'description': 'Padding oracle in AES-NI CBC MAC check',
                    'severity': SeverityLevel.HIGH,
                    'cvss': 7.5,
                },
            ],
            'jquery': [
                {
                    'versions': ['0.0.0', '3.4.0'],
                    'cve': 'CVE-2019-11358',
                    'description': 'Prototype pollution vulnerability',
                    'severity': SeverityLevel.MEDIUM,
                    'cvss': 6.1,
                },
                {
                    'versions': ['0.0.0', '3.0.0'],
                    'cve': 'CVE-2020-11022',
                    'description': 'XSS vulnerability in HTML parsing',
                    'severity': SeverityLevel.MEDIUM,
                    'cvss': 6.1,
                },
            ],
            'drupal': [
                {
                    'versions': ['7.0', '7.57'],
                    'cve': 'CVE-2018-7600',
                    'description': 'Drupalgeddon 2 - Remote code execution',
                    'severity': SeverityLevel.CRITICAL,
                    'cvss': 9.8,
                },
                {
                    'versions': ['8.0.0', '8.5.0'],
                    'cve': 'CVE-2018-7600',
                    'description': 'Drupalgeddon 2 - Remote code execution',
                    'severity': SeverityLevel.CRITICAL,
                    'cvss': 9.8,
                },
            ],
        }
        
        # Common vulnerable components to check
        self.vulnerable_components = [
            {
                'name': 'Log4j',
                'pattern': r'log4j[/-]?([\d.]+)',
                'vulnerable_versions': ['2.0', '2.14.1'],
                'cve': 'CVE-2021-44228',
                'description': 'Log4Shell - Remote code execution vulnerability',
                'severity': SeverityLevel.CRITICAL,
                'cvss': 10.0,
            },
            {
                'name': 'Spring Framework',
                'pattern': r'spring[/-]?([\d.]+)',
                'vulnerable_versions': ['5.0.0', '5.3.17'],
                'cve': 'CVE-2022-22965',
                'description': 'Spring4Shell - Remote code execution',
                'severity': SeverityLevel.CRITICAL,
                'cvss': 9.8,
            },
            {
                'name': 'Struts',
                'pattern': r'struts[/-]?([\d.]+)',
                'vulnerable_versions': ['2.0.0', '2.5.30'],
                'cve': 'CVE-2017-5638',
                'description': 'Remote code execution in file upload',
                'severity': SeverityLevel.CRITICAL,
                'cvss': 10.0,
            },
        ]
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is suitable for CVE mapping."""
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform CVE mapping scan."""
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'software_detected': {},
            'cves_found': [],
            'vulnerable_components': [],
            'eol_software': [],
        }
        statistics = {
            'software_identified': 0,
            'cves_mapped': 0,
            'critical_vulns': 0,
            'high_vulns': 0,
            'total_vulnerabilities': 0,
        }
        
        try:
            # Ensure URL has scheme
            target_url = config.target
            if not target_url.startswith(('http://', 'https://')):
                target_url = f"https://{target_url}"
            
            # 1. Detect software versions
            detected_software = await self._detect_software_versions(target_url)
            info['software_detected'] = detected_software
            statistics['software_identified'] = len(detected_software)
            
            # 2. Map to CVEs
            for software, version_str in detected_software.items():
                cve_vulns = await self._check_cves(software, version_str)
                vulnerabilities.extend(cve_vulns)
                for vuln in cve_vulns:
                    if 'cve' in vuln.evidence:
                        info['cves_found'].append(vuln.evidence['cve'])
            
            # 3. Check for vulnerable components
            component_vulns = await self._check_vulnerable_components(target_url)
            vulnerabilities.extend(component_vulns)
            for vuln in component_vulns:
                if 'component' in vuln.evidence:
                    info['vulnerable_components'].append(vuln.evidence['component'])
            
            # 4. Check for end-of-life software
            eol_vulns = await self._check_eol_software(detected_software)
            vulnerabilities.extend(eol_vulns)
            for software, version_str in detected_software.items():
                if self._is_eol(software, version_str):
                    info['eol_software'].append(f"{software} {version_str}")
            
            # 5. Check common paths for version disclosure
            path_vulns = await self._check_version_disclosure_paths(target_url)
            vulnerabilities.extend(path_vulns)
            
            # 6. If NVD API key is available, query NVD database
            if config.custom_params and 'nvd_api_key' in config.custom_params:
                nvd_vulns = await self._query_nvd(detected_software, config.custom_params['nvd_api_key'])
                vulnerabilities.extend(nvd_vulns)
            
            # Update statistics
            statistics['cves_mapped'] = len(info['cves_found'])
            statistics['total_vulnerabilities'] = len(vulnerabilities)
            
            for vuln in vulnerabilities:
                if vuln.severity == SeverityLevel.CRITICAL:
                    statistics['critical_vulns'] += 1
                elif vuln.severity == SeverityLevel.HIGH:
                    statistics['high_vulns'] += 1
            
        except Exception as e:
            errors.append(f"CVE mapping scan failed: {str(e)}")
        
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
    
    async def _detect_software_versions(self, url: str) -> Dict[str, str]:
        """Detect software and their versions from headers and content."""
        detected = {}
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(url)
                
                # Check headers
                headers_str = ' '.join([f"{k}: {v}" for k, v in response.headers.items()])
                
                # Check response body
                content = response.text[:50000]  # Limit content size
                
                # Combined text to search
                search_text = headers_str + ' ' + content
                
                # Search for version patterns
                for software, pattern in self.version_patterns.items():
                    matches = re.findall(pattern, search_text, re.IGNORECASE)
                    if matches:
                        # Take the first match (usually most reliable)
                        detected[software] = matches[0]
                
                # Check for specific headers
                if 'server' in response.headers:
                    server = response.headers['server']
                    for software, pattern in self.version_patterns.items():
                        if software not in detected:
                            match = re.search(pattern, server, re.IGNORECASE)
                            if match:
                                detected[software] = match.group(1)
                
                if 'x-powered-by' in response.headers:
                    powered_by = response.headers['x-powered-by']
                    for software, pattern in self.version_patterns.items():
                        if software not in detected:
                            match = re.search(pattern, powered_by, re.IGNORECASE)
                            if match:
                                detected[software] = match.group(1)
                
                # Check meta tags for CMS versions
                cms_patterns = {
                    'wordpress': r'<meta name="generator" content="WordPress ([\d.]+)"',
                    'drupal': r'Drupal ([\d.]+)',
                    'joomla': r'Joomla! ([\d.]+)',
                }
                
                for cms, pattern in cms_patterns.items():
                    if cms not in detected:
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            detected[cms] = match.group(1)
                
        except:
            pass
        
        return detected
    
    async def _check_cves(self, software: str, version_str: str) -> List[Vulnerability]:
        """Check for known CVEs for the detected software version."""
        vulnerabilities = []
        
        if software not in self.vulnerable_versions:
            return vulnerabilities
        
        try:
            detected_version = version.parse(version_str)
        except:
            # If version parsing fails, try basic string comparison
            detected_version = version_str
        
        for vuln_info in self.vulnerable_versions[software]:
            try:
                # Check if version is in vulnerable range
                min_version = version.parse(vuln_info['versions'][0])
                max_version = version.parse(vuln_info['versions'][1])
                
                if isinstance(detected_version, str):
                    # Basic string comparison fallback
                    is_vulnerable = vuln_info['versions'][0] <= detected_version <= vuln_info['versions'][1]
                else:
                    is_vulnerable = min_version <= detected_version <= max_version
                
                if is_vulnerable:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name=f"{software.title()} {version_str} - {vuln_info['cve']}",
                            description=vuln_info['description'],
                            severity=vuln_info['severity'],
                            confidence=0.95,
                            cvss_score=vuln_info['cvss'],
                            cve_ids=[vuln_info['cve']] if vuln_info['cve'] != 'Multiple' else [],
                            affected_urls=[],
                            evidence={
                                'software': software,
                                'version': version_str,
                                'cve': vuln_info['cve'],
                                'vulnerable_range': f"{vuln_info['versions'][0]} - {vuln_info['versions'][1]}",
                            },
                            remediation=f"Update {software} to the latest version or apply security patches.",
                            references=[
                                f"https://nvd.nist.gov/vuln/detail/{vuln_info['cve']}" if vuln_info['cve'] != 'Multiple' else "https://nvd.nist.gov/"
                            ],
                            cwe_ids=["CWE-1035"]  # NVD-CWE-noinfo
                        )
                    )
            except:
                # If version comparison fails, skip this vulnerability
                pass
        
        return vulnerabilities
    
    async def _check_vulnerable_components(self, url: str) -> List[Vulnerability]:
        """Check for known vulnerable components."""
        vulnerabilities = []
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(url)
                content = response.text[:100000]  # Limit content size
                
                # Also check common JavaScript library paths
                js_paths = [
                    '/js/', '/scripts/', '/assets/', '/static/',
                    '/vendor/', '/lib/', '/bower_components/', '/node_modules/'
                ]
                
                for component_info in self.vulnerable_components:
                    # Check in main content
                    match = re.search(component_info['pattern'], content, re.IGNORECASE)
                    
                    if match:
                        detected_version = match.group(1)
                        try:
                            det_ver = version.parse(detected_version)
                            min_ver = version.parse(component_info['vulnerable_versions'][0])
                            max_ver = version.parse(component_info['vulnerable_versions'][1])
                            
                            if min_ver <= det_ver <= max_ver:
                                vulnerabilities.append(
                                    Vulnerability(
                                        module=self.name,
                                        name=f"{component_info['name']} {detected_version} - {component_info['cve']}",
                                        description=component_info['description'],
                                        severity=component_info['severity'],
                                        confidence=0.9,
                                        cvss_score=component_info['cvss'],
                                        cve_ids=[component_info['cve']],
                                        affected_urls=[url],
                                        evidence={
                                            'component': component_info['name'],
                                            'version': detected_version,
                                            'cve': component_info['cve'],
                                        },
                                        remediation=f"Update {component_info['name']} to the latest version immediately.",
                                        references=[
                                            f"https://nvd.nist.gov/vuln/detail/{component_info['cve']}"
                                        ],
                                        cwe_ids=["CWE-1035"]
                                    )
                                )
                        except:
                            pass
        except:
            pass
        
        return vulnerabilities
    
    async def _check_eol_software(self, detected_software: Dict[str, str]) -> List[Vulnerability]:
        """Check for end-of-life software versions."""
        vulnerabilities = []
        
        # EOL database (simplified)
        eol_versions = {
            'php': [
                ('5.0', '5.6', '2019-01-01'),
                ('7.0', '7.0', '2019-01-01'),
                ('7.1', '7.1', '2019-12-01'),
                ('7.2', '7.2', '2020-11-30'),
                ('7.3', '7.3', '2021-12-06'),
            ],
            'python': [
                ('2.0', '2.7', '2020-01-01'),
                ('3.0', '3.5', '2020-09-30'),
                ('3.6', '3.6', '2021-12-23'),
            ],
            'wordpress': [
                ('0.0', '5.6', '2022-01-01'),
            ],
            'windows': [
                ('7', '7', '2020-01-14'),
                ('8', '8.1', '2023-01-10'),
            ],
        }
        
        for software, version_str in detected_software.items():
            if software in eol_versions:
                for min_ver, max_ver, eol_date in eol_versions[software]:
                    try:
                        detected_ver = version.parse(version_str)
                        min_version = version.parse(min_ver)
                        max_version = version.parse(max_ver)
                        
                        eol_datetime = datetime.strptime(eol_date, '%Y-%m-%d')
                        
                        if min_version <= detected_ver <= max_version and datetime.utcnow() > eol_datetime:
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"End-of-Life Software: {software.title()} {version_str}",
                                    description=f"{software.title()} {version_str} reached end-of-life on {eol_date}",
                                    severity=SeverityLevel.HIGH,
                                    confidence=1.0,
                                    affected_urls=[],
                                    evidence={
                                        'software': software,
                                        'version': version_str,
                                        'eol_date': eol_date,
                                    },
                                    remediation=f"Upgrade to a supported version of {software.title()}.",
                                    references=[
                                        f"https://endoflife.date/{software}"
                                    ],
                                    cwe_ids=["CWE-1104"]  # Use of Unmaintained Third Party Components
                                )
                            )
                            break
                    except:
                        pass
        
        return vulnerabilities
    
    async def _check_version_disclosure_paths(self, url: str) -> List[Vulnerability]:
        """Check common paths that might disclose version information."""
        vulnerabilities = []
        
        # Common version disclosure paths
        version_paths = [
            '/version', '/version.txt', '/VERSION',
            '/readme.txt', '/README.txt', '/README.md',
            '/CHANGELOG.md', '/CHANGELOG.txt', '/changelog.txt',
            '/package.json', '/composer.json', '/requirements.txt',
            '/.git/HEAD', '/.git/config',
            '/wp-includes/version.php',  # WordPress
            '/administrator/manifests/files/joomla.xml',  # Joomla
            '/core/lib/Drupal.php',  # Drupal
            '/app/etc/env.php',  # Magento
        ]
        
        from urllib.parse import urljoin
        
        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            for path in version_paths:
                test_url = urljoin(url, path)
                
                try:
                    response = await client.get(test_url, timeout=5)
                    
                    if response.status_code == 200:
                        # Check if response contains version information
                        version_indicators = [
                            r'version["\s:]+([0-9.]+)',
                            r'"version":\s*"([0-9.]+)"',
                            r'Version:\s*([0-9.]+)',
                            r'v([0-9.]+)',
                        ]
                        
                        for pattern in version_indicators:
                            match = re.search(pattern, response.text[:1000], re.IGNORECASE)
                            if match:
                                vulnerabilities.append(
                                    Vulnerability(
                                        module=self.name,
                                        name=f"Version Disclosure: {path}",
                                        description=f"Version information exposed at {path}",
                                        severity=SeverityLevel.LOW,
                                        confidence=0.9,
                                        affected_urls=[test_url],
                                        evidence={
                                            'path': path,
                                            'version_found': match.group(1),
                                        },
                                        remediation="Remove or restrict access to files containing version information.",
                                        cwe_ids=["CWE-200"]
                                    )
                                )
                                break
                except:
                    pass
        
        return vulnerabilities
    
    async def _query_nvd(self, detected_software: Dict[str, str], api_key: str) -> List[Vulnerability]:
        """Query NVD database for CVEs (requires API key)."""
        vulnerabilities = []
        
        # NVD API endpoint
        nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        for software, version_str in detected_software.items():
            try:
                # Build CPE string (Common Platform Enumeration)
                cpe_string = f"cpe:2.3:a:*:{software}:{version_str}:*:*:*:*:*:*:*"
                
                headers = {'apiKey': api_key} if api_key else {}
                params = {
                    'cpeName': cpe_string,
                    'resultsPerPage': 10
                }
                
                async with httpx.AsyncClient(verify=False) as client:
                    response = await client.get(nvd_api_url, params=params, headers=headers, timeout=10)
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        for cve_item in data.get('vulnerabilities', [])[:5]:  # Limit to 5 CVEs per software
                            cve_data = cve_item.get('cve', {})
                            cve_id = cve_data.get('id', 'Unknown')
                            
                            # Extract CVSS score
                            cvss_score = 0.0
                            metrics = cve_data.get('metrics', {})
                            if 'cvssMetricV31' in metrics:
                                cvss_score = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 0.0)
                            elif 'cvssMetricV30' in metrics:
                                cvss_score = metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseScore', 0.0)
                            
                            # Determine severity
                            if cvss_score >= 9.0:
                                severity = SeverityLevel.CRITICAL
                            elif cvss_score >= 7.0:
                                severity = SeverityLevel.HIGH
                            elif cvss_score >= 4.0:
                                severity = SeverityLevel.MEDIUM
                            else:
                                severity = SeverityLevel.LOW
                            
                            # Get description
                            descriptions = cve_data.get('descriptions', [])
                            description = descriptions[0].get('value', 'No description available') if descriptions else 'No description available'
                            
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"{software.title()} {version_str} - {cve_id}",
                                    description=description[:200],  # Limit description length
                                    severity=severity,
                                    confidence=1.0,
                                    cvss_score=cvss_score,
                                    cve_ids=[cve_id],
                                    affected_urls=[],
                                    evidence={
                                        'software': software,
                                        'version': version_str,
                                        'cve': cve_id,
                                        'source': 'NVD',
                                    },
                                    remediation=f"Review and apply patches for {cve_id}.",
                                    references=[
                                        f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                                    ],
                                    cwe_ids=["CWE-1035"]
                                )
                            )
                            
            except:
                pass
        
        return vulnerabilities
    
    def _is_eol(self, software: str, version_str: str) -> bool:
        """Check if software version is end-of-life."""
        eol_quick_check = {
            'php': ['5.', '7.0', '7.1', '7.2', '7.3'],
            'python': ['2.'],
            'java': ['6', '7', '8'],
            'windows': ['xp', 'vista', '7', '8'],
        }
        
        if software in eol_quick_check:
            for eol_prefix in eol_quick_check[software]:
                if version_str.startswith(eol_prefix):
                    return True
        
        return False
