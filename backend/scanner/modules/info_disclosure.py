"""Information Disclosure Scanner Module for detecting sensitive information leaks."""

import asyncio
import httpx
import re
import json
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from urllib.parse import urlparse, urljoin
from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)

class InfoDisclosureScanner(BaseScannerModule):
    """Information Disclosure vulnerability scanner."""
    
    def __init__(self):
        super().__init__()
        self.name = "InfoDisclosureScanner"
        self.description = "Detects information disclosure vulnerabilities and sensitive data exposure"
        self.scan_type = ScanType.PASSIVE
        
        # Sensitive file paths to check
        self.sensitive_files = [
            # Version control
            '.git/config', '.git/HEAD', '.git/index',
            '.svn/entries', '.svn/wc.db',
            '.hg/requires', '.bzr/README',
            
            # Backup files
            'backup.sql', 'backup.zip', 'backup.tar.gz',
            'database.sql', 'dump.sql', 'db_backup.sql',
            'site_backup.zip', 'www.zip', 'website.zip',
            
            # Configuration files
            '.env', '.env.local', '.env.production',
            'config.php', 'config.json', 'config.yml',
            'settings.py', 'settings.ini', 'app.config',
            'web.config', 'php.ini', '.htaccess',
            'package.json', 'composer.json', 'requirements.txt',
            
            # Cloud/Container
            'Dockerfile', 'docker-compose.yml', '.dockerignore',
            'kubernetes.yml', 'k8s.yaml',
            '.travis.yml', '.gitlab-ci.yml', 'Jenkinsfile',
            
            # IDE/Editor files
            '.vscode/settings.json', '.idea/workspace.xml',
            'nbproject/project.properties',
            
            # Documentation
            'README.md', 'readme.txt', 'CHANGELOG.md',
            'TODO.txt', 'todo.md', 'notes.txt',
            
            # API/Swagger
            'swagger.json', 'swagger.yaml', 'openapi.json',
            'api-docs.json', 'api/swagger.json',
            
            # Database files
            'database.sqlite', 'db.sqlite3', 'data.db',
            
            # Log files
            'debug.log', 'error.log', 'access.log',
            'application.log', 'system.log',
            
            # Security files
            'private.key', 'server.key', 'id_rsa',
            'cert.pem', 'certificate.crt',
            '.ssh/id_rsa', '.ssh/known_hosts',
            
            # Application specific
            'phpinfo.php', 'info.php', 'test.php',
            'admin.php', 'login.php', 'shell.php',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'security.txt', '.well-known/security.txt',
        ]
        
        # Sensitive patterns in content
        self.sensitive_patterns = {
            'api_keys': [
                # Generic API key patterns
                r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
                r'["\']?apikey["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
                r'["\']?api[_-]?secret["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
                
                # AWS
                r'AKIA[0-9A-Z]{16}',
                r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']?AKIA[0-9A-Z]{16}',
                r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9/+=]{40}["\']',
                
                # Google
                r'AIza[0-9A-Za-z_\-]{35}',
                
                # GitHub
                r'ghp_[a-zA-Z0-9]{36}',
                r'gho_[a-zA-Z0-9]{36}',
                
                # Slack
                r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}',
                
                # Stripe
                r'sk_live_[a-zA-Z0-9]{24,}',
                r'pk_live_[a-zA-Z0-9]{24,}',
            ],
            
            'passwords': [
                r'["\']?password["\']?\s*[:=]\s*["\'][^"\']{4,}["\']',
                r'["\']?passwd["\']?\s*[:=]\s*["\'][^"\']{4,}["\']',
                r'["\']?pwd["\']?\s*[:=]\s*["\'][^"\']{4,}["\']',
                r'["\']?pass["\']?\s*[:=]\s*["\'][^"\']{4,}["\']',
                r'["\']?secret["\']?\s*[:=]\s*["\'][^"\']{4,}["\']',
            ],
            
            'tokens': [
                r'["\']?token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']',
                r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']',
                r'["\']?access[_-]?token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']',
                r'["\']?bearer["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']',
                r'Bearer\s+[a-zA-Z0-9_\-\.]+',
            ],
            
            'database': [
                r'["\']?db[_-]?host["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'["\']?db[_-]?user["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'["\']?db[_-]?pass["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'["\']?database[_-]?url["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'mongodb://[^"\s]+',
                r'mysql://[^"\s]+',
                r'postgres://[^"\s]+',
                r'redis://[^"\s]+',
            ],
            
            'private_keys': [
                r'-----BEGIN RSA PRIVATE KEY-----',
                r'-----BEGIN PRIVATE KEY-----',
                r'-----BEGIN EC PRIVATE KEY-----',
                r'-----BEGIN OPENSSH PRIVATE KEY-----',
                r'-----BEGIN DSA PRIVATE KEY-----',
                r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            ],
            
            'emails': [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            ],
            
            'ip_addresses': [
                # IPv4
                r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
                # IPv6
                r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}',
            ],
            
            'credit_cards': [
                # Visa
                r'4[0-9]{12}(?:[0-9]{3})?',
                # MasterCard
                r'5[1-5][0-9]{14}',
                # American Express
                r'3[47][0-9]{13}',
                # Discover
                r'6(?:011|5[0-9]{2})[0-9]{12}',
            ],
            
            'social_security': [
                # SSN
                r'\b\d{3}-\d{2}-\d{4}\b',
                r'\b\d{9}\b',
            ],
        }
        
        # Error messages that leak information
        self.error_patterns = {
            'stack_traces': [
                r'Traceback \(most recent call last\)',
                r'at [a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\([^)]+\)',
                r'Exception in thread',
                r'Fatal error:',
                r'Stack trace:',
                r'at line \d+',
            ],
            
            'database_errors': [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_',
                r'MySqlException',
                r'PostgreSQL.*ERROR',
                r'ORA-[0-9]{5}',
                r'SQLite error',
                r'mongodb error',
            ],
            
            'framework_errors': [
                r'Django [\d.]+ using',
                r'Laravel.*Exception',
                r'Symfony Exception',
                r'Rails.root:',
                r'Spring Boot',
                r'ASP\.NET',
            ],
            
            'server_info': [
                r'Apache/[\d.]+',
                r'nginx/[\d.]+',
                r'IIS/[\d.]+',
                r'PHP/[\d.]+',
                r'Python/[\d.]+',
                r'Ruby/[\d.]+',
            ],
        }
        
        # Technology fingerprints
        self.tech_fingerprints = {
            'frameworks': {
                'Django': ['csrfmiddlewaretoken', 'django-admin', '__debug__'],
                'Laravel': ['laravel_session', 'XSRF-TOKEN'],
                'Spring': ['JSESSIONID', 'spring.'],
                'Express': ['X-Powered-By: Express'],
                'Rails': ['_rails_session', 'authenticity_token'],
                'WordPress': ['wp-content', 'wp-admin', 'wp-includes'],
                'Drupal': ['sites/default', 'node/add'],
                'Joomla': ['option=com_', 'joomla'],
            },
            
            'servers': {
                'Apache': ['Apache', 'mod_'],
                'Nginx': ['nginx', 'X-Nginx'],
                'IIS': ['IIS', 'ASP.NET'],
                'Tomcat': ['Tomcat', 'JSESSIONID'],
            },
            
            'databases': {
                'MySQL': ['mysql', 'mysqli'],
                'PostgreSQL': ['postgresql', 'postgres'],
                'MongoDB': ['mongodb', 'mongoose'],
                'Redis': ['redis'],
                'SQLite': ['sqlite'],
            },
        }
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is suitable for information disclosure scanning."""
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform information disclosure scan."""
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'sensitive_files_found': [],
            'technologies_detected': [],
            'sensitive_data_types': [],
            'error_types_found': [],
        }
        statistics = {
            'files_checked': 0,
            'sensitive_files': 0,
            'data_leaks': 0,
            'error_disclosures': 0,
            'total_vulnerabilities': 0,
        }
        
        try:
            # Ensure URL has scheme
            target_url = config.target
            if not target_url.startswith(('http://', 'https://')):
                target_url = f"https://{target_url}"
            
            # 1. Check for sensitive files
            file_vulns = await self._check_sensitive_files(target_url, config)
            vulnerabilities.extend(file_vulns)
            statistics['sensitive_files'] = len(file_vulns)
            for vuln in file_vulns:
                if 'file' in vuln.evidence:
                    info['sensitive_files_found'].append(vuln.evidence['file'])
            
            # 2. Check response headers
            header_vulns = await self._check_headers(target_url)
            vulnerabilities.extend(header_vulns)
            
            # 3. Check for sensitive data in page content
            content_vulns = await self._check_content(target_url, config)
            vulnerabilities.extend(content_vulns)
            statistics['data_leaks'] = len(content_vulns)
            
            # 4. Check for error messages
            error_vulns = await self._check_error_messages(target_url)
            vulnerabilities.extend(error_vulns)
            statistics['error_disclosures'] = len(error_vulns)
            
            # 5. Technology fingerprinting
            tech_info = await self._fingerprint_technologies(target_url)
            info['technologies_detected'] = tech_info
            
            # 6. Check robots.txt and sitemap
            robot_vulns = await self._check_robots_sitemap(target_url)
            vulnerabilities.extend(robot_vulns)
            
            # 7. Check for directory listing
            dir_vulns = await self._check_directory_listing(target_url)
            vulnerabilities.extend(dir_vulns)
            
            # 8. Check for source code disclosure
            source_vulns = await self._check_source_disclosure(target_url)
            vulnerabilities.extend(source_vulns)
            
            # Update statistics
            statistics['total_vulnerabilities'] = len(vulnerabilities)
            statistics['files_checked'] = len(self.sensitive_files)
            
            # Determine sensitive data types found
            data_types = set()
            for vuln in vulnerabilities:
                if 'data_type' in vuln.evidence:
                    data_types.add(vuln.evidence['data_type'])
            info['sensitive_data_types'] = list(data_types)
            
        except Exception as e:
            errors.append(f"Information disclosure scan failed: {str(e)}")
        
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
    
    async def _check_sensitive_files(self, url: str, config: ScanConfig) -> List[Vulnerability]:
        """Check for exposed sensitive files."""
        vulnerabilities = []
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        
        # Limit files to check based on scan type
        if config.scan_type == ScanType.PASSIVE:
            files_to_check = self.sensitive_files[:10]
        elif config.scan_type == ScanType.ACTIVE:
            files_to_check = self.sensitive_files[:30]
        else:
            files_to_check = self.sensitive_files
        
        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            for file_path in files_to_check:
                test_url = urljoin(base_url + '/', file_path)
                
                try:
                    response = await client.get(test_url, timeout=5)
                    
                    # Check if file exists and is accessible
                    if response.status_code == 200:
                        # Determine severity based on file type
                        severity = SeverityLevel.CRITICAL if any(
                            x in file_path for x in ['.env', 'private.key', 'id_rsa', '.git', 'backup.sql']
                        ) else SeverityLevel.HIGH if any(
                            x in file_path for x in ['config', 'password', 'token', 'secret']
                        ) else SeverityLevel.MEDIUM
                        
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"Sensitive File Exposed: {file_path}",
                                description=f"Sensitive file '{file_path}' is publicly accessible",
                                severity=severity,
                                confidence=1.0,
                                affected_urls=[test_url],
                                evidence={
                                    'file': file_path,
                                    'status_code': response.status_code,
                                    'content_length': len(response.text),
                                },
                                remediation="Remove or restrict access to sensitive files. Use proper access controls.",
                                references=[
                                    "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
                                ],
                                cwe_ids=["CWE-200", "CWE-538"]
                            )
                        )
                        
                        # Check content for additional sensitive data
                        if response.text:
                            for data_type, patterns in self.sensitive_patterns.items():
                                for pattern in patterns:
                                    if re.search(pattern, response.text, re.IGNORECASE):
                                        vulnerabilities.append(
                                            Vulnerability(
                                                module=self.name,
                                                name=f"Sensitive Data in {file_path}: {data_type}",
                                                description=f"File contains sensitive {data_type} data",
                                                severity=SeverityLevel.CRITICAL,
                                                confidence=0.9,
                                                affected_urls=[test_url],
                                                evidence={
                                                    'file': file_path,
                                                    'data_type': data_type,
                                                },
                                                remediation=f"Remove {data_type} from publicly accessible files.",
                                                cwe_ids=["CWE-200", "CWE-312"]
                                            )
                                        )
                                        break
                                        
                except:
                    pass
        
        return vulnerabilities
    
    async def _check_headers(self, url: str) -> List[Vulnerability]:
        """Check response headers for information disclosure."""
        vulnerabilities = []
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(url)
                
                # Check for server version disclosure
                if 'server' in response.headers:
                    server_header = response.headers['server']
                    # Check if version is disclosed
                    if re.search(r'[\d.]+', server_header):
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="Server Version Disclosure",
                                description=f"Server header reveals version: {server_header}",
                                severity=SeverityLevel.LOW,
                                confidence=1.0,
                                affected_urls=[url],
                                evidence={'header': 'Server', 'value': server_header},
                                remediation="Remove version information from Server header.",
                                cwe_ids=["CWE-200"]
                            )
                        )
                
                # Check for X-Powered-By
                if 'x-powered-by' in response.headers:
                    powered_by = response.headers['x-powered-by']
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Technology Disclosure via X-Powered-By",
                            description=f"X-Powered-By header reveals: {powered_by}",
                            severity=SeverityLevel.LOW,
                            confidence=1.0,
                            affected_urls=[url],
                            evidence={'header': 'X-Powered-By', 'value': powered_by},
                            remediation="Remove X-Powered-By header.",
                            cwe_ids=["CWE-200"]
                        )
                    )
                
                # Check for debug headers
                debug_headers = ['x-debug', 'x-debug-token', 'x-debug-token-link']
                for header in debug_headers:
                    if header in response.headers:
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"Debug Header Exposed: {header}",
                                description=f"Debug header '{header}' is exposed",
                                severity=SeverityLevel.MEDIUM,
                                confidence=1.0,
                                affected_urls=[url],
                                evidence={'header': header, 'value': response.headers[header]},
                                remediation="Remove debug headers in production.",
                                cwe_ids=["CWE-200", "CWE-489"]
                            )
                        )
                        
        except:
            pass
        
        return vulnerabilities
    
    async def _check_content(self, url: str, config: ScanConfig) -> List[Vulnerability]:
        """Check page content for sensitive data."""
        vulnerabilities = []
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(url)
                content = response.text
                
                # Check for sensitive patterns
                for data_type, patterns in self.sensitive_patterns.items():
                    for pattern in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            # Don't report emails as high severity
                            severity = SeverityLevel.LOW if data_type == 'emails' else \
                                      SeverityLevel.CRITICAL if data_type in ['api_keys', 'passwords', 'private_keys'] else \
                                      SeverityLevel.HIGH
                            
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"Sensitive Data Exposure: {data_type}",
                                    description=f"Page contains exposed {data_type}",
                                    severity=severity,
                                    confidence=0.8,
                                    affected_urls=[url],
                                    evidence={
                                        'data_type': data_type,
                                        'matches_found': len(matches),
                                        'sample': matches[0][:50] if matches else None,
                                    },
                                    remediation=f"Remove {data_type} from public pages. Use environment variables for sensitive configuration.",
                                    cwe_ids=["CWE-200", "CWE-312"]
                                )
                            )
                            break
                
                # Check for HTML comments with sensitive info
                comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
                for comment in comments:
                    # Check if comment contains sensitive keywords
                    sensitive_keywords = ['password', 'token', 'api', 'secret', 'key', 'todo', 'fixme', 'hack']
                    if any(keyword in comment.lower() for keyword in sensitive_keywords):
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="Sensitive Information in HTML Comments",
                                description="HTML comments contain potentially sensitive information",
                                severity=SeverityLevel.MEDIUM,
                                confidence=0.7,
                                affected_urls=[url],
                                evidence={'comment_snippet': comment[:100]},
                                remediation="Remove sensitive information from HTML comments.",
                                cwe_ids=["CWE-615"]
                            )
                        )
                        break
                        
        except:
            pass
        
        return vulnerabilities
    
    async def _check_error_messages(self, url: str) -> List[Vulnerability]:
        """Check for verbose error messages."""
        vulnerabilities = []
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                # Try to trigger errors with various techniques
                test_urls = [
                    url + "/'",  # SQL error
                    url + "/nonexistent",  # 404 error
                    url + "/?debug=1",  # Debug mode
                    url + "/?test=<script>",  # XSS attempt might trigger error
                ]
                
                for test_url in test_urls:
                    try:
                        response = await client.get(test_url)
                        
                        # Check for error patterns
                        for error_type, patterns in self.error_patterns.items():
                            for pattern in patterns:
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    vulnerabilities.append(
                                        Vulnerability(
                                            module=self.name,
                                            name=f"Verbose Error Message: {error_type}",
                                            description=f"Application exposes {error_type} information",
                                            severity=SeverityLevel.MEDIUM,
                                            confidence=0.8,
                                            affected_urls=[test_url],
                                            evidence={
                                                'error_type': error_type,
                                                'pattern_matched': pattern,
                                            },
                                            remediation="Implement custom error pages and disable debug mode in production.",
                                            cwe_ids=["CWE-209", "CWE-200"]
                                        )
                                    )
                                    break
                    except:
                        pass
                        
        except:
            pass
        
        return vulnerabilities
    
    async def _fingerprint_technologies(self, url: str) -> List[str]:
        """Fingerprint technologies used by the application."""
        technologies = []
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(url)
                content = response.text.lower()
                headers = {k.lower(): v.lower() for k, v in response.headers.items()}
                
                # Check for frameworks
                for tech, indicators in self.tech_fingerprints['frameworks'].items():
                    for indicator in indicators:
                        if indicator.lower() in content or indicator.lower() in str(headers):
                            technologies.append(f"Framework: {tech}")
                            break
                
                # Check for servers
                for tech, indicators in self.tech_fingerprints['servers'].items():
                    for indicator in indicators:
                        if indicator.lower() in str(headers):
                            technologies.append(f"Server: {tech}")
                            break
                
                # Check cookies for technology hints
                if 'set-cookie' in headers:
                    cookies = headers['set-cookie']
                    if 'phpsessid' in cookies:
                        technologies.append("Language: PHP")
                    elif 'asp.net' in cookies:
                        technologies.append("Language: ASP.NET")
                    elif 'jsessionid' in cookies:
                        technologies.append("Language: Java")
                        
        except:
            pass
        
        return list(set(technologies))
    
    async def _check_robots_sitemap(self, url: str) -> List[Vulnerability]:
        """Check robots.txt and sitemap for sensitive paths."""
        vulnerabilities = []
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        
        async with httpx.AsyncClient(verify=False) as client:
            # Check robots.txt
            robots_url = urljoin(base_url, '/robots.txt')
            try:
                response = await client.get(robots_url)
                if response.status_code == 200:
                    # Look for sensitive paths
                    sensitive_paths = re.findall(r'Disallow:\s*([^\s]+)', response.text)
                    admin_paths = [path for path in sensitive_paths if any(
                        x in path.lower() for x in ['admin', 'backup', 'config', 'private', 'secret']
                    )]
                    
                    if admin_paths:
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="Sensitive Paths in robots.txt",
                                description="robots.txt reveals sensitive paths",
                                severity=SeverityLevel.LOW,
                                confidence=1.0,
                                affected_urls=[robots_url],
                                evidence={'sensitive_paths': admin_paths[:5]},
                                remediation="Avoid listing sensitive paths in robots.txt.",
                                cwe_ids=["CWE-200"]
                            )
                        )
            except:
                pass
            
            # Check sitemap
            sitemap_url = urljoin(base_url, '/sitemap.xml')
            try:
                response = await client.get(sitemap_url)
                if response.status_code == 200:
                    # Look for admin/sensitive URLs
                    urls = re.findall(r'<loc>([^<]+)</loc>', response.text)
                    sensitive_urls = [url for url in urls if any(
                        x in url.lower() for x in ['admin', 'user', 'private', 'internal']
                    )]
                    
                    if sensitive_urls:
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="Sensitive URLs in Sitemap",
                                description="Sitemap exposes potentially sensitive URLs",
                                severity=SeverityLevel.LOW,
                                confidence=0.8,
                                affected_urls=[sitemap_url],
                                evidence={'sensitive_urls': sensitive_urls[:5]},
                                remediation="Review and remove sensitive URLs from public sitemap.",
                                cwe_ids=["CWE-200"]
                            )
                        )
            except:
                pass
        
        return vulnerabilities
    
    async def _check_directory_listing(self, url: str) -> List[Vulnerability]:
        """Check for directory listing vulnerabilities."""
        vulnerabilities = []
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        
        # Common directories to check
        directories = [
            '/images/', '/img/', '/css/', '/js/', '/scripts/',
            '/uploads/', '/files/', '/documents/', '/backup/',
            '/temp/', '/tmp/', '/logs/', '/data/'
        ]
        
        async with httpx.AsyncClient(verify=False) as client:
            for directory in directories:
                test_url = urljoin(base_url, directory)
                
                try:
                    response = await client.get(test_url)
                    
                    # Check for directory listing indicators
                    if response.status_code == 200:
                        listing_indicators = [
                            'Index of',
                            'Parent Directory',
                            '<title>Index of',
                            'Directory listing for',
                            '[DIR]',
                            '[PARENTDIR]',
                            'Apache Server at',
                            'nginx/',
                        ]
                        
                        for indicator in listing_indicators:
                            if indicator in response.text:
                                vulnerabilities.append(
                                    Vulnerability(
                                        module=self.name,
                                        name=f"Directory Listing Enabled: {directory}",
                                        description=f"Directory listing is enabled for {directory}",
                                        severity=SeverityLevel.MEDIUM,
                                        confidence=1.0,
                                        affected_urls=[test_url],
                                        evidence={'directory': directory, 'indicator': indicator},
                                        remediation="Disable directory listing in web server configuration.",
                                        cwe_ids=["CWE-548"]
                                    )
                                )
                                break
                except:
                    pass
        
        return vulnerabilities
    
    async def _check_source_disclosure(self, url: str) -> List[Vulnerability]:
        """Check for source code disclosure vulnerabilities."""
        vulnerabilities = []
        
        # Try to access source code with backup extensions
        backup_extensions = [
            '.bak', '.backup', '.old', '.orig', '.save',
            '.swp', '.swo', '~', '.tmp', '.temp',
            '.copy', '.1', '.2', '.txt'
        ]
        
        parsed = urlparse(url)
        path = parsed.path if parsed.path else '/index.php'
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        async with httpx.AsyncClient(verify=False) as client:
            for ext in backup_extensions:
                test_url = urljoin(base_url, path + ext)
                
                try:
                    response = await client.get(test_url)
                    
                    if response.status_code == 200:
                        # Check if response contains source code
                        source_indicators = ['<?php', '<%', 'import ', 'function ', 'class ', 'def ', 'var ']
                        if any(indicator in response.text for indicator in source_indicators):
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"Source Code Disclosure: {path + ext}",
                                    description=f"Source code file exposed with extension {ext}",
                                    severity=SeverityLevel.HIGH,
                                    confidence=0.9,
                                    affected_urls=[test_url],
                                    evidence={'file': path + ext},
                                    remediation="Remove backup files and configure server to not serve source files.",
                                    cwe_ids=["CWE-540", "CWE-200"]
                                )
                            )
                except:
                    pass
        
        return vulnerabilities
