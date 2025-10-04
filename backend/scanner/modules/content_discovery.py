"""Content Discovery Module for finding hidden endpoints, directories, and files."""

import asyncio
import httpx
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from urllib.parse import urlparse, urljoin
import re
from pathlib import Path
from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)

class ContentDiscoveryModule(BaseScannerModule):
    """Content discovery and directory brute-forcing module."""
    
    def __init__(self):
        super().__init__()
        self.name = "ContentDiscovery"
        self.description = "Discovers hidden directories, files, and endpoints"
        self.scan_type = ScanType.ACTIVE
        
        # Common directories to check
        self.common_directories = [
            # Admin interfaces
            'admin', 'administrator', 'admin-panel', 'wp-admin', 'cpanel', 'phpmyadmin',
            'adminer', 'manager', 'management', 'panel', 'controlpanel', 'dashboard',
            
            # Authentication
            'login', 'signin', 'auth', 'authenticate', 'sso', 'oauth', 'saml',
            'logout', 'signout', 'register', 'signup', 'forgot-password', 'reset-password',
            
            # API endpoints
            'api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'restapi', 'graphql', 'soap',
            'swagger', 'swagger-ui', 'api-docs', 'openapi', 'docs', 'documentation',
            
            # Development/Debug
            'dev', 'development', 'test', 'testing', 'debug', 'staging', 'stage',
            'demo', 'sandbox', 'alpha', 'beta', 'preview', 'uat',
            
            # Backup and temp
            'backup', 'backups', 'bak', 'old', 'temp', 'tmp', 'cache', '_backup',
            'backup_old', 'site_backup', 'db_backup', 'database_backup',
            
            # Configuration
            'config', 'configuration', 'conf', 'settings', 'setup', 'install',
            'installer', 'installation', 'wizard', 'init',
            
            # Database
            'db', 'database', 'sql', 'mysql', 'phpmyadmin', 'pma', 'dbadmin',
            'sqladmin', 'myadmin', 'postgres', 'mongodb',
            
            # Files and uploads
            'files', 'uploads', 'upload', 'media', 'assets', 'static', 'public',
            'images', 'img', 'css', 'js', 'javascript', 'scripts', 'styles',
            'documents', 'docs', 'downloads', 'download', 'attachments',
            
            # Version control
            '.git', '.svn', '.hg', '.bzr', 'CVS', '.gitignore', '.gitconfig',
            '.git/HEAD', '.git/config', '.svn/entries',
            
            # Hidden directories
            'hidden', 'private', 'secret', 'internal', 'restricted', 'secure',
            'protected', 'confidential',
            
            # Common applications
            'wordpress', 'wp', 'wp-content', 'wp-includes', 'wp-json',
            'joomla', 'drupal', 'magento', 'prestashop', 'opencart',
            'phpbb', 'forum', 'forums', 'blog', 'news', 'wiki',
            
            # Monitoring and logs
            'logs', 'log', 'logging', 'monitor', 'monitoring', 'status',
            'health', 'healthcheck', 'metrics', 'stats', 'statistics',
            'analytics', 'reports', 'reporting',
            
            # User related
            'user', 'users', 'profile', 'profiles', 'account', 'accounts',
            'member', 'members', 'customer', 'customers', 'client', 'clients',
            
            # Other common
            'home', 'index', 'main', 'default', 'portal', 'gateway',
            'service', 'services', 'application', 'applications', 'app',
            'system', 'server', 'node', 'cluster',
        ]
        
        # Common files to check
        self.common_files = [
            # Configuration files
            '.env', '.env.local', '.env.production', '.env.development',
            'config.php', 'config.inc.php', 'configuration.php', 'settings.php',
            'database.php', 'db.php', 'conn.php', 'connect.php',
            'wp-config.php', 'wp-config.php.bak', 'local-config.php',
            '.htaccess', '.htpasswd', 'web.config', 'nginx.conf',
            'package.json', 'composer.json', 'requirements.txt', 'Gemfile',
            
            # Backup files
            'backup.sql', 'dump.sql', 'database.sql', 'db.sql', 'data.sql',
            'backup.zip', 'backup.tar.gz', 'backup.rar', 'site.zip',
            'www.zip', 'website.zip', 'public_html.zip',
            '1.zip', '2.zip', 'old.zip', 'new.zip',
            
            # Information disclosure
            'robots.txt', 'sitemap.xml', 'sitemap.xml.gz', 'crossdomain.xml',
            'clientaccesspolicy.xml', 'security.txt', '.well-known/security.txt',
            'humans.txt', 'readme.txt', 'README.md', 'readme.html',
            'changelog.txt', 'CHANGELOG.md', 'VERSION', 'version.txt',
            'license.txt', 'LICENSE', 'TODO.txt', 'TODO.md',
            
            # Log files
            'error.log', 'errors.log', 'debug.log', 'access.log',
            'system.log', 'application.log', 'app.log', 'development.log',
            'production.log', 'php_error.log', 'mysql_error.log',
            
            # IDE and editor files
            '.idea/workspace.xml', '.vscode/settings.json', '.project',
            '.DS_Store', 'Thumbs.db', 'desktop.ini',
            
            # API documentation
            'swagger.json', 'swagger.yaml', 'openapi.json', 'openapi.yaml',
            'api-docs.json', 'api-docs.yaml',
            
            # Source code
            'index.php.bak', 'index.php~', 'index.php.old', 'index.php.save',
            'admin.php', 'login.php', 'config.php.bak', 'test.php',
            'phpinfo.php', 'info.php', 'i.php', 'php.php',
            
            # Shell scripts
            'shell.php', 'cmd.php', 'command.php', 'terminal.php',
            'console.php', 'eval.php', 'exec.php', 'system.php',
            
            # Database dumps
            'dump.tar.gz', 'mysql.tar.gz', 'backup.tar.gz',
            'database.tar.gz', 'db.tar.gz', 'data.tar.gz',
        ]
        
        # Sensitive file patterns
        self.sensitive_patterns = {
            'private_key': ['.pem', '.key', '.pfx', '.p12', 'id_rsa', 'id_dsa'],
            'config': ['config', 'settings', 'configuration', '.conf', '.ini', '.cfg'],
            'database': ['.sql', '.db', '.sqlite', '.mdb'],
            'backup': ['.bak', '.backup', '.old', '.save', '~', '.swp'],
            'archive': ['.zip', '.tar', '.gz', '.rar', '.7z'],
            'credentials': ['password', 'passwd', 'pwd', 'secret', 'token', 'api_key'],
        }
        
        # Response signatures for interesting findings
        self.interesting_responses = {
            'directory_listing': ['Index of', 'Directory listing', 'Parent Directory'],
            'error_page': ['Fatal error', 'Warning:', 'Notice:', 'Parse error', 
                          'Stack trace', 'Exception', 'Traceback'],
            'debug_info': ['DEBUG', 'Development', 'Staging', 'Test environment'],
            'version_disclosure': ['Version', 'Powered by', 'Server:'],
        }
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is a valid URL."""
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform content discovery scan."""
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'discovered_paths': [],
            'discovered_files': [],
            'interesting_findings': [],
            'potential_vulnerabilities': [],
        }
        statistics = {
            'paths_tested': 0,
            'paths_found': 0,
            'files_tested': 0,
            'files_found': 0,
            'sensitive_files': 0,
            'directory_listings': 0,
        }
        
        try:
            # Ensure URL has scheme
            base_url = config.target
            if not base_url.startswith(('http://', 'https://')):
                base_url = f"https://{base_url}"
            
            # Remove trailing slash
            base_url = base_url.rstrip('/')
            
            # Create HTTP client
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=False,
                timeout=httpx.Timeout(10.0)
            ) as client:
                
                # Get baseline response for 404 detection
                baseline_404 = await self._get_404_baseline(client, base_url)
                
                # Discover directories
                if config.scan_type in [ScanType.ACTIVE, ScanType.AGGRESSIVE]:
                    dir_discoveries = await self._discover_directories(
                        client, base_url, baseline_404, config
                    )
                    info['discovered_paths'].extend(dir_discoveries['paths'])
                    vulnerabilities.extend(dir_discoveries['vulnerabilities'])
                    statistics['paths_tested'] = dir_discoveries['tested']
                    statistics['paths_found'] = len(dir_discoveries['paths'])
                
                # Discover files
                file_discoveries = await self._discover_files(
                    client, base_url, baseline_404, config
                )
                info['discovered_files'].extend(file_discoveries['files'])
                vulnerabilities.extend(file_discoveries['vulnerabilities'])
                statistics['files_tested'] = file_discoveries['tested']
                statistics['files_found'] = len(file_discoveries['files'])
                statistics['sensitive_files'] = file_discoveries['sensitive_count']
                
                # Check for specific vulnerabilities
                specific_vulns = await self._check_specific_vulnerabilities(client, base_url)
                vulnerabilities.extend(specific_vulns)
                
                # Check robots.txt
                robots_findings = await self._analyze_robots_txt(client, base_url)
                if robots_findings:
                    info['interesting_findings'].extend(robots_findings['findings'])
                    vulnerabilities.extend(robots_findings['vulnerabilities'])
                
                # Check for directory listings
                dir_listing_vulns = await self._check_directory_listings(
                    client, base_url, info['discovered_paths']
                )
                vulnerabilities.extend(dir_listing_vulns)
                statistics['directory_listings'] = len(dir_listing_vulns)
                
        except Exception as e:
            errors.append(f"Content discovery scan failed: {str(e)}")
        
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
    
    async def _get_404_baseline(self, client: httpx.AsyncClient, base_url: str) -> Dict[str, Any]:
        """Get baseline 404 response for comparison."""
        baseline = {
            'status_code': 404,
            'content_length': 0,
            'content_patterns': [],
        }
        
        try:
            # Request a random non-existent path
            random_path = f"/random-{datetime.now().timestamp()}-does-not-exist"
            response = await client.get(f"{base_url}{random_path}")
            
            baseline['status_code'] = response.status_code
            baseline['content_length'] = len(response.content)
            
            # Extract common 404 patterns
            if response.text:
                patterns = ['404', 'not found', 'does not exist', 'error']
                baseline['content_patterns'] = [
                    p for p in patterns if p.lower() in response.text.lower()
                ]
        except:
            pass
        
        return baseline
    
    async def _discover_directories(
        self, 
        client: httpx.AsyncClient, 
        base_url: str, 
        baseline_404: Dict,
        config: ScanConfig
    ) -> Dict[str, Any]:
        """Discover directories through brute-forcing."""
        discovered = []
        vulnerabilities = []
        tested = 0
        
        # Limit directories based on scan type
        if config.scan_type == ScanType.ACTIVE:
            directories_to_test = self.common_directories[:50]  # Test top 50
        else:  # AGGRESSIVE
            directories_to_test = self.common_directories
        
        # Test directories with rate limiting
        semaphore = asyncio.Semaphore(config.rate_limit)
        
        async def check_directory(directory: str):
            nonlocal tested
            async with semaphore:
                tested += 1
                url = f"{base_url}/{directory}"
                
                try:
                    response = await client.get(url, timeout=5.0)
                    
                    # Check if directory exists (not 404)
                    if self._is_valid_response(response, baseline_404):
                        discovered.append({
                            'path': f"/{directory}",
                            'status_code': response.status_code,
                            'size': len(response.content),
                            'title': self._extract_title(response.text),
                        })
                        
                        # Check for sensitive directories
                        vuln = self._check_sensitive_directory(directory, url, response)
                        if vuln:
                            vulnerabilities.append(vuln)
                        
                        # Check response content for interesting patterns
                        interesting = self._check_interesting_response(response.text, url)
                        if interesting:
                            vulnerabilities.extend(interesting)
                            
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    pass
        
        # Run directory checks concurrently
        tasks = [check_directory(dir) for dir in directories_to_test]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            'paths': discovered,
            'vulnerabilities': vulnerabilities,
            'tested': tested,
        }
    
    async def _discover_files(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        baseline_404: Dict,
        config: ScanConfig
    ) -> Dict[str, Any]:
        """Discover files through brute-forcing."""
        discovered = []
        vulnerabilities = []
        tested = 0
        sensitive_count = 0
        
        # Limit files based on scan type
        if config.scan_type == ScanType.PASSIVE:
            files_to_test = self.common_files[:20]  # Test top 20
        elif config.scan_type == ScanType.ACTIVE:
            files_to_test = self.common_files[:50]  # Test top 50
        else:  # AGGRESSIVE
            files_to_test = self.common_files
        
        # Test files with rate limiting
        semaphore = asyncio.Semaphore(config.rate_limit)
        
        async def check_file(filename: str):
            nonlocal tested, sensitive_count
            async with semaphore:
                tested += 1
                url = f"{base_url}/{filename}"
                
                try:
                    response = await client.get(url, timeout=5.0)
                    
                    # Check if file exists (not 404)
                    if self._is_valid_response(response, baseline_404):
                        file_info = {
                            'filename': filename,
                            'url': url,
                            'status_code': response.status_code,
                            'size': len(response.content),
                            'content_type': response.headers.get('content-type', 'unknown'),
                        }
                        discovered.append(file_info)
                        
                        # Check for sensitive files
                        vuln = self._check_sensitive_file(filename, url, response)
                        if vuln:
                            vulnerabilities.append(vuln)
                            sensitive_count += 1
                            
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    pass
        
        # Run file checks concurrently
        tasks = [check_file(file) for file in files_to_test]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            'files': discovered,
            'vulnerabilities': vulnerabilities,
            'tested': tested,
            'sensitive_count': sensitive_count,
        }
    
    def _is_valid_response(self, response: httpx.Response, baseline_404: Dict) -> bool:
        """Check if response indicates a valid resource (not 404)."""
        # Check status code
        if response.status_code in [200, 201, 301, 302, 401, 403]:
            return True
        
        # If status is 404, check if it's a custom 404 page
        if response.status_code == 404:
            # Check content length difference
            if abs(len(response.content) - baseline_404['content_length']) > 500:
                return True
            
            # Check for absence of 404 patterns
            if baseline_404['content_patterns']:
                has_404_pattern = any(
                    pattern in response.text.lower() 
                    for pattern in baseline_404['content_patterns']
                )
                if not has_404_pattern:
                    return True
        
        return False
    
    def _extract_title(self, html: str) -> str:
        """Extract title from HTML."""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""
    
    def _check_sensitive_directory(
        self, 
        directory: str, 
        url: str, 
        response: httpx.Response
    ) -> Optional[Vulnerability]:
        """Check if discovered directory is sensitive."""
        sensitive_dirs = [
            'admin', 'administrator', 'phpmyadmin', 'wp-admin',
            '.git', '.svn', 'backup', 'database', 'config',
            'api', 'swagger', 'graphql', 'debug', 'test'
        ]
        
        for sensitive in sensitive_dirs:
            if sensitive in directory.lower():
                severity = SeverityLevel.HIGH if sensitive in ['.git', '.svn', 'phpmyadmin'] else SeverityLevel.MEDIUM
                
                return Vulnerability(
                    module=self.name,
                    name=f"Sensitive Directory Exposed: {directory}",
                    description=f"Sensitive directory '{directory}' is accessible",
                    severity=severity,
                    confidence=0.9,
                    affected_urls=[url],
                    evidence={
                        'directory': directory,
                        'status_code': response.status_code,
                        'accessible': response.status_code != 403,
                    },
                    remediation=f"Restrict access to {directory} directory or remove if unnecessary",
                    cwe_ids=["CWE-548"]
                )
        
        return None
    
    def _check_sensitive_file(
        self,
        filename: str,
        url: str,
        response: httpx.Response
    ) -> Optional[Vulnerability]:
        """Check if discovered file contains sensitive information."""
        
        # Check for specific sensitive files
        critical_files = {
            '.env': ('Environment Configuration File', SeverityLevel.CRITICAL),
            'wp-config.php': ('WordPress Configuration', SeverityLevel.CRITICAL),
            '.git/config': ('Git Configuration', SeverityLevel.HIGH),
            'database.sql': ('Database Dump', SeverityLevel.CRITICAL),
            'backup.sql': ('Database Backup', SeverityLevel.CRITICAL),
            '.htpasswd': ('Password File', SeverityLevel.HIGH),
            'id_rsa': ('Private SSH Key', SeverityLevel.CRITICAL),
        }
        
        for critical_file, (desc, severity) in critical_files.items():
            if critical_file in filename.lower():
                return Vulnerability(
                    module=self.name,
                    name=f"Critical File Exposed: {desc}",
                    description=f"Sensitive file '{filename}' is publicly accessible",
                    severity=severity,
                    confidence=1.0,
                    affected_urls=[url],
                    evidence={
                        'filename': filename,
                        'size': len(response.content),
                        'sample': response.text[:200] if response.text else None,
                    },
                    remediation=f"Remove or restrict access to {filename} immediately",
                    cwe_ids=["CWE-200", "CWE-538"]
                )
        
        # Check for backup files
        if any(ext in filename for ext in ['.bak', '.backup', '.old', '~', '.save']):
            return Vulnerability(
                module=self.name,
                name=f"Backup File Exposed: {filename}",
                description=f"Backup file '{filename}' is accessible and may contain sensitive data",
                severity=SeverityLevel.MEDIUM,
                confidence=0.9,
                affected_urls=[url],
                remediation="Remove backup files from web root",
                cwe_ids=["CWE-530"]
            )
        
        # Check for information disclosure in content
        if response.text:
            sensitive_patterns = [
                (r'(?i)password\s*[:=]\s*["\']?[\w]+', 'Password in file'),
                (r'(?i)api[_-]?key\s*[:=]\s*["\']?[\w]+', 'API key in file'),
                (r'(?i)secret[_-]?key\s*[:=]\s*["\']?[\w]+', 'Secret key in file'),
                (r'(?i)aws[_-]?access[_-]?key', 'AWS credentials'),
                (r'(?i)private[_-]?key', 'Private key'),
            ]
            
            for pattern, desc in sensitive_patterns:
                if re.search(pattern, response.text):
                    return Vulnerability(
                        module=self.name,
                        name=f"Sensitive Data in File: {desc}",
                        description=f"File '{filename}' contains {desc.lower()}",
                        severity=SeverityLevel.HIGH,
                        confidence=0.8,
                        affected_urls=[url],
                        evidence={'filename': filename},
                        remediation="Remove sensitive data from publicly accessible files",
                        cwe_ids=["CWE-200"]
                    )
        
        return None
    
    def _check_interesting_response(self, content: str, url: str) -> List[Vulnerability]:
        """Check response content for interesting patterns."""
        vulnerabilities = []
        
        if not content:
            return vulnerabilities
        
        # Check for directory listing
        if any(pattern in content for pattern in self.interesting_responses['directory_listing']):
            vulnerabilities.append(
                Vulnerability(
                    module=self.name,
                    name="Directory Listing Enabled",
                    description="Directory listing is enabled, exposing file structure",
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.9,
                    affected_urls=[url],
                    remediation="Disable directory listing in web server configuration",
                    cwe_ids=["CWE-548"]
                )
            )
        
        # Check for error messages
        if any(pattern in content for pattern in self.interesting_responses['error_page']):
            vulnerabilities.append(
                Vulnerability(
                    module=self.name,
                    name="Verbose Error Messages",
                    description="Application exposes detailed error messages",
                    severity=SeverityLevel.LOW,
                    confidence=0.8,
                    affected_urls=[url],
                    remediation="Disable debug mode and use custom error pages",
                    cwe_ids=["CWE-209"]
                )
            )
        
        # Check for debug information
        if any(pattern in content for pattern in self.interesting_responses['debug_info']):
            vulnerabilities.append(
                Vulnerability(
                    module=self.name,
                    name="Debug Information Exposed",
                    description="Debug or development information is exposed",
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.7,
                    affected_urls=[url],
                    remediation="Disable debug mode in production",
                    cwe_ids=["CWE-489"]
                )
            )
        
        return vulnerabilities
    
    async def _check_specific_vulnerabilities(
        self,
        client: httpx.AsyncClient,
        base_url: str
    ) -> List[Vulnerability]:
        """Check for specific known vulnerabilities."""
        vulnerabilities = []
        
        # Check for Git repository exposure
        git_vuln = await self._check_git_exposure(client, base_url)
        if git_vuln:
            vulnerabilities.append(git_vuln)
        
        # Check for SVN repository exposure
        svn_vuln = await self._check_svn_exposure(client, base_url)
        if svn_vuln:
            vulnerabilities.append(svn_vuln)
        
        # Check for phpinfo() exposure
        phpinfo_vuln = await self._check_phpinfo(client, base_url)
        if phpinfo_vuln:
            vulnerabilities.append(phpinfo_vuln)
        
        return vulnerabilities
    
    async def _check_git_exposure(
        self,
        client: httpx.AsyncClient,
        base_url: str
    ) -> Optional[Vulnerability]:
        """Check for exposed Git repository."""
        try:
            response = await client.get(f"{base_url}/.git/HEAD")
            if response.status_code == 200 and 'ref:' in response.text:
                return Vulnerability(
                    module=self.name,
                    name="Git Repository Exposed",
                    description="Git repository (.git) is publicly accessible",
                    severity=SeverityLevel.CRITICAL,
                    confidence=1.0,
                    affected_urls=[f"{base_url}/.git/"],
                    evidence={'git_head': response.text[:100]},
                    remediation="Remove .git directory from web root or restrict access",
                    references=["https://github.com/lijiejie/GitHack"],
                    cwe_ids=["CWE-538"]
                )
        except:
            pass
        
        return None
    
    async def _check_svn_exposure(
        self,
        client: httpx.AsyncClient,
        base_url: str
    ) -> Optional[Vulnerability]:
        """Check for exposed SVN repository."""
        try:
            response = await client.get(f"{base_url}/.svn/entries")
            if response.status_code == 200:
                return Vulnerability(
                    module=self.name,
                    name="SVN Repository Exposed",
                    description="Subversion repository (.svn) is publicly accessible",
                    severity=SeverityLevel.HIGH,
                    confidence=1.0,
                    affected_urls=[f"{base_url}/.svn/"],
                    remediation="Remove .svn directory from web root or restrict access",
                    cwe_ids=["CWE-538"]
                )
        except:
            pass
        
        return None
    
    async def _check_phpinfo(
        self,
        client: httpx.AsyncClient,
        base_url: str
    ) -> Optional[Vulnerability]:
        """Check for phpinfo() exposure."""
        phpinfo_files = ['phpinfo.php', 'info.php', 'i.php', 'php.php', 'test.php']
        
        for file in phpinfo_files:
            try:
                response = await client.get(f"{base_url}/{file}")
                if response.status_code == 200 and 'phpinfo()' in response.text:
                    return Vulnerability(
                        module=self.name,
                        name="PHPInfo() Page Exposed",
                        description=f"PHPInfo page ({file}) exposes sensitive configuration",
                        severity=SeverityLevel.HIGH,
                        confidence=1.0,
                        affected_urls=[f"{base_url}/{file}"],
                        remediation="Remove phpinfo files from production",
                        cwe_ids=["CWE-200"]
                    )
            except:
                pass
        
        return None
    
    async def _analyze_robots_txt(
        self,
        client: httpx.AsyncClient,
        base_url: str
    ) -> Optional[Dict[str, Any]]:
        """Analyze robots.txt for interesting paths."""
        findings = []
        vulnerabilities = []
        
        try:
            response = await client.get(f"{base_url}/robots.txt")
            if response.status_code == 200:
                lines = response.text.split('\n')
                
                disallowed_paths = []
                for line in lines:
                    if line.strip().startswith('Disallow:'):
                        path = line.split('Disallow:')[1].strip()
                        if path and path != '/':
                            disallowed_paths.append(path)
                            findings.append(f"Disallowed path in robots.txt: {path}")
                
                # Check if sensitive paths are mentioned
                sensitive_keywords = ['admin', 'backup', 'config', 'database', 'private']
                for path in disallowed_paths:
                    if any(keyword in path.lower() for keyword in sensitive_keywords):
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="Sensitive Path in robots.txt",
                                description=f"robots.txt reveals sensitive path: {path}",
                                severity=SeverityLevel.LOW,
                                confidence=0.7,
                                affected_urls=[base_url],
                                evidence={'path': path},
                                remediation="Avoid listing sensitive paths in robots.txt",
                                cwe_ids=["CWE-200"]
                            )
                        )
                
                return {'findings': findings, 'vulnerabilities': vulnerabilities}
        except:
            pass
        
        return None
    
    async def _check_directory_listings(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        discovered_paths: List[Dict]
    ) -> List[Vulnerability]:
        """Check discovered directories for directory listing vulnerabilities."""
        vulnerabilities = []
        
        for path_info in discovered_paths:
            path = path_info.get('path', '')
            if path:
                try:
                    url = f"{base_url}{path}"
                    response = await client.get(url)
                    
                    # Check for directory listing indicators
                    if any(indicator in response.text for indicator in ['Index of', 'Directory listing', 'Parent Directory']):
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"Directory Listing: {path}",
                                description=f"Directory listing is enabled for {path}",
                                severity=SeverityLevel.MEDIUM,
                                confidence=0.95,
                                affected_urls=[url],
                                remediation="Disable directory listing in web server configuration",
                                cwe_ids=["CWE-548"]
                            )
                        )
                except:
                    pass
        
        return vulnerabilities
