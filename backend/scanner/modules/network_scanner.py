"""Network Scanner Module with built-in fallback for when Nmap is not available."""

# Try to import nmap, but don't fail if it's not available
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import ipaddress
import re
import socket
import concurrent.futures
import ssl
from ..base_module import (
    BaseScannerModule, 
    ScanConfig, 
    ScanResult, 
    Vulnerability, 
    SeverityLevel,
    ScanType
)

class NetworkScanner(BaseScannerModule):
    """Network scanning module that works with or without Nmap."""
    
    def __init__(self):
        super().__init__()
        self.name = "NetworkScanner"
        self.scan_type = ScanType.ACTIVE
        
        # Check if we can use nmap
        if NMAP_AVAILABLE:
            try:
                self.nm = nmap.PortScanner()
                self.use_nmap = True
                self.description = "Performs network scanning for open ports and services using Nmap"
            except:
                self.nm = None
                self.use_nmap = False
                self.description = "Performs network scanning using Python sockets (Nmap not available)"
        else:
            self.nm = None
            self.use_nmap = False
            self.description = "Performs network scanning using Python sockets (Nmap not installed)"
        
        # Common vulnerable ports
        self.vulnerable_ports = {
            21: ("FTP", "File Transfer Protocol - Often misconfigured"),
            22: ("SSH", "Secure Shell - Check for weak authentication"),
            23: ("Telnet", "Unencrypted protocol - Critical security risk"),
            25: ("SMTP", "Mail server - Check for open relay"),
            53: ("DNS", "Domain Name System - Check for zone transfers"),
            80: ("HTTP", "Unencrypted web traffic"),
            110: ("POP3", "Mail protocol - Often unencrypted"),
            111: ("RPC", "Remote Procedure Call - Information disclosure"),
            135: ("RPC-DCOM", "Windows RPC - Often exploitable"),
            139: ("NetBIOS", "Windows networking - Information disclosure"),
            143: ("IMAP", "Mail protocol - Check encryption"),
            443: ("HTTPS", "Encrypted web traffic"),
            445: ("SMB", "Windows file sharing - Often vulnerable"),
            1433: ("MSSQL", "Microsoft SQL Server - Check authentication"),
            1521: ("Oracle", "Oracle Database - Check authentication"),
            3306: ("MySQL", "MySQL Database - Check authentication"),
            3389: ("RDP", "Remote Desktop - Brute force target"),
            5432: ("PostgreSQL", "PostgreSQL Database - Check authentication"),
            5900: ("VNC", "Virtual Network Computing - Often weak auth"),
            6379: ("Redis", "Redis Database - Often unauthenticated"),
            8080: ("HTTP-Alt", "Alternative HTTP port"),
            8443: ("HTTPS-Alt", "Alternative HTTPS port"),
            9200: ("Elasticsearch", "Often exposed without authentication"),
            27017: ("MongoDB", "MongoDB Database - Check authentication"),
        }
        
    def validate_target(self, target: str) -> bool:
        """Validate if target is a valid IP or hostname."""
        # Check if it's an IP address
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        
        # Check if it's a valid hostname/domain
        hostname_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        # Extract hostname from URL if needed
        if target.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            target = parsed.hostname
        
        return bool(hostname_pattern.match(target)) if target else False
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform network scan using Nmap or fallback to socket scanning."""
        # Use socket-based scanning if nmap is not available
        if not self.use_nmap:
            return await self._scan_with_sockets(config)
        
        # Otherwise use nmap
        started_at = datetime.now(timezone.utc)
        vulnerabilities = []
        errors = []
        warnings = []
        info = {}
        statistics = {
            "total_ports_scanned": 0,
            "open_ports": 0,
            "closed_ports": 0,
            "filtered_ports": 0,
            "services_detected": 0,
        }
        
        try:
            # Extract hostname/IP from URL if needed
            target = config.target
            if target.startswith(('http://', 'https://')):
                from urllib.parse import urlparse
                parsed = urlparse(target)
                target = parsed.hostname
            
            # Determine scan arguments based on scan type
            scan_args = self._get_scan_arguments(config.scan_type)
            
            # Run Nmap scan in executor to avoid blocking
            loop = asyncio.get_event_loop()
            scan_result = await loop.run_in_executor(
                None, 
                self._perform_nmap_scan,
                target,
                scan_args
            )
            
            if scan_result:
                # Process scan results
                for host in scan_result.all_hosts():
                    host_info = scan_result[host]
                    
                    # Store host information
                    info['host'] = {
                        'ip': host,
                        'hostname': host_info.hostname(),
                        'state': host_info.state(),
                        'os_detection': self._extract_os_info(host_info),
                    }
                    
                    # Process ports
                    if 'tcp' in host_info:
                        for port, port_info in host_info['tcp'].items():
                            statistics['total_ports_scanned'] += 1
                            
                            if port_info['state'] == 'open':
                                statistics['open_ports'] += 1
                                
                                # Check for vulnerable services
                                vuln = self._check_port_vulnerability(
                                    port, 
                                    port_info,
                                    host
                                )
                                if vuln:
                                    vulnerabilities.append(vuln)
                                
                                # Detect services
                                if port_info.get('name'):
                                    statistics['services_detected'] += 1
                                    
                            elif port_info['state'] == 'closed':
                                statistics['closed_ports'] += 1
                            elif port_info['state'] == 'filtered':
                                statistics['filtered_ports'] += 1
                    
                    # Check for specific vulnerabilities using NSE scripts
                    if config.scan_type in [ScanType.ACTIVE, ScanType.AGGRESSIVE]:
                        script_vulns = await self._run_vulnerability_scripts(host)
                        vulnerabilities.extend(script_vulns)
                        
        except Exception as e:
            errors.append(f"Network scan failed: {str(e)}")
            
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
    
    def _get_scan_arguments(self, scan_type: ScanType) -> str:
        """Get Nmap arguments based on scan type."""
        if scan_type == ScanType.PASSIVE:
            # Passive scan - minimal intrusion
            return "-sn -PS21,22,25,80,443"  # Ping scan with common ports
        elif scan_type == ScanType.ACTIVE:
            # Active scan - standard port scan
            return "-sS -sV -O -A --top-ports 1000"  # SYN scan with version and OS detection
        else:  # AGGRESSIVE
            # Aggressive scan - comprehensive
            return "-sS -sV -sC -O -A -p- --script vuln"  # Full port scan with vulnerability scripts
    
    def _perform_nmap_scan(self, target: str, arguments: str) -> Dict:
        """Perform the actual Nmap scan."""
        try:
            self.nm.scan(hosts=target, arguments=arguments)
            return self.nm
        except Exception as e:
            raise Exception(f"Nmap scan failed: {str(e)}")
    
    def _check_port_vulnerability(
        self, 
        port: int, 
        port_info: Dict,
        host: str
    ) -> Optional[Vulnerability]:
        """Check if an open port represents a vulnerability."""
        
        service_name = port_info.get('name', 'unknown')
        service_product = port_info.get('product', '')
        service_version = port_info.get('version', '')
        
        # Check for known vulnerable ports
        if port in self.vulnerable_ports:
            port_desc, risk_info = self.vulnerable_ports[port]
            
            # Determine severity based on port and service
            severity = self._determine_port_severity(port, port_info)
            
            vuln = Vulnerability(
                module=self.name,
                name=f"Open {port_desc} Port Detected",
                description=f"Port {port} ({port_desc}) is open on {host}. {risk_info}",
                severity=severity,
                confidence=0.9,
                affected_urls=[f"{host}:{port}"],
                evidence={
                    "port": port,
                    "service": service_name,
                    "product": service_product,
                    "version": service_version,
                    "state": port_info['state'],
                },
                remediation=self._get_port_remediation(port, service_name),
                references=[
                    f"https://www.speedguide.net/port.php?port={port}",
                    "https://www.iana.org/assignments/service-names-port-numbers/"
                ]
            )
            
            # Add CVE information if available
            if service_product and service_version:
                vuln.metadata['requires_cve_check'] = True
                vuln.metadata['product'] = service_product
                vuln.metadata['version'] = service_version
            
            return vuln
        
        # Check for uncommon open ports (potential backdoors)
        elif port > 10000:
            return Vulnerability(
                module=self.name,
                name=f"Unusual High Port Open",
                description=f"Uncommon high port {port} is open on {host}. This could indicate a backdoor or non-standard service.",
                severity=SeverityLevel.MEDIUM,
                confidence=0.6,
                affected_urls=[f"{host}:{port}"],
                evidence={
                    "port": port,
                    "service": service_name,
                    "state": port_info['state'],
                },
                remediation="Investigate the service running on this port and close if unnecessary.",
            )
        
        return None
    
    def _determine_port_severity(self, port: int, port_info: Dict) -> SeverityLevel:
        """Determine severity level based on port and service."""
        
        # Critical severity for unencrypted sensitive services
        critical_ports = [23, 21, 110, 143, 445, 3389, 5900]
        if port in critical_ports:
            return SeverityLevel.CRITICAL
        
        # High severity for database and admin ports
        high_ports = [1433, 1521, 3306, 5432, 6379, 9200, 27017, 135, 139]
        if port in high_ports:
            return SeverityLevel.HIGH
        
        # Medium severity for web and mail services
        medium_ports = [80, 25, 53, 111, 8080, 8443]
        if port in medium_ports:
            return SeverityLevel.MEDIUM
        
        # Low severity for encrypted services
        low_ports = [22, 443]
        if port in low_ports:
            return SeverityLevel.LOW
        
        return SeverityLevel.INFO
    
    def _get_port_remediation(self, port: int, service: str) -> str:
        """Get remediation advice for specific ports."""
        
        remediations = {
            21: "Disable FTP and use SFTP/FTPS instead. If FTP is required, ensure strong authentication and consider using FTP over TLS.",
            22: "Ensure SSH is using key-based authentication, disable root login, and use fail2ban to prevent brute force attacks.",
            23: "Immediately disable Telnet and use SSH instead. Telnet transmits everything in plaintext including passwords.",
            25: "Configure SMTP authentication, use TLS/SSL, and ensure the server is not an open relay.",
            53: "Restrict zone transfers, implement DNSSEC, and limit recursive queries to trusted sources.",
            80: "Implement HTTPS redirection and ensure all sensitive data is transmitted over encrypted connections.",
            110: "Use POP3S (port 995) instead of plain POP3. Implement SSL/TLS encryption.",
            135: "Block this port at the firewall. It's rarely needed externally and often exploited.",
            139: "Disable NetBIOS over TCP/IP if not needed. Block at firewall for external access.",
            143: "Use IMAPS (port 993) instead of plain IMAP. Implement SSL/TLS encryption.",
            445: "Restrict SMB access to trusted networks only. Keep systems patched against SMB vulnerabilities.",
            1433: "Use Windows Authentication, encrypt connections, and restrict access to specific IPs.",
            3306: "Bind MySQL to localhost only if external access isn't needed. Use SSL connections and strong passwords.",
            3389: "Use VPN for RDP access, implement Network Level Authentication, and restrict access by IP.",
            5432: "Configure pg_hba.conf properly, use SSL connections, and restrict access by IP.",
            6379: "Enable Redis authentication, bind to localhost if possible, and use SSH tunneling for remote access.",
            9200: "Enable Elasticsearch security features, use authentication, and restrict access by IP.",
            27017: "Enable MongoDB authentication, use SSL/TLS, and bind to localhost if external access isn't needed.",
        }
        
        return remediations.get(
            port, 
            f"Review if this service ({service}) is necessary. If not, disable it. If required, ensure it's properly secured with authentication and encryption."
        )
    
    def _extract_os_info(self, host_info: Dict) -> Dict:
        """Extract OS detection information."""
        os_info = {}
        
        if 'osmatch' in host_info:
            os_matches = host_info['osmatch']
            if os_matches:
                best_match = os_matches[0]
                os_info = {
                    'name': best_match.get('name', 'Unknown'),
                    'accuracy': best_match.get('accuracy', 0),
                    'type': best_match.get('osclass', [{}])[0].get('type', 'Unknown') if best_match.get('osclass') else 'Unknown',
                }
        
        return os_info
    
    async def _run_vulnerability_scripts(self, host: str) -> List[Vulnerability]:
        """Run Nmap vulnerability detection scripts."""
        vulnerabilities = []
        
        try:
            # Run specific vulnerability scripts
            loop = asyncio.get_event_loop()
            script_results = await loop.run_in_executor(
                None,
                self._run_nse_scripts,
                host
            )
            
            # Parse script results for vulnerabilities
            if script_results:
                for script_name, script_output in script_results.items():
                    if 'VULNERABLE' in str(script_output).upper():
                        vuln = Vulnerability(
                            module=self.name,
                            name=f"NSE Script Vulnerability: {script_name}",
                            description=f"Nmap script {script_name} detected a vulnerability",
                            severity=SeverityLevel.HIGH,
                            confidence=0.8,
                            affected_urls=[host],
                            evidence={"script": script_name, "output": str(script_output)},
                            remediation="Review the specific vulnerability and apply appropriate patches or configuration changes.",
                        )
                        vulnerabilities.append(vuln)
                        
        except Exception as e:
            # Log error but don't fail the entire scan
            pass
        
        return vulnerabilities
    
    def _run_nse_scripts(self, host: str) -> Dict:
        """Run NSE vulnerability detection scripts."""
        try:
            # Run common vulnerability scripts
            scripts = "vuln,exploit,auth,default,discovery"
            self.nm.scan(hosts=host, arguments=f"--script {scripts}")
            
            if host in self.nm.all_hosts():
                return self.nm[host].get('hostscript', {})
        except:
            pass
        
        return {}
    
    async def _scan_with_sockets(self, config: ScanConfig) -> ScanResult:
        """Fallback socket-based scanning when Nmap is not available."""
        started_at = datetime.now(timezone.utc)
        vulnerabilities = []
        errors = []
        warnings = []
        info = {"open_ports": [], "services": {}}
        statistics = {
            "total_ports_scanned": 0,
            "open_ports": 0,
            "closed_ports": 0,
            "services_detected": 0,
        }
        
        try:
            # Extract hostname/IP
            target = config.target
            if target.startswith(('http://', 'https://')):
                from urllib.parse import urlparse
                parsed = urlparse(target)
                target = parsed.hostname
            
            # Resolve to IP
            try:
                ip = socket.gethostbyname(target)
                info['target_ip'] = ip
                info['hostname'] = target
            except socket.gaierror:
                errors.append(f"Cannot resolve hostname: {target}")
                return ScanResult(
                    module_name=self.name,
                    success=False,
                    started_at=started_at,
                    completed_at=datetime.now(timezone.utc),
                    vulnerabilities=vulnerabilities,
                    errors=errors,
                    warnings=warnings,
                    info=info,
                    statistics=statistics
                )
            
            # Determine which ports to scan
            if config.scan_type == ScanType.PASSIVE:
                ports_to_scan = [80, 443]  # Minimal scan
            elif config.scan_type == ScanType.ACTIVE:
                ports_to_scan = list(self.vulnerable_ports.keys())[:15]  # Top 15 common ports
            else:  # AGGRESSIVE
                ports_to_scan = list(range(1, 1001))  # Top 1000 ports
            
            # Scan ports
            open_ports = await self._scan_ports_with_sockets(ip, ports_to_scan, config.timeout or 1)
            
            statistics['total_ports_scanned'] = len(ports_to_scan)
            statistics['open_ports'] = len(open_ports)
            statistics['closed_ports'] = len(ports_to_scan) - len(open_ports)
            
            # Detect services and check for vulnerabilities
            for port in open_ports:
                info['open_ports'].append(port)
                
                # Try to detect service
                service = await self._detect_service_with_socket(ip, port)
                if service:
                    info['services'][port] = service
                    statistics['services_detected'] += 1
                
                # Check for vulnerabilities using simplified port_info
                port_info = {'name': service, 'state': 'open'}
                vuln = self._check_port_vulnerability(port, port_info, ip)
                if vuln:
                    vulnerabilities.append(vuln)
            
            # Add warning that this is fallback mode
            warnings.append("Using fallback socket scanning (Nmap not available). Install Nmap for more comprehensive scanning.")
                
        except Exception as e:
            errors.append(f"Socket scan failed: {str(e)}")
        
        completed_at = datetime.now(timezone.utc)
        
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
    
    async def _scan_ports_with_sockets(self, host: str, ports: List[int], timeout: int = 1) -> List[int]:
        """Scan multiple ports using sockets."""
        open_ports = []
        
        # Use ThreadPoolExecutor for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            # Create tasks for all ports
            future_to_port = {
                executor.submit(self._is_port_open_socket, host, port, timeout): port 
                for port in ports
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except:
                    pass
        
        return sorted(open_ports)
    
    def _is_port_open_socket(self, host: str, port: int, timeout: int = 1) -> bool:
        """Check if a single port is open using socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    async def _detect_service_with_socket(self, host: str, port: int) -> str:
        """Try to detect what service is running on a port using sockets."""
        # First check if it's a known port
        if port in self.vulnerable_ports:
            service = self.vulnerable_ports[port][0]
            
            # Try to grab banner for verification
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((host, port))
                
                # Send a probe and get response for HTTP ports
                if port in [80, 8080]:
                    sock.send(b"GET / HTTP/1.0\r\n\r\n")
                elif port in [443, 8443]:
                    # HTTPS requires SSL
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock)
                    sock.send(b"GET / HTTP/1.0\r\n\r\n")
                
                # Try to receive banner
                try:
                    banner = sock.recv(1024)
                    sock.close()
                    
                    # Check banner patterns
                    service_patterns = {
                        b'SSH': 'SSH',
                        b'220': 'FTP/SMTP',
                        b'HTTP': 'HTTP',
                        b'+OK': 'POP3',
                        b'* OK': 'IMAP',
                        b'mysql_native_password': 'MySQL',
                        b'PostgreSQL': 'PostgreSQL',
                    }
                    
                    for pattern, service_name in service_patterns.items():
                        if pattern in banner:
                            return f"{service} ({service_name} detected)"
                except:
                    pass
                    
            except:
                pass
            
            return service
        
        return "Unknown"
