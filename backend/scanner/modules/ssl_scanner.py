"""SSL/TLS Scanner Module using SSLyze for comprehensive SSL/TLS configuration analysis."""

import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from urllib.parse import urlparse
import ssl
import socket
from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommand,
    ServerHostnameCouldNotBeResolved,
)
from sslyze.plugins.scan_commands import ScanCommand as ScanCommandEnum
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)

class SSLScanner(BaseScannerModule):
    """SSL/TLS configuration scanner using SSLyze."""
    
    def __init__(self):
        super().__init__()
        self.name = "SSLScanner"
        self.description = "Analyzes SSL/TLS configuration for security vulnerabilities"
        self.scan_type = ScanType.PASSIVE
        
        # Weak cipher suites to check for
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon',
            'IDEA', 'SEED', 'CAMELLIA', 'ARIA'
        ]
        
        # Insecure SSL/TLS protocols
        self.insecure_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
        
        # Known SSL/TLS vulnerabilities
        self.known_vulnerabilities = {
            'heartbleed': {
                'name': 'Heartbleed (CVE-2014-0160)',
                'severity': SeverityLevel.CRITICAL,
                'cve': 'CVE-2014-0160',
                'description': 'Server is vulnerable to Heartbleed attack allowing memory disclosure'
            },
            'ccs_injection': {
                'name': 'CCS Injection (CVE-2014-0224)',
                'severity': SeverityLevel.HIGH,
                'cve': 'CVE-2014-0224',
                'description': 'Server is vulnerable to CCS injection allowing MITM attacks'
            },
            'robot': {
                'name': 'ROBOT Attack',
                'severity': SeverityLevel.HIGH,
                'description': 'Server is vulnerable to ROBOT (Return Of Bleichenbacher\'s Oracle Threat)'
            },
            'crime': {
                'name': 'CRIME Attack',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Server is vulnerable to CRIME compression attack'
            },
            'breach': {
                'name': 'BREACH Attack',
                'severity': SeverityLevel.MEDIUM,
                'description': 'Server may be vulnerable to BREACH compression attack'
            },
            'poodle': {
                'name': 'POODLE (CVE-2014-3566)',
                'severity': SeverityLevel.HIGH,
                'cve': 'CVE-2014-3566',
                'description': 'Server is vulnerable to POODLE attack on SSLv3'
            },
            'sweet32': {
                'name': 'Sweet32 (CVE-2016-2183)',
                'severity': SeverityLevel.MEDIUM,
                'cve': 'CVE-2016-2183',
                'description': 'Server uses 64-bit block ciphers vulnerable to Sweet32 attack'
            },
            'drown': {
                'name': 'DROWN (CVE-2016-0800)',
                'severity': SeverityLevel.HIGH,
                'cve': 'CVE-2016-0800',
                'description': 'Server is vulnerable to DROWN attack'
            },
            'logjam': {
                'name': 'Logjam (CVE-2015-4000)',
                'severity': SeverityLevel.HIGH,
                'cve': 'CVE-2015-4000',
                'description': 'Server is vulnerable to Logjam attack on weak DH parameters'
            },
            'freak': {
                'name': 'FREAK (CVE-2015-0204)',
                'severity': SeverityLevel.HIGH,
                'cve': 'CVE-2015-0204',
                'description': 'Server is vulnerable to FREAK attack allowing downgrade to export ciphers'
            }
        }
    
    def validate_target(self, target: str) -> bool:
        """Validate if target has SSL/TLS enabled."""
        # Extract hostname and port
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        else:
            hostname = target
            port = 443
        
        # Check if SSL/TLS is available
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return True
        except:
            return False
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform SSL/TLS configuration scan."""
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'certificate': {},
            'protocols': {},
            'cipher_suites': {},
            'vulnerabilities': {},
            'configuration': {}
        }
        statistics = {
            'protocols_tested': 0,
            'cipher_suites_tested': 0,
            'vulnerabilities_found': 0,
            'weak_ciphers_found': 0,
            'certificate_issues': 0
        }
        
        try:
            # Parse target
            hostname, port = self._parse_target(config.target)
            
            # Create SSLyze scanner
            scanner = Scanner()
            
            # Define scan commands based on scan type
            scan_commands = self._get_scan_commands(config.scan_type)
            
            # Create server scan request
            try:
                server_location = ServerNetworkLocation(hostname, port)
                scan_request = ServerScanRequest(
                    server_location=server_location,
                    scan_commands=scan_commands
                )
            except ServerHostnameCouldNotBeResolved:
                errors.append(f"Could not resolve hostname: {hostname}")
                return self._create_error_result(started_at, errors)
            
            # Perform scan
            loop = asyncio.get_event_loop()
            scan_results = await loop.run_in_executor(
                None,
                self._perform_sslyze_scan,
                scanner,
                [scan_request]
            )
            
            if scan_results:
                for server_scan_result in scan_results:
                    # Process certificate information
                    cert_vulns, cert_info = await self._analyze_certificate(server_scan_result)
                    vulnerabilities.extend(cert_vulns)
                    info['certificate'] = cert_info
                    statistics['certificate_issues'] = len(cert_vulns)
                    
                    # Process protocol support
                    protocol_vulns, protocol_info = self._analyze_protocols(server_scan_result)
                    vulnerabilities.extend(protocol_vulns)
                    info['protocols'] = protocol_info
                    statistics['protocols_tested'] = len(protocol_info)
                    
                    # Process cipher suites
                    cipher_vulns, cipher_info = self._analyze_cipher_suites(server_scan_result)
                    vulnerabilities.extend(cipher_vulns)
                    info['cipher_suites'] = cipher_info
                    statistics['cipher_suites_tested'] = sum(len(suites) for suites in cipher_info.values())
                    statistics['weak_ciphers_found'] = len(cipher_vulns)
                    
                    # Check for known vulnerabilities
                    vuln_results = self._check_known_vulnerabilities(server_scan_result)
                    for vuln_name, is_vulnerable in vuln_results.items():
                        info['vulnerabilities'][vuln_name] = is_vulnerable
                        if is_vulnerable:
                            statistics['vulnerabilities_found'] += 1
                            vuln_info = self.known_vulnerabilities[vuln_name]
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name=vuln_info['name'],
                                    description=vuln_info['description'],
                                    severity=vuln_info['severity'],
                                    confidence=0.95,
                                    cve_ids=[vuln_info.get('cve')] if vuln_info.get('cve') else [],
                                    affected_urls=[f"https://{hostname}:{port}"],
                                    remediation=self._get_vulnerability_remediation(vuln_name),
                                    references=self._get_vulnerability_references(vuln_name)
                                )
                            )
                    
                    # Check security headers and HSTS
                    header_vulns = await self._check_security_headers(hostname, port)
                    vulnerabilities.extend(header_vulns)
                    
                    # Check for other configuration issues
                    config_vulns = self._check_configuration_issues(server_scan_result)
                    vulnerabilities.extend(config_vulns)
            
        except Exception as e:
            errors.append(f"SSL scan failed: {str(e)}")
        
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
    
    def _parse_target(self, target: str) -> tuple:
        """Parse target URL to extract hostname and port."""
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        else:
            # Assume format is hostname:port or just hostname
            if ':' in target:
                hostname, port = target.split(':', 1)
                port = int(port)
            else:
                hostname = target
                port = 443
        
        return hostname, port
    
    def _get_scan_commands(self, scan_type: ScanType) -> set:
        """Get SSLyze scan commands based on scan type."""
        if scan_type == ScanType.PASSIVE:
            # Basic scan - certificate and protocol info only
            return {
                ScanCommandEnum.CERTIFICATE_INFO,
                ScanCommandEnum.SSL_2_0_CIPHER_SUITES,
                ScanCommandEnum.SSL_3_0_CIPHER_SUITES,
                ScanCommandEnum.TLS_1_0_CIPHER_SUITES,
                ScanCommandEnum.TLS_1_1_CIPHER_SUITES,
                ScanCommandEnum.TLS_1_2_CIPHER_SUITES,
                ScanCommandEnum.TLS_1_3_CIPHER_SUITES,
            }
        elif scan_type == ScanType.ACTIVE:
            # Standard scan - include vulnerability checks
            return {
                ScanCommandEnum.CERTIFICATE_INFO,
                ScanCommandEnum.SSL_2_0_CIPHER_SUITES,
                ScanCommandEnum.SSL_3_0_CIPHER_SUITES,
                ScanCommandEnum.TLS_1_0_CIPHER_SUITES,
                ScanCommandEnum.TLS_1_1_CIPHER_SUITES,
                ScanCommandEnum.TLS_1_2_CIPHER_SUITES,
                ScanCommandEnum.TLS_1_3_CIPHER_SUITES,
                ScanCommandEnum.HEARTBLEED,
                ScanCommandEnum.ROBOT,
                ScanCommandEnum.OPENSSL_CCS_INJECTION,
                ScanCommandEnum.SESSION_RENEGOTIATION,
                ScanCommandEnum.TLS_COMPRESSION,
                ScanCommandEnum.TLS_FALLBACK_SCSV,
                ScanCommandEnum.HTTP_HEADERS,
            }
        else:  # AGGRESSIVE
            # Full scan - all available checks
            return set(ScanCommandEnum)
    
    def _perform_sslyze_scan(self, scanner: Scanner, scan_requests: list) -> list:
        """Perform the actual SSLyze scan."""
        results = []
        for server_scan_result in scanner.get_results(scan_requests):
            results.append(server_scan_result)
        return results
    
    async def _analyze_certificate(self, scan_result) -> tuple:
        """Analyze SSL certificate for issues."""
        vulnerabilities = []
        cert_info = {}
        
        if hasattr(scan_result, 'certificate_info') and scan_result.certificate_info:
            cert_result = scan_result.certificate_info.result
            
            if cert_result:
                # Get certificate chain
                cert_chain = cert_result.certificate_deployments[0].received_certificate_chain if cert_result.certificate_deployments else []
                
                if cert_chain:
                    leaf_cert = cert_chain[0]
                    
                    # Extract certificate information
                    cert_info = {
                        'subject': leaf_cert.subject.rfc4514_string(),
                        'issuer': leaf_cert.issuer.rfc4514_string(),
                        'serial_number': str(leaf_cert.serial_number),
                        'not_before': leaf_cert.not_valid_before_utc.isoformat(),
                        'not_after': leaf_cert.not_valid_after_utc.isoformat(),
                        'signature_algorithm': leaf_cert.signature_algorithm_oid._name,
                        'key_size': leaf_cert.public_key().key_size if hasattr(leaf_cert.public_key(), 'key_size') else 'Unknown',
                    }
                    
                    # Check certificate validity
                    now = datetime.utcnow()
                    
                    # Check if expired
                    if now > leaf_cert.not_valid_after_utc:
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="Expired SSL Certificate",
                                description=f"SSL certificate expired on {leaf_cert.not_valid_after_utc}",
                                severity=SeverityLevel.CRITICAL,
                                confidence=1.0,
                                affected_urls=[str(scan_result.server_location)],
                                evidence=cert_info,
                                remediation="Renew the SSL certificate immediately.",
                            )
                        )
                    # Check if expiring soon
                    elif now + timedelta(days=30) > leaf_cert.not_valid_after_utc:
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="SSL Certificate Expiring Soon",
                                description=f"SSL certificate will expire on {leaf_cert.not_valid_after_utc}",
                                severity=SeverityLevel.MEDIUM,
                                confidence=1.0,
                                affected_urls=[str(scan_result.server_location)],
                                evidence=cert_info,
                                remediation="Plan to renew the SSL certificate before expiration.",
                            )
                        )
                    
                    # Check if not yet valid
                    if now < leaf_cert.not_valid_before_utc:
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="SSL Certificate Not Yet Valid",
                                description=f"SSL certificate is not valid until {leaf_cert.not_valid_before_utc}",
                                severity=SeverityLevel.HIGH,
                                confidence=1.0,
                                affected_urls=[str(scan_result.server_location)],
                                evidence=cert_info,
                                remediation="Check certificate configuration and system time.",
                            )
                        )
                    
                    # Check for self-signed certificate
                    if leaf_cert.issuer == leaf_cert.subject:
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="Self-Signed SSL Certificate",
                                description="Server is using a self-signed SSL certificate",
                                severity=SeverityLevel.MEDIUM,
                                confidence=1.0,
                                affected_urls=[str(scan_result.server_location)],
                                evidence=cert_info,
                                remediation="Use a certificate signed by a trusted Certificate Authority.",
                            )
                        )
                    
                    # Check for weak key size
                    key_size = cert_info.get('key_size', 0)
                    if isinstance(key_size, int):
                        if key_size < 2048:
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name="Weak SSL Certificate Key",
                                    description=f"SSL certificate uses weak key size ({key_size} bits)",
                                    severity=SeverityLevel.HIGH,
                                    confidence=1.0,
                                    affected_urls=[str(scan_result.server_location)],
                                    evidence={'key_size': key_size},
                                    remediation="Use at least 2048-bit RSA keys or 256-bit ECC keys.",
                                )
                            )
                    
                    # Check for weak signature algorithm
                    sig_algo = cert_info.get('signature_algorithm', '').lower()
                    if 'sha1' in sig_algo or 'md5' in sig_algo:
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="Weak Certificate Signature Algorithm",
                                description=f"Certificate uses weak signature algorithm: {sig_algo}",
                                severity=SeverityLevel.MEDIUM,
                                confidence=1.0,
                                affected_urls=[str(scan_result.server_location)],
                                evidence={'signature_algorithm': sig_algo},
                                remediation="Use SHA-256 or stronger signature algorithms.",
                            )
                        )
        
        return vulnerabilities, cert_info
    
    def _analyze_protocols(self, scan_result) -> tuple:
        """Analyze supported SSL/TLS protocols."""
        vulnerabilities = []
        protocol_info = {}
        
        protocol_scans = {
            'SSLv2': scan_result.ssl_2_0_cipher_suites,
            'SSLv3': scan_result.ssl_3_0_cipher_suites,
            'TLSv1.0': scan_result.tls_1_0_cipher_suites,
            'TLSv1.1': scan_result.tls_1_1_cipher_suites,
            'TLSv1.2': scan_result.tls_1_2_cipher_suites,
            'TLSv1.3': scan_result.tls_1_3_cipher_suites,
        }
        
        for protocol_name, protocol_result in protocol_scans.items():
            if protocol_result and hasattr(protocol_result, 'result') and protocol_result.result:
                result = protocol_result.result
                
                # Check if protocol is supported
                is_supported = len(result.accepted_cipher_suites) > 0 if hasattr(result, 'accepted_cipher_suites') else False
                
                protocol_info[protocol_name] = {
                    'supported': is_supported,
                    'cipher_count': len(result.accepted_cipher_suites) if hasattr(result, 'accepted_cipher_suites') else 0
                }
                
                # Check for insecure protocols
                if is_supported and protocol_name in self.insecure_protocols:
                    severity = SeverityLevel.CRITICAL if protocol_name in ['SSLv2', 'SSLv3'] else SeverityLevel.HIGH
                    
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name=f"Insecure Protocol {protocol_name} Supported",
                            description=f"Server supports {protocol_name} which has known security vulnerabilities",
                            severity=severity,
                            confidence=1.0,
                            affected_urls=[str(scan_result.server_location)],
                            evidence={'protocol': protocol_name, 'cipher_count': protocol_info[protocol_name]['cipher_count']},
                            remediation=f"Disable {protocol_name} and use TLS 1.2 or higher.",
                            cve_ids=['CVE-2014-3566'] if protocol_name == 'SSLv3' else [],
                        )
                    )
        
        # Check if only old protocols are supported
        modern_protocols = ['TLSv1.2', 'TLSv1.3']
        has_modern = any(protocol_info.get(p, {}).get('supported', False) for p in modern_protocols)
        
        if not has_modern:
            vulnerabilities.append(
                Vulnerability(
                    module=self.name,
                    name="No Modern TLS Protocol Support",
                    description="Server does not support TLS 1.2 or higher",
                    severity=SeverityLevel.HIGH,
                    confidence=1.0,
                    affected_urls=[str(scan_result.server_location)],
                    evidence=protocol_info,
                    remediation="Enable TLS 1.2 and TLS 1.3 support.",
                )
            )
        
        return vulnerabilities, protocol_info
    
    def _analyze_cipher_suites(self, scan_result) -> tuple:
        """Analyze cipher suites for weak configurations."""
        vulnerabilities = []
        cipher_info = {}
        
        protocol_scans = {
            'SSLv2': scan_result.ssl_2_0_cipher_suites,
            'SSLv3': scan_result.ssl_3_0_cipher_suites,
            'TLSv1.0': scan_result.tls_1_0_cipher_suites,
            'TLSv1.1': scan_result.tls_1_1_cipher_suites,
            'TLSv1.2': scan_result.tls_1_2_cipher_suites,
            'TLSv1.3': scan_result.tls_1_3_cipher_suites,
        }
        
        weak_ciphers_found = []
        
        for protocol_name, protocol_result in protocol_scans.items():
            if protocol_result and hasattr(protocol_result, 'result') and protocol_result.result:
                result = protocol_result.result
                
                if hasattr(result, 'accepted_cipher_suites'):
                    cipher_info[protocol_name] = []
                    
                    for cipher_suite in result.accepted_cipher_suites:
                        cipher_name = cipher_suite.cipher_suite.name if hasattr(cipher_suite, 'cipher_suite') else str(cipher_suite)
                        cipher_info[protocol_name].append(cipher_name)
                        
                        # Check for weak ciphers
                        for weak_cipher in self.weak_ciphers:
                            if weak_cipher in cipher_name.upper():
                                weak_ciphers_found.append({
                                    'protocol': protocol_name,
                                    'cipher': cipher_name,
                                    'weakness': weak_cipher
                                })
        
        # Report weak ciphers
        if weak_ciphers_found:
            for weak_cipher in weak_ciphers_found:
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name=f"Weak Cipher Suite: {weak_cipher['weakness']}",
                        description=f"Server supports weak cipher {weak_cipher['cipher']} in {weak_cipher['protocol']}",
                        severity=SeverityLevel.HIGH if weak_cipher['weakness'] in ['NULL', 'EXPORT', 'DES'] else SeverityLevel.MEDIUM,
                        confidence=1.0,
                        affected_urls=[str(scan_result.server_location)],
                        evidence=weak_cipher,
                        remediation="Disable weak cipher suites and use only strong, modern ciphers.",
                    )
                )
        
        # Check for cipher suite order (server preference)
        # This would require additional analysis of cipher suite preferences
        
        return vulnerabilities, cipher_info
    
    def _check_known_vulnerabilities(self, scan_result) -> Dict[str, bool]:
        """Check for known SSL/TLS vulnerabilities."""
        vuln_results = {}
        
        # Heartbleed
        if hasattr(scan_result, 'heartbleed') and scan_result.heartbleed:
            if hasattr(scan_result.heartbleed, 'result') and scan_result.heartbleed.result:
                vuln_results['heartbleed'] = scan_result.heartbleed.result.is_vulnerable_to_heartbleed
        
        # ROBOT
        if hasattr(scan_result, 'robot') and scan_result.robot:
            if hasattr(scan_result.robot, 'result') and scan_result.robot.result:
                vuln_results['robot'] = scan_result.robot.result.robot_result.value != 'NOT_VULNERABLE'
        
        # CCS Injection
        if hasattr(scan_result, 'openssl_ccs_injection') and scan_result.openssl_ccs_injection:
            if hasattr(scan_result.openssl_ccs_injection, 'result') and scan_result.openssl_ccs_injection.result:
                vuln_results['ccs_injection'] = scan_result.openssl_ccs_injection.result.is_vulnerable_to_ccs_injection
        
        # TLS Compression (CRIME)
        if hasattr(scan_result, 'tls_compression') and scan_result.tls_compression:
            if hasattr(scan_result.tls_compression, 'result') and scan_result.tls_compression.result:
                vuln_results['crime'] = scan_result.tls_compression.result.supports_compression
        
        # Check for POODLE (SSLv3 support)
        if hasattr(scan_result, 'ssl_3_0_cipher_suites') and scan_result.ssl_3_0_cipher_suites:
            if hasattr(scan_result.ssl_3_0_cipher_suites, 'result') and scan_result.ssl_3_0_cipher_suites.result:
                vuln_results['poodle'] = len(scan_result.ssl_3_0_cipher_suites.result.accepted_cipher_suites) > 0
        
        return vuln_results
    
    async def _check_security_headers(self, hostname: str, port: int) -> List[Vulnerability]:
        """Check for security-related HTTP headers."""
        vulnerabilities = []
        
        try:
            import httpx
            
            url = f"https://{hostname}:{port}"
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(url, follow_redirects=False)
                headers = response.headers
                
                # Check for HSTS
                if 'strict-transport-security' not in headers:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Missing HSTS Header",
                            description="HTTP Strict Transport Security (HSTS) header is not set",
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.9,
                            affected_urls=[url],
                            remediation="Add Strict-Transport-Security header with appropriate max-age directive.",
                            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"]
                        )
                    )
                else:
                    # Check HSTS configuration
                    hsts = headers['strict-transport-security']
                    if 'max-age=0' in hsts or 'max-age=1' in hsts:
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name="Weak HSTS Configuration",
                                description="HSTS max-age is too short",
                                severity=SeverityLevel.LOW,
                                confidence=0.9,
                                affected_urls=[url],
                                evidence={'hsts_header': hsts},
                                remediation="Set HSTS max-age to at least 31536000 (1 year).",
                            )
                        )
                
        except Exception:
            # If we can't check headers, it's not critical for SSL scan
            pass
        
        return vulnerabilities
    
    def _check_configuration_issues(self, scan_result) -> List[Vulnerability]:
        """Check for other SSL/TLS configuration issues."""
        vulnerabilities = []
        
        # Check for session renegotiation issues
        if hasattr(scan_result, 'session_renegotiation') and scan_result.session_renegotiation:
            if hasattr(scan_result.session_renegotiation, 'result') and scan_result.session_renegotiation.result:
                result = scan_result.session_renegotiation.result
                
                if result.is_vulnerable_to_client_renegotiation_dos:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Client-Initiated Renegotiation DoS",
                            description="Server is vulnerable to DoS via client-initiated renegotiation",
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.9,
                            affected_urls=[str(scan_result.server_location)],
                            remediation="Disable client-initiated renegotiation.",
                        )
                    )
        
        # Check for TLS Fallback SCSV support
        if hasattr(scan_result, 'tls_fallback_scsv') and scan_result.tls_fallback_scsv:
            if hasattr(scan_result.tls_fallback_scsv, 'result') and scan_result.tls_fallback_scsv.result:
                if not scan_result.tls_fallback_scsv.result.supports_fallback_scsv:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Missing TLS Fallback SCSV Support",
                            description="Server does not support TLS Fallback SCSV to prevent downgrade attacks",
                            severity=SeverityLevel.LOW,
                            confidence=0.8,
                            affected_urls=[str(scan_result.server_location)],
                            remediation="Enable TLS Fallback SCSV support.",
                            references=["https://tools.ietf.org/html/rfc7507"]
                        )
                    )
        
        return vulnerabilities
    
    def _get_vulnerability_remediation(self, vuln_name: str) -> str:
        """Get remediation advice for specific vulnerabilities."""
        remediations = {
            'heartbleed': "Update OpenSSL to version 1.0.1g or later. Revoke and reissue certificates. Reset user passwords.",
            'ccs_injection': "Update OpenSSL to version 1.0.1h or later.",
            'robot': "Disable RSA encryption cipher suites. Use ECDHE cipher suites instead.",
            'crime': "Disable TLS compression on the server.",
            'breach': "Disable HTTP compression for sensitive data. Use CSRF tokens.",
            'poodle': "Disable SSLv3 protocol completely.",
            'sweet32': "Disable 64-bit block cipher suites (3DES, Blowfish).",
            'drown': "Disable SSLv2 on all servers using the same certificate.",
            'logjam': "Use 2048-bit or larger DH parameters. Disable export cipher suites.",
            'freak': "Disable export-grade RSA cipher suites.",
        }
        return remediations.get(vuln_name, "Apply appropriate security patches and follow best practices.")
    
    def _get_vulnerability_references(self, vuln_name: str) -> List[str]:
        """Get references for specific vulnerabilities."""
        references = {
            'heartbleed': [
                "https://heartbleed.com/",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160"
            ],
            'ccs_injection': [
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224"
            ],
            'robot': [
                "https://robotattack.org/",
                "https://www.cve.org/CVERecord?id=CVE-2017-13099"
            ],
            'poodle': [
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566"
            ],
            'sweet32': [
                "https://sweet32.info/",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2183"
            ],
            'drown': [
                "https://drownattack.com/",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0800"
            ],
            'logjam': [
                "https://weakdh.org/",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000"
            ],
            'freak': [
                "https://freakattack.com/",
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0204"
            ],
        }
        return references.get(vuln_name, ["https://owasp.org/www-project-top-ten/"])
    
    def _create_error_result(self, started_at: datetime, errors: List[str]) -> ScanResult:
        """Create an error result when scan fails."""
        return ScanResult(
            module_name=self.name,
            success=False,
            started_at=started_at,
            completed_at=datetime.utcnow(),
            vulnerabilities=[],
            errors=errors,
            warnings=[],
            info={},
            statistics={}
        )
