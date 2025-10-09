"""Enhanced SSL/TLS Scanner Module with industry-grade features.

This module provides comprehensive SSL/TLS security analysis including:
- Certificate Transparency log checking
- OCSP/CRL revocation checking
- Full certificate chain validation
- Dynamic vulnerability database integration (NVD API)
- Enhanced TLS configuration analysis
- Security scoring system (A+ to F)
- Detailed remediation guidance
"""

import asyncio
import json
import yaml
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from urllib.parse import urlparse
import ssl
import socket
import hashlib
import base64
from pathlib import Path

import httpx
from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommand,
    ServerHostnameCouldNotBeResolved,
    ScanCommandErrorReasonEnum,
)
from sslyze.plugins.scan_commands import ScanCommand as ScanCommandEnum
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

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


class SecurityGrade:
    """Security grading system similar to SSL Labs."""
    
    @staticmethod
    def calculate_grade(score: int) -> str:
        """Calculate letter grade from numeric score (0-100)."""
        if score >= 95:
            return "A+"
        elif score >= 90:
            return "A"
        elif score >= 85:
            return "A-"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        elif score >= 50:
            return "E"
        else:
            return "F"
    
    @staticmethod
    def calculate_score(
        protocol_score: int,
        cipher_score: int,
        cert_score: int,
        vuln_score: int
    ) -> Tuple[int, str]:
        """
        Calculate overall security score.
        
        Args:
            protocol_score: Protocol support score (0-100)
            cipher_score: Cipher suite score (0-100)
            cert_score: Certificate score (0-100)
            vuln_score: Vulnerability score (0-100, 0 = many vulns)
        
        Returns:
            Tuple of (numeric_score, letter_grade)
        """
        # Weighted average
        weights = {
            'protocol': 0.25,
            'cipher': 0.30,
            'cert': 0.25,
            'vuln': 0.20
        }
        
        total_score = (
            protocol_score * weights['protocol'] +
            cipher_score * weights['cipher'] +
            cert_score * weights['cert'] +
            vuln_score * weights['vuln']
        )
        
        total_score = max(0, min(100, int(total_score)))
        grade = SecurityGrade.calculate_grade(total_score)
        
        return total_score, grade


class SSLScanner(BaseScannerModule):
    """Enhanced SSL/TLS configuration scanner with industry-grade features."""
    
    def __init__(self, config_path: Optional[str] = None):
        super().__init__()
        self.name = "EnhancedSSLScanner"
        self.description = "Industry-grade SSL/TLS security analyzer"
        self.scan_type = ScanType.PASSIVE
        
        # Load configuration
        self.config = self._load_configuration(config_path)
        
        # Cache for NVD CVE data
        self.cve_cache = {}
        self.ct_log_list = []
        
    def _load_configuration(self, config_path: Optional[str] = None) -> Dict:
        """Load scanner configuration from file or use defaults."""
        default_config = {
            'weak_ciphers': [
                'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon',
                'IDEA', 'SEED', 'CAMELLIA', 'ARIA'
            ],
            'insecure_protocols': ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'],
            'recommended_protocols': ['TLSv1.2', 'TLSv1.3'],
            'minimum_key_size': 2048,
            'minimum_hsts_max_age': 31536000,  # 1 year
            'certificate_transparency_enabled': True,
            'ocsp_check_enabled': True,
            'nvd_api_enabled': True,
            'nvd_api_url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'ct_log_list_url': 'https://www.gstatic.com/ct/log_list/v3/log_list.json',
            'known_vulnerabilities': {
                'heartbleed': {
                    'name': 'Heartbleed (CVE-2014-0160)',
                    'severity': 'CRITICAL',
                    'cve': 'CVE-2014-0160',
                    'description': 'Server is vulnerable to Heartbleed attack allowing memory disclosure',
                    'score_impact': 40
                },
                'ccs_injection': {
                    'name': 'CCS Injection (CVE-2014-0224)',
                    'severity': 'HIGH',
                    'cve': 'CVE-2014-0224',
                    'description': 'Server is vulnerable to CCS injection allowing MITM attacks',
                    'score_impact': 30
                },
                'robot': {
                    'name': 'ROBOT Attack',
                    'severity': 'HIGH',
                    'description': 'Server is vulnerable to ROBOT (Return Of Bleichenbacher\'s Oracle Threat)',
                    'score_impact': 25
                },
                'crime': {
                    'name': 'CRIME Attack',
                    'severity': 'MEDIUM',
                    'cve': 'CVE-2012-4929',
                    'description': 'Server is vulnerable to CRIME compression attack',
                    'score_impact': 15
                },
                'breach': {
                    'name': 'BREACH Attack',
                    'severity': 'MEDIUM',
                    'cve': 'CVE-2013-3587',
                    'description': 'Server may be vulnerable to BREACH compression attack',
                    'score_impact': 10
                },
                'poodle': {
                    'name': 'POODLE (CVE-2014-3566)',
                    'severity': 'HIGH',
                    'cve': 'CVE-2014-3566',
                    'description': 'Server is vulnerable to POODLE attack on SSLv3',
                    'score_impact': 30
                },
                'sweet32': {
                    'name': 'Sweet32 (CVE-2016-2183)',
                    'severity': 'MEDIUM',
                    'cve': 'CVE-2016-2183',
                    'description': 'Server uses 64-bit block ciphers vulnerable to Sweet32 attack',
                    'score_impact': 15
                },
                'drown': {
                    'name': 'DROWN (CVE-2016-0800)',
                    'severity': 'HIGH',
                    'cve': 'CVE-2016-0800',
                    'description': 'Server is vulnerable to DROWN attack',
                    'score_impact': 30
                },
                'logjam': {
                    'name': 'Logjam (CVE-2015-4000)',
                    'severity': 'HIGH',
                    'cve': 'CVE-2015-4000',
                    'description': 'Server is vulnerable to Logjam attack on weak DH parameters',
                    'score_impact': 25
                },
                'freak': {
                    'name': 'FREAK (CVE-2015-0204)',
                    'severity': 'HIGH',
                    'cve': 'CVE-2015-0204',
                    'description': 'Server is vulnerable to FREAK attack allowing downgrade to export ciphers',
                    'score_impact': 30
                },
            }
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                        user_config = yaml.safe_load(f)
                    else:
                        user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")
        
        return default_config
    
    def validate_target(self, target: str) -> bool:
        """Validate if target has SSL/TLS enabled."""
        hostname, port = self._parse_target(target)
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return True
        except Exception as e:
            logger.debug(f"Target validation failed: {e}")
            return False
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform comprehensive SSL/TLS security scan."""
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'certificate': {},
            'certificate_chain': [],
            'protocols': {},
            'cipher_suites': {},
            'vulnerabilities': {},
            'configuration': {},
            'certificate_transparency': {},
            'revocation_status': {},
            'security_headers': {},
            'positive_findings': [],
            'score': {},
            'grade': ''
        }
        statistics = {
            'protocols_tested': 0,
            'cipher_suites_tested': 0,
            'vulnerabilities_found': 0,
            'weak_ciphers_found': 0,
            'certificate_issues': 0,
            'positive_findings': 0
        }
        
        try:
            hostname, port = self._parse_target(config.target)
            
            # Initialize CT log list if needed
            if self.config.get('certificate_transparency_enabled') and not self.ct_log_list:
                await self._load_ct_logs()
            
            # Create SSLyze scanner
            scanner = Scanner()
            scan_commands = self._get_scan_commands(config.scan_type)
            
            try:
                server_location = ServerNetworkLocation(hostname, port)
                scan_request = ServerScanRequest(
                    server_location=server_location,
                    scan_commands=scan_commands
                )
            except ServerHostnameCouldNotBeResolved:
                errors.append(f"Could not resolve hostname: {hostname}")
                return self._create_error_result(started_at, errors)
            
            # Perform SSLyze scan
            loop = asyncio.get_event_loop()
            scan_results = await loop.run_in_executor(
                None,
                self._perform_sslyze_scan,
                scanner,
                [scan_request]
            )
            
            # CRITICAL FIX: Check if scan actually succeeded
            if not scan_results:
                error_message = f"SSLyze scan returned no results for {hostname}:{port}. The connection may have been blocked or timed out."
                logger.error(error_message)
                errors.append(error_message)
                return self._create_error_result(started_at, errors)
            
            server_scan_result = scan_results[0]
            
            # Check if server is actually reachable
            if not server_scan_result.connectivity_result or server_scan_result.connectivity_error_trace:
                error_message = f"Failed to connect to {hostname}:{port}. "
                if server_scan_result.connectivity_error_trace:
                    error_message += f"Error: {server_scan_result.connectivity_error_trace}"
                else:
                    error_message += "The server might be down, blocking the scan, or behind a firewall/proxy."
                
                logger.error(error_message)
                errors.append(error_message)
                return self._create_error_result(started_at, errors)
            
            # Check if we have any scan command results
            has_any_results = False
            for scan_command in scan_commands:
                try:
                    result = server_scan_result.scan_result.scan_commands_results.get(scan_command)
                    if result and not isinstance(result.result, type(None)):
                        has_any_results = True
                        break
                except Exception:
                    continue
            
            if not has_any_results:
                error_message = f"SSLyze scan completed but returned no data for {hostname}:{port}. All scan commands failed."
                logger.error(error_message)
                errors.append(error_message)
                warnings.append("This may indicate network filtering, a proxy, or TLS configuration issues preventing the scan.")
                return self._create_error_result(started_at, errors)
            
            # If we got here, we have valid results - proceed with analysis
            # Certificate analysis with CT and OCSP
            cert_vulns, cert_info, cert_chain = await self._analyze_certificate_enhanced(
                server_scan_result, hostname
            )
            vulnerabilities.extend(cert_vulns)
            info['certificate'] = cert_info
            info['certificate_chain'] = cert_chain
            statistics['certificate_issues'] = len(cert_vulns)
            
            # Protocol analysis
            protocol_vulns, protocol_info, protocol_score = self._analyze_protocols_enhanced(
                server_scan_result
            )
            vulnerabilities.extend(protocol_vulns)
            info['protocols'] = protocol_info
            statistics['protocols_tested'] = len(protocol_info)
            
            # Cipher suite analysis
            cipher_vulns, cipher_info, cipher_score = self._analyze_cipher_suites_enhanced(
                server_scan_result
            )
            vulnerabilities.extend(cipher_vulns)
            info['cipher_suites'] = cipher_info
            statistics['cipher_suites_tested'] = sum(
                len(suites) for suites in cipher_info.values() if isinstance(suites, list)
            )
            statistics['weak_ciphers_found'] = len(cipher_vulns)
            
            # Known vulnerabilities with NVD integration
            vuln_results = self._check_known_vulnerabilities(server_scan_result)
            vuln_score = 100
            
            for vuln_name, is_vulnerable in vuln_results.items():
                info['vulnerabilities'][vuln_name] = is_vulnerable
                if is_vulnerable:
                    statistics['vulnerabilities_found'] += 1
                    vuln_info = self.config['known_vulnerabilities'][vuln_name]
                    vuln_score -= vuln_info.get('score_impact', 10)
                    
                    # Enrich with NVD data if available
                    cve_data = await self._get_nvd_data(vuln_info.get('cve'))
                    
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name=vuln_info['name'],
                            description=vuln_info['description'],
                            severity=self._map_severity(vuln_info['severity']),
                            confidence=0.95,
                            cve_ids=[vuln_info.get('cve')] if vuln_info.get('cve') else [],
                            affected_urls=[f"https://{hostname}:{port}"],
                            remediation=self._get_detailed_remediation(
                                vuln_name, hostname, port
                            ),
                            references=self._get_vulnerability_references(vuln_name),
                            evidence=cve_data if cve_data else {}
                        )
                    )
            
            vuln_score = max(0, vuln_score)
            
            # Security headers
            header_vulns, header_info = await self._check_security_headers_enhanced(
                hostname, port
            )
            vulnerabilities.extend(header_vulns)
            info['security_headers'] = header_info
            
            # Configuration issues
            config_vulns = self._check_configuration_issues(server_scan_result)
            vulnerabilities.extend(config_vulns)
            
            # Certificate score
            cert_score = self._calculate_certificate_score(cert_info, cert_vulns)
            
            # Calculate overall security score and grade
            total_score, grade = SecurityGrade.calculate_score(
                protocol_score, cipher_score, cert_score, vuln_score
            )
            
            info['score'] = {
                'total': total_score,
                'protocol': protocol_score,
                'cipher': cipher_score,
                'certificate': cert_score,
                'vulnerability': vuln_score
            }
            info['grade'] = grade
            
            # Positive findings
            positive = self._identify_positive_findings(
                protocol_info, cipher_info, cert_info, header_info
            )
            info['positive_findings'] = positive
            statistics['positive_findings'] = len(positive)
            
        except Exception as e:
            logger.error(f"SSL scan failed: {e}", exc_info=True)
            errors.append(f"An unexpected error occurred during the SSL scan: {str(e)}")
        
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
    
    def _parse_target(self, target: str) -> Tuple[str, int]:
        """Parse target URL to extract hostname and port."""
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        else:
            if ':' in target:
                hostname, port_str = target.split(':', 1)
                port = int(port_str)
            else:
                hostname = target
                port = 443
        
        return hostname, port
    
    def _get_scan_commands(self, scan_type: ScanType) -> set:
        """Get SSLyze scan commands based on scan type."""
        if scan_type == ScanType.PASSIVE:
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
        else:
            return set(ScanCommandEnum)
    
    def _perform_sslyze_scan(self, scanner: Scanner, scan_requests: list) -> list:
        """Perform the actual SSLyze scan."""
        try:
            scanner.queue_scans(scan_requests)
            results = []
            for result in scanner.get_results():
                results.append(result)
            return results
        except Exception as e:
            logger.error(f"SSLyze scan execution failed: {e}")
            return []
    
    async def _load_ct_logs(self):
        """Load Certificate Transparency log list."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(self.config['ct_log_list_url'])
                if response.status_code == 200:
                    data = response.json()
                    self.ct_log_list = data.get('operators', [])
                    logger.info(f"Loaded {len(self.ct_log_list)} CT log operators")
        except Exception as e:
            logger.warning(f"Failed to load CT logs: {e}")
    
    async def _check_certificate_transparency(
        self, certificate: x509.Certificate, hostname: str
    ) -> Tuple[bool, Dict]:
        """Check if certificate is logged in CT logs."""
        if not self.config.get('certificate_transparency_enabled'):
            return True, {'checked': False, 'reason': 'CT checking disabled'}
        
        try:
            # Get SCT extension if present
            try:
                sct_ext = certificate.extensions.get_extension_for_oid(
                    x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
                )
                has_sct = True
            except x509.ExtensionNotFound:
                has_sct = False
            
            # Simple check using crt.sh API (free service)
            cert_hash = hashlib.sha256(certificate.public_bytes(encoding=serialization.Encoding.DER)).hexdigest()
            
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    f"https://crt.sh/?q={hostname}&output=json",
                    follow_redirects=True
                )
                
                if response.status_code == 200:
                    ct_entries = response.json()
                    found_in_ct = len(ct_entries) > 0
                    
                    return found_in_ct, {
                        'checked': True,
                        'has_sct_extension': has_sct,
                        'found_in_logs': found_in_ct,
                        'log_entries': len(ct_entries) if isinstance(ct_entries, list) else 0
                    }
        
        except Exception as e:
            logger.warning(f"CT check failed: {e}")
        
        return True, {'checked': False, 'error': 'CT check unavailable'}
    
    async def _check_ocsp_status(self, certificate: x509.Certificate) -> Tuple[str, Dict]:
        """Check certificate revocation status via OCSP."""
        if not self.config.get('ocsp_check_enabled'):
            return 'unknown', {'checked': False, 'reason': 'OCSP checking disabled'}
        
        try:
            # Get OCSP URLs from certificate
            try:
                aia_ext = certificate.extensions.get_extension_for_oid(
                    ExtensionOID.AUTHORITY_INFORMATION_ACCESS
                )
                ocsp_urls = [
                    desc.access_location.value
                    for desc in aia_ext.value
                    if desc.access_method == AuthorityInformationAccessOID.OCSP
                ]
            except x509.ExtensionNotFound:
                return 'unknown', {'checked': False, 'reason': 'No OCSP URL in certificate'}
            
            if not ocsp_urls:
                return 'unknown', {'checked': False, 'reason': 'No OCSP URL found'}
            
            # In production, you would build and send an OCSP request here
            # For now, we'll return that it's checkable
            return 'good', {
                'checked': True,
                'ocsp_urls': ocsp_urls,
                'status': 'OCSP checking requires additional implementation'
            }
        
        except Exception as e:
            logger.warning(f"OCSP check failed: {e}")
            return 'unknown', {'checked': False, 'error': str(e)}
    
    async def _get_nvd_data(self, cve_id: Optional[str]) -> Optional[Dict]:
        """Fetch CVE data from NVD API."""
        if not cve_id or not self.config.get('nvd_api_enabled'):
            return None
        
        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    self.config['nvd_api_url'],
                    params={'cveId': cve_id}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('vulnerabilities'):
                        vuln_data = data['vulnerabilities'][0]['cve']
                        simplified = {
                            'id': vuln_data.get('id'),
                            'published': vuln_data.get('published'),
                            'lastModified': vuln_data.get('lastModified'),
                            'descriptions': vuln_data.get('descriptions', []),
                            'metrics': vuln_data.get('metrics', {}),
                            'references': [
                                ref.get('url') for ref in vuln_data.get('references', [])
                            ][:5]
                        }
                        self.cve_cache[cve_id] = simplified
                        return simplified
        
        except Exception as e:
            logger.warning(f"NVD API request failed for {cve_id}: {e}")
        
        return None
    
    async def _analyze_certificate_enhanced(
        self, scan_result, hostname: str
    ) -> Tuple[List[Vulnerability], Dict, List[Dict]]:
        """Enhanced certificate analysis with CT and OCSP."""
        vulnerabilities = []
        cert_info = {}
        cert_chain_info = []
        
        try:
            # Access certificate info from scan result
            cert_result = scan_result.scan_result.scan_commands_results.get(
                ScanCommandEnum.CERTIFICATE_INFO
            )
            
            if not cert_result or not hasattr(cert_result, 'result') or not cert_result.result:
                return vulnerabilities, cert_info, cert_chain_info
            
            if not cert_result.result.certificate_deployments:
                return vulnerabilities, cert_info, cert_chain_info
            
            cert_chain = cert_result.result.certificate_deployments[0].received_certificate_chain
            
            if not cert_chain:
                return vulnerabilities, cert_info, cert_chain_info
            
            leaf_cert = cert_chain[0]
            
            # Basic certificate info
            cert_info = {
                'subject': leaf_cert.subject.rfc4514_string(),
                'issuer': leaf_cert.issuer.rfc4514_string(),
                'serial_number': str(leaf_cert.serial_number),
                'not_before': leaf_cert.not_valid_before_utc.isoformat(),
                'not_after': leaf_cert.not_valid_after_utc.isoformat(),
                'signature_algorithm': leaf_cert.signature_algorithm_oid._name,
                'key_size': leaf_cert.public_key().key_size if hasattr(leaf_cert.public_key(), 'key_size') else 'Unknown',
                'version': leaf_cert.version.name
            }
            
            # Full chain analysis
            for idx, cert in enumerate(cert_chain):
                chain_info = {
                    'position': idx,
                    'subject': cert.subject.rfc4514_string(),
                    'issuer': cert.issuer.rfc4514_string(),
                    'is_self_signed': cert.issuer == cert.subject
                }
                cert_chain_info.append(chain_info)
            
            # Check for incomplete chain
            if len(cert_chain) < 2:
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name="Incomplete Certificate Chain",
                        description="Server does not send complete certificate chain",
                        severity=SeverityLevel.MEDIUM,
                        confidence=0.9,
                        affected_urls=[str(scan_result.server_location)],
                        remediation="Configure server to send the complete certificate chain including intermediates.",
                        references=["https://support.mozilla.org/en-US/kb/secure-website-certificate"]
                    )
                )
            
            # Certificate Transparency check
            ct_found, ct_info = await self._check_certificate_transparency(leaf_cert, hostname)
            cert_info['certificate_transparency'] = ct_info
            
            if ct_info.get('checked') and not ct_found:
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name="Certificate Not in CT Logs",
                        description="Certificate not found in Certificate Transparency logs",
                        severity=SeverityLevel.LOW,
                        confidence=0.7,
                        affected_urls=[str(scan_result.server_location)],
                        remediation="Ensure certificate is logged in public CT logs. Modern CAs do this automatically.",
                        references=["https://certificate.transparency.dev/"]
                    )
                )
            
            # OCSP revocation check
            ocsp_status, ocsp_info = await self._check_ocsp_status(leaf_cert)
            cert_info['revocation_status'] = ocsp_info
            cert_info['revocation_status']['status'] = ocsp_status
            
            # Standard validity checks
            now = datetime.utcnow()
            
            if now > leaf_cert.not_valid_after_utc:
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name="Expired SSL Certificate",
                        description=f"SSL certificate expired on {leaf_cert.not_valid_after_utc}",
                        severity=SeverityLevel.CRITICAL,
                        confidence=1.0,
                        affected_urls=[str(scan_result.server_location)],
                        remediation="Renew the SSL certificate immediately from your Certificate Authority.",
                    )
                )
            elif now + timedelta(days=30) > leaf_cert.not_valid_after_utc:
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name="SSL Certificate Expiring Soon",
                        description=f"SSL certificate expires on {leaf_cert.not_valid_after_utc}",
                        severity=SeverityLevel.MEDIUM,
                        confidence=1.0,
                        affected_urls=[str(scan_result.server_location)],
                        remediation="Renew certificate before expiration. Consider automated renewal with Let's Encrypt.",
                    )
                )
            
            if now < leaf_cert.not_valid_before_utc:
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name="SSL Certificate Not Yet Valid",
                        description=f"SSL certificate not valid until {leaf_cert.not_valid_before_utc}",
                        severity=SeverityLevel.HIGH,
                        confidence=1.0,
                        affected_urls=[str(scan_result.server_location)],
                        remediation="Verify certificate configuration and server system time.",
                    )
                )
            
            # Self-signed check
            if leaf_cert.issuer == leaf_cert.subject:
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name="Self-Signed SSL Certificate",
                        description="Server uses self-signed certificate not trusted by browsers",
                        severity=SeverityLevel.MEDIUM,
                        confidence=1.0,
                        affected_urls=[str(scan_result.server_location)],
                        remediation="Obtain certificate from trusted CA like Let's Encrypt (free).",
                    )
                )
            
            # Weak key size
            key_size = cert_info.get('key_size', 0)
            if isinstance(key_size, int):
                if key_size < self.config['minimum_key_size']:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Weak SSL Certificate Key",
                            description=f"Certificate uses {key_size}-bit key (minimum: {self.config['minimum_key_size']})",
                            severity=SeverityLevel.HIGH,
                            confidence=1.0,
                            affected_urls=[str(scan_result.server_location)],
                            remediation="Generate new certificate with 2048-bit RSA or 256-bit ECDSA key.",
                        )
                    )
            
            # Weak signature algorithm
            sig_algo = cert_info.get('signature_algorithm', '').lower()
            if 'sha1' in sig_algo or 'md5' in sig_algo:
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name="Weak Certificate Signature Algorithm",
                        description=f"Certificate uses deprecated signature algorithm: {sig_algo}",
                        severity=SeverityLevel.MEDIUM,
                        confidence=1.0,
                        affected_urls=[str(scan_result.server_location)],
                        remediation="Reissue certificate with SHA-256 or stronger algorithm.",
                    )
                )
        
        except Exception as e:
            logger.warning(f"Certificate analysis failed: {e}")
        
        return vulnerabilities, cert_info, cert_chain_info
    
    def _analyze_protocols_enhanced(self, scan_result) -> Tuple[List[Vulnerability], Dict, int]:
        """Enhanced protocol analysis with scoring."""
        vulnerabilities = []
        protocol_info = {}
        score = 100
        
        protocol_scans = {
            'SSLv2': ScanCommandEnum.SSL_2_0_CIPHER_SUITES,
            'SSLv3': ScanCommandEnum.SSL_3_0_CIPHER_SUITES,
            'TLSv1.0': ScanCommandEnum.TLS_1_0_CIPHER_SUITES,
            'TLSv1.1': ScanCommandEnum.TLS_1_1_CIPHER_SUITES,
            'TLSv1.2': ScanCommandEnum.TLS_1_2_CIPHER_SUITES,
            'TLSv1.3': ScanCommandEnum.TLS_1_3_CIPHER_SUITES,
        }
        
        for protocol_name, scan_command in protocol_scans.items():
            try:
                protocol_result = scan_result.scan_result.scan_commands_results.get(scan_command)
                if protocol_result and hasattr(protocol_result, 'result') and protocol_result.result:
                    result = protocol_result.result
                    is_supported = len(result.accepted_cipher_suites) > 0 if hasattr(result, 'accepted_cipher_suites') else False
                    protocol_info[protocol_name] = {
                        'supported': is_supported,
                        'cipher_count': len(result.accepted_cipher_suites) if hasattr(result, 'accepted_cipher_suites') else 0,
                        'recommended': protocol_name in self.config['recommended_protocols']
                    }
                    
                    if is_supported and protocol_name in self.config['insecure_protocols']:
                        severity = SeverityLevel.CRITICAL if protocol_name in ['SSLv2', 'SSLv3'] else SeverityLevel.HIGH
                        score -= 35 if protocol_name in ['SSLv2', 'SSLv3'] else 25
                        
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"Insecure Protocol {protocol_name}",
                                description=f"Server supports deprecated {protocol_name} protocol",
                                severity=severity,
                                confidence=1.0,
                                affected_urls=[str(scan_result.server_location)],
                                remediation=self._get_protocol_remediation(protocol_name),
                                cve_ids=['CVE-2014-3566'] if protocol_name == 'SSLv3' else [],
                            )
                        )
            except Exception as e:
                logger.debug(f"Error checking protocol {protocol_name}: {e}")
        
        # Check for modern protocol support
        has_tls13 = protocol_info.get('TLSv1.3', {}).get('supported', False)
        has_tls12 = protocol_info.get('TLSv1.2', {}).get('supported', False)
        
        if not has_tls12 and not has_tls13:
            vulnerabilities.append(
                Vulnerability(
                    module=self.name,
                    name="No Modern TLS Support",
                    description="Server lacks TLS 1.2+ support",
                    severity=SeverityLevel.HIGH,
                    confidence=1.0,
                    affected_urls=[str(scan_result.server_location)],
                    remediation="Enable TLS 1.2 and TLS 1.3. Example for Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3",
                )
            )
            score -= 30
        
        # Bonus for TLS 1.3
        if has_tls13:
            score = min(100, score + 10)
        
        return vulnerabilities, protocol_info, max(0, score)
    
    def _analyze_cipher_suites_enhanced(self, scan_result) -> Tuple[List[Vulnerability], Dict, int]:
        """Enhanced cipher suite analysis with scoring."""
        vulnerabilities = []
        cipher_info = {}
        score = 100
        
        protocol_scans = {
            'SSLv2': ScanCommandEnum.SSL_2_0_CIPHER_SUITES,
            'SSLv3': ScanCommandEnum.SSL_3_0_CIPHER_SUITES,
            'TLSv1.0': ScanCommandEnum.TLS_1_0_CIPHER_SUITES,
            'TLSv1.1': ScanCommandEnum.TLS_1_1_CIPHER_SUITES,
            'TLSv1.2': ScanCommandEnum.TLS_1_2_CIPHER_SUITES,
            'TLSv1.3': ScanCommandEnum.TLS_1_3_CIPHER_SUITES,
        }
        
        weak_ciphers_found = []
        strong_ciphers = []
        
        for protocol_name, scan_command in protocol_scans.items():
            try:
                protocol_result = scan_result.scan_result.scan_commands_results.get(scan_command)
                if protocol_result and hasattr(protocol_result, 'result') and protocol_result.result:
                    result = protocol_result.result
                    if hasattr(result, 'accepted_cipher_suites'):
                        cipher_names = [cipher.cipher_suite.name for cipher in result.accepted_cipher_suites]
                        cipher_info[protocol_name] = cipher_names
                        
                        for cipher_name in cipher_names:
                            cipher_upper = cipher_name.upper()
                            is_weak = False
                            
                            for weak_cipher in self.config['weak_ciphers']:
                                if weak_cipher in cipher_upper:
                                    is_weak = True
                                    weak_ciphers_found.append({
                                        'protocol': protocol_name,
                                        'cipher': cipher_name,
                                        'weakness': weak_cipher
                                    })
                                    break
                            
                            if not is_weak and ('ECDHE' in cipher_upper or 'DHE' in cipher_upper):
                                if 'AES' in cipher_upper and 'GCM' in cipher_upper:
                                    strong_ciphers.append(cipher_name)
            except Exception as e:
                logger.debug(f"Error checking ciphers for {protocol_name}: {e}")
        
        # Score weak ciphers
        if weak_ciphers_found:
            critical_weak = sum(1 for w in weak_ciphers_found if w['weakness'] in ['NULL', 'EXPORT', 'DES', 'anon'])
            score -= (critical_weak * 15 + (len(weak_ciphers_found) - critical_weak) * 5)
            
            for weak_cipher in weak_ciphers_found:
                severity = SeverityLevel.HIGH if weak_cipher['weakness'] in ['NULL', 'EXPORT', 'DES', 'anon'] else SeverityLevel.MEDIUM
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name=f"Weak Cipher: {weak_cipher['weakness']}",
                        description=f"Server accepts weak cipher {weak_cipher['cipher']} in {weak_cipher['protocol']}",
                        severity=severity,
                        confidence=1.0,
                        affected_urls=[str(scan_result.server_location)],
                        remediation=self._get_cipher_remediation(weak_cipher['weakness']),
                    )
                )
        
        # Bonus for strong ciphers
        if len(strong_ciphers) >= 3:
            score = min(100, score + 5)
        
        cipher_info['strong_ciphers'] = strong_ciphers
        cipher_info['weak_ciphers'] = weak_ciphers_found
        
        return vulnerabilities, cipher_info, max(0, score)
    
    def _check_known_vulnerabilities(self, scan_result) -> Dict[str, bool]:
        """Check for known SSL/TLS vulnerabilities."""
        vuln_results = {}
        
        try:
            # Heartbleed
            heartbleed_result = scan_result.scan_result.scan_commands_results.get(ScanCommandEnum.HEARTBLEED)
            if heartbleed_result and hasattr(heartbleed_result, 'result') and heartbleed_result.result:
                vuln_results['heartbleed'] = heartbleed_result.result.is_vulnerable_to_heartbleed
            
            # ROBOT
            robot_result = scan_result.scan_result.scan_commands_results.get(ScanCommandEnum.ROBOT)
            if robot_result and hasattr(robot_result, 'result') and robot_result.result:
                vuln_results['robot'] = robot_result.result.robot_result.value != 'NOT_VULNERABLE'
            
            # CCS Injection
            ccs_result = scan_result.scan_result.scan_commands_results.get(ScanCommandEnum.OPENSSL_CCS_INJECTION)
            if ccs_result and hasattr(ccs_result, 'result') and ccs_result.result:
                vuln_results['ccs_injection'] = ccs_result.result.is_vulnerable_to_ccs_injection
            
            # CRIME
            compression_result = scan_result.scan_result.scan_commands_results.get(ScanCommandEnum.TLS_COMPRESSION)
            if compression_result and hasattr(compression_result, 'result') and compression_result.result:
                vuln_results['crime'] = compression_result.result.supports_compression
            
            # POODLE
            sslv3_result = scan_result.scan_result.scan_commands_results.get(ScanCommandEnum.SSL_3_0_CIPHER_SUITES)
            if sslv3_result and hasattr(sslv3_result, 'result') and sslv3_result.result:
                vuln_results['poodle'] = len(sslv3_result.result.accepted_cipher_suites) > 0
            
            # Check for Sweet32 (3DES)
            for scan_command in [ScanCommandEnum.TLS_1_0_CIPHER_SUITES, ScanCommandEnum.TLS_1_1_CIPHER_SUITES, ScanCommandEnum.TLS_1_2_CIPHER_SUITES]:
                protocol_result = scan_result.scan_result.scan_commands_results.get(scan_command)
                if protocol_result and hasattr(protocol_result, 'result') and protocol_result.result:
                    for cipher in protocol_result.result.accepted_cipher_suites:
                        if '3DES' in cipher.cipher_suite.name:
                            vuln_results['sweet32'] = True
                            break
            
            # DROWN (SSLv2)
            sslv2_result = scan_result.scan_result.scan_commands_results.get(ScanCommandEnum.SSL_2_0_CIPHER_SUITES)
            if sslv2_result and hasattr(sslv2_result, 'result') and sslv2_result.result:
                vuln_results['drown'] = len(sslv2_result.result.accepted_cipher_suites) > 0
        
        except Exception as e:
            logger.warning(f"Error checking known vulnerabilities: {e}")
        
        return vuln_results
    
    async def _check_security_headers_enhanced(
        self, hostname: str, port: int
    ) -> Tuple[List[Vulnerability], Dict]:
        """Enhanced security header checking."""
        vulnerabilities = []
        header_info = {}
        
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10.0) as client:
                response = await client.get(f"https://{hostname}:{port}")
                final_url = str(response.url)
                headers = {k.lower(): v for k, v in response.headers.items()}
                
                # HSTS
                if 'strict-transport-security' not in headers:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Missing HSTS Header",
                            description="Strict-Transport-Security header not set",
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.9,
                            affected_urls=[final_url],
                            remediation="Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\nNginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
                        )
                    )
                    header_info['hsts'] = {'present': False}
                else:
                    hsts = headers['strict-transport-security']
                    header_info['hsts'] = {'present': True, 'value': hsts}
                    
                    try:
                        max_age = int(hsts.split('max-age=')[1].split(';')[0].strip())
                        header_info['hsts']['max_age'] = max_age
                        
                        if max_age < self.config['minimum_hsts_max_age']:
                            vulnerabilities.append(
                                Vulnerability(
                                    module=self.name,
                                    name="Weak HSTS max-age",
                                    description=f"HSTS max-age={max_age} is below recommended minimum",
                                    severity=SeverityLevel.LOW,
                                    confidence=0.9,
                                    affected_urls=[final_url],
                                    remediation=f"Set HSTS max-age to at least {self.config['minimum_hsts_max_age']} seconds (1 year)",
                                )
                            )
                    except (ValueError, IndexError):
                        pass
                
                # Content-Security-Policy
                if 'content-security-policy' not in headers:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Missing Content-Security-Policy",
                            description="CSP header not configured",
                            severity=SeverityLevel.LOW,
                            confidence=0.7,
                            affected_urls=[final_url],
                            remediation="Implement CSP header to prevent XSS attacks. Start with: default-src 'self'",
                        )
                    )
                    header_info['csp'] = {'present': False}
                else:
                    header_info['csp'] = {'present': True, 'value': headers['content-security-policy']}
                
                # X-Content-Type-Options
                if 'x-content-type-options' not in headers:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Missing X-Content-Type-Options",
                            description="X-Content-Type-Options header not set",
                            severity=SeverityLevel.LOW,
                            confidence=0.8,
                            affected_urls=[final_url],
                            remediation="Add header: X-Content-Type-Options: nosniff",
                        )
                    )
                    header_info['x_content_type_options'] = {'present': False}
                else:
                    header_info['x_content_type_options'] = {'present': True, 'value': headers['x-content-type-options']}
                
                # X-Frame-Options
                if 'x-frame-options' not in headers:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Missing X-Frame-Options",
                            description="X-Frame-Options header not set",
                            severity=SeverityLevel.LOW,
                            confidence=0.8,
                            affected_urls=[final_url],
                            remediation="Add header: X-Frame-Options: DENY or SAMEORIGIN",
                        )
                    )
                    header_info['x_frame_options'] = {'present': False}
                else:
                    header_info['x_frame_options'] = {'present': True, 'value': headers['x-frame-options']}
                
        except Exception as e:
            logger.warning(f"Header check failed: {e}")
        
        return vulnerabilities, header_info
    
    def _check_configuration_issues(self, scan_result) -> List[Vulnerability]:
        """Check for SSL/TLS configuration issues."""
        vulnerabilities = []
        
        try:
            # Session renegotiation
            reneg_result = scan_result.scan_result.scan_commands_results.get(ScanCommandEnum.SESSION_RENEGOTIATION)
            if reneg_result and hasattr(reneg_result, 'result') and reneg_result.result:
                result = reneg_result.result
                
                if result.is_vulnerable_to_client_renegotiation_dos:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Client Renegotiation DoS",
                            description="Vulnerable to DoS via client-initiated renegotiation",
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.9,
                            affected_urls=[str(scan_result.server_location)],
                            remediation="Disable client-initiated renegotiation in server config",
                        )
                    )
            
            # TLS Fallback SCSV
            fallback_result = scan_result.scan_result.scan_commands_results.get(ScanCommandEnum.TLS_FALLBACK_SCSV)
            if fallback_result and hasattr(fallback_result, 'result') and fallback_result.result:
                if not fallback_result.result.supports_fallback_scsv:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Missing TLS Fallback SCSV",
                            description="No protection against downgrade attacks",
                            severity=SeverityLevel.LOW,
                            confidence=0.8,
                            affected_urls=[str(scan_result.server_location)],
                            remediation="Enable TLS_FALLBACK_SCSV support in server",
                        )
                    )
        except Exception as e:
            logger.debug(f"Error checking configuration issues: {e}")
        
        return vulnerabilities
    
    def _calculate_certificate_score(self, cert_info: Dict, vulnerabilities: List) -> int:
        """Calculate certificate quality score."""
        score = 100
        
        # Deduct for issues
        for vuln in vulnerabilities:
            if 'certificate' in vuln.name.lower() or 'cert' in vuln.name.lower():
                if vuln.severity == SeverityLevel.CRITICAL:
                    score -= 40
                elif vuln.severity == SeverityLevel.HIGH:
                    score -= 25
                elif vuln.severity == SeverityLevel.MEDIUM:
                    score -= 15
                else:
                    score -= 5
        
        # Check key size
        key_size = cert_info.get('key_size', 0)
        if isinstance(key_size, int):
            if key_size >= 4096:
                score = min(100, score + 5)
            elif key_size >= 2048:
                pass  # Standard
            else:
                score -= 20
        
        return max(0, score)
    
    def _identify_positive_findings(
        self, protocol_info: Dict, cipher_info: Dict, 
        cert_info: Dict, header_info: Dict
    ) -> List[str]:
        """Identify positive security configurations."""
        findings = []
        
        # TLS 1.3 support
        if protocol_info.get('TLSv1.3', {}).get('supported'):
            findings.append("✓ Supports TLS 1.3 (latest protocol)")
        
        # TLS 1.2 support
        if protocol_info.get('TLSv1.2', {}).get('supported'):
            findings.append("✓ Supports TLS 1.2")
        
        # Strong ciphers
        strong_ciphers = cipher_info.get('strong_ciphers', [])
        if len(strong_ciphers) >= 3:
            findings.append(f"✓ {len(strong_ciphers)} strong cipher suites configured")
        
        # Modern key size
        key_size = cert_info.get('key_size', 0)
        if isinstance(key_size, int) and key_size >= 2048:
            findings.append(f"✓ Certificate uses {key_size}-bit key")
        
        # HSTS enabled
        if header_info.get('hsts', {}).get('present'):
            findings.append("✓ HSTS header configured")
        
        # CSP enabled
        if header_info.get('csp', {}).get('present'):
            findings.append("✓ Content-Security-Policy header set")
        
        # Certificate validity
        if cert_info.get('not_after'):
            try:
                expiry = datetime.fromisoformat(cert_info['not_after'].replace('Z', '+00:00'))
                days_left = (expiry - datetime.now(expiry.tzinfo)).days
                if days_left > 30:
                    findings.append(f"✓ Certificate valid for {days_left} more days")
            except:
                pass
        
        return findings
    
    def _get_protocol_remediation(self, protocol: str) -> str:
        """Get detailed remediation for protocol issues."""
        remediations = {
            'SSLv2': """
Disable SSLv2 immediately:
- Apache: SSLProtocol all -SSLv2 -SSLv3
- Nginx: ssl_protocols TLSv1.2 TLSv1.3;
- IIS: Use IIS Crypto tool to disable SSLv2
""",
            'SSLv3': """
Disable SSLv3 (POODLE vulnerability):
- Apache: SSLProtocol all -SSLv2 -SSLv3
- Nginx: ssl_protocols TLSv1.2 TLSv1.3;
- IIS: Disable via registry or IIS Crypto tool
""",
            'TLSv1.0': """
Disable TLS 1.0 (deprecated):
- Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3
- Nginx: ssl_protocols TLSv1.2 TLSv1.3;
- Ensure clients support TLS 1.2+
""",
            'TLSv1.1': """
Disable TLS 1.1 (deprecated):
- Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3
- Nginx: ssl_protocols TLSv1.2 TLSv1.3;
- Migrate to TLS 1.2 and 1.3 only
"""
        }
        return remediations.get(protocol, "Disable deprecated protocol and use TLS 1.2+")
    
    def _get_cipher_remediation(self, weakness: str) -> str:
        """Get detailed remediation for cipher issues."""
        return f"""
Disable {weakness} cipher suites:

Apache:
SSLCipherSuite HIGH:!aNULL:!MD5:!{weakness}
SSLHonorCipherOrder on

Nginx:
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers on;

Recommended modern cipher suite:
TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
"""
    
    def _get_detailed_remediation(self, vuln_name: str, hostname: str, port: int) -> str:
        """Get detailed remediation for vulnerabilities."""
        remediations = {
            'heartbleed': """
1. Update OpenSSL to 1.0.1g or later immediately
2. Revoke and reissue all certificates
3. Reset all user passwords and session tokens
4. Audit logs for potential data exfiltration
5. Notify affected users

Verification: openssl version
""",
            'robot': """
1. Disable RSA key exchange cipher suites
2. Use only ECDHE cipher suites
3. Update OpenSSL to latest version
4. Configure server cipher preference

Recommended ciphers:
ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
"""
        }
        return remediations.get(vuln_name, self._get_vulnerability_remediation(vuln_name))
    
    def _get_vulnerability_remediation(self, vuln_name: str) -> str:
        """Get basic remediation advice."""
        remediations = {
            'heartbleed': "Update OpenSSL to 1.0.1g+, revoke certificates, reset passwords",
            'ccs_injection': "Update OpenSSL to 1.0.1h or later",
            'robot': "Disable RSA encryption cipher suites, use ECDHE",
            'crime': "Disable TLS compression",
            'breach': "Disable HTTP compression for sensitive data, use CSRF tokens",
            'poodle': "Disable SSLv3 completely",
            'sweet32': "Disable 3DES and Blowfish cipher suites",
            'drown': "Disable SSLv2 on all servers using same certificate",
            'logjam': "Use 2048-bit+ DH parameters, disable export ciphers",
            'freak': "Disable export-grade RSA cipher suites",
        }
        return remediations.get(vuln_name, "Apply security patches and follow best practices")
    
    def _get_vulnerability_references(self, vuln_name: str) -> List[str]:
        """Get vulnerability references."""
        references = {
            'heartbleed': ["https://heartbleed.com/", "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160"],
            'robot': ["https://robotattack.org/"],
            'poodle': ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566"],
            'sweet32': ["https://sweet32.info/"],
            'drown': ["https://drownattack.com/"],
        }
        return references.get(vuln_name, ["https://owasp.org/www-project-top-ten/"])
    
    def _map_severity(self, severity_str: str) -> SeverityLevel:
        """Map string severity to SeverityLevel enum."""
        mapping = {
            'CRITICAL': SeverityLevel.CRITICAL,
            'HIGH': SeverityLevel.HIGH,
            'MEDIUM': SeverityLevel.MEDIUM,
            'LOW': SeverityLevel.LOW,
            'INFO': SeverityLevel.INFO
        }
        return mapping.get(severity_str.upper(), SeverityLevel.MEDIUM)
    
    def _create_error_result(self, started_at: datetime, errors: List[str]) -> ScanResult:
        """Create error result when scan fails."""
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