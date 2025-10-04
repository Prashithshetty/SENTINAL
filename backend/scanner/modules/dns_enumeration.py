"""DNS Enumeration and OSINT Module using dnspython and various OSINT techniques."""

import dns.resolver
import dns.zone
import dns.query
import dns.reversename
import asyncio
import socket
import whois
import requests
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
import re
from urllib.parse import urlparse
from ..base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)

class DNSEnumerationModule(BaseScannerModule):
    """DNS enumeration and OSINT footprinting module."""
    
    def __init__(self):
        super().__init__()
        self.name = "DNSEnumeration"
        self.description = "Performs DNS enumeration and OSINT footprinting"
        self.scan_type = ScanType.PASSIVE
        
        # DNS record types to query
        self.record_types = [
            'A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 
            'CNAME', 'PTR', 'SRV', 'CAA', 'DMARC'
        ]
        
        # Common subdomains to check
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'administrator', 'api', 'app',
            'blog', 'dev', 'staging', 'test', 'demo', 'portal', 'secure',
            'vpn', 'remote', 'webmail', 'ns', 'ns1', 'ns2', 'mx', 'mx1',
            'smtp', 'pop', 'imap', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
            'mobile', 'm', 'help', 'support', 'kb', 'knowledgebase', 'wiki',
            'git', 'gitlab', 'github', 'bitbucket', 'jira', 'confluence',
            'jenkins', 'ci', 'cd', 'deploy', 'docker', 'k8s', 'kubernetes',
            'grafana', 'prometheus', 'elastic', 'elasticsearch', 'kibana',
            'logstash', 'metrics', 'monitor', 'monitoring', 'nagios', 'zabbix',
            'db', 'database', 'mysql', 'postgres', 'postgresql', 'mongo', 'mongodb',
            'redis', 'memcached', 'rabbitmq', 'kafka', 'zookeeper',
            'phpmyadmin', 'pma', 'dbadmin', 'sqladmin', 'wp-admin', 'wordpress',
            'shop', 'store', 'ecommerce', 'checkout', 'payment', 'pay',
            'owa', 'outlook', 'exchange', 'o365', 'microsoft', 'teams',
            'slack', 'discord', 'chat', 'im', 'messaging',
            'cdn', 'static', 'assets', 'images', 'img', 'media', 'upload',
            'downloads', 'files', 'docs', 'documents', 'share', 'sharing',
            'backup', 'bak', 'old', 'new', 'temp', 'tmp', 'cache',
            'alpha', 'beta', 'gamma', 'delta', 'v1', 'v2', 'v3',
            'api-v1', 'api-v2', 'api-v3', 'rest', 'restapi', 'graphql',
            'internal', 'external', 'extranet', 'intranet', 'localhost',
            'proxy', 'gateway', 'firewall', 'waf', 'lb', 'loadbalancer',
            'sso', 'auth', 'authentication', 'oauth', 'oauth2', 'saml',
            'ldap', 'ad', 'activedirectory', 'radius', 'nps',
        ]
        
        # OSINT APIs (when API keys are available)
        self.osint_sources = {
            'crtsh': 'https://crt.sh/?q={domain}&output=json',
            'threatcrowd': 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}',
            'hackertarget': 'https://api.hackertarget.com/hostsearch/?q={domain}',
            'urlscan': 'https://urlscan.io/api/v1/search/?q=domain:{domain}',
            'wayback': 'http://web.archive.org/cdx/search/cdx?url={domain}&output=json&fl=original&collapse=urlkey',
        }
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is a valid domain."""
        # Extract domain from URL if needed
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            target = parsed.hostname
        
        # Basic domain validation
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        return bool(domain_pattern.match(target)) if target else False
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Perform DNS enumeration and OSINT gathering."""
        started_at = datetime.utcnow()
        vulnerabilities = []
        errors = []
        warnings = []
        info = {
            'dns_records': {},
            'subdomains': [],
            'whois_info': {},
            'osint_data': {},
        }
        statistics = {
            'dns_records_found': 0,
            'subdomains_discovered': 0,
            'zone_transfer_attempted': False,
            'zone_transfer_successful': False,
            'osint_sources_queried': 0,
        }
        
        try:
            # Extract domain from URL if needed
            domain = config.target
            if domain.startswith(('http://', 'https://')):
                parsed = urlparse(domain)
                domain = parsed.hostname
            
            # 1. DNS Record Enumeration
            dns_records = await self._enumerate_dns_records(domain)
            info['dns_records'] = dns_records
            statistics['dns_records_found'] = sum(len(records) for records in dns_records.values())
            
            # Check for DNS misconfigurations
            dns_vulns = self._check_dns_vulnerabilities(dns_records, domain)
            vulnerabilities.extend(dns_vulns)
            
            # 2. Subdomain Enumeration
            if config.scan_type in [ScanType.ACTIVE, ScanType.AGGRESSIVE]:
                subdomains = await self._enumerate_subdomains(domain)
                info['subdomains'] = list(subdomains)
                statistics['subdomains_discovered'] = len(subdomains)
                
                # Check for subdomain takeover vulnerabilities
                takeover_vulns = await self._check_subdomain_takeover(subdomains)
                vulnerabilities.extend(takeover_vulns)
            
            # 3. Zone Transfer Attempt
            zone_transfer_result = await self._attempt_zone_transfer(domain)
            statistics['zone_transfer_attempted'] = True
            if zone_transfer_result:
                statistics['zone_transfer_successful'] = True
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name="DNS Zone Transfer Enabled",
                        description=f"DNS zone transfer is enabled on {domain}. This exposes all DNS records to unauthorized parties.",
                        severity=SeverityLevel.CRITICAL,
                        confidence=1.0,
                        affected_urls=[domain],
                        evidence={'zone_data': zone_transfer_result[:1000]},  # Truncate for storage
                        remediation="Restrict zone transfers to authorized secondary DNS servers only.",
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/DNS_zone_transfer",
                            "https://cwe.mitre.org/data/definitions/200.html"
                        ],
                        cwe_ids=["CWE-200"]
                    )
                )
            
            # 4. WHOIS Information
            whois_info = await self._get_whois_info(domain)
            info['whois_info'] = whois_info
            
            # Check for WHOIS privacy issues
            if whois_info and not whois_info.get('privacy_protected'):
                warnings.append("WHOIS information is publicly exposed without privacy protection")
            
            # 5. OSINT Data Collection
            if config.scan_type != ScanType.PASSIVE:
                osint_data = await self._gather_osint_data(domain)
                info['osint_data'] = osint_data
                statistics['osint_sources_queried'] = len(osint_data)
                
                # Check for information disclosure in OSINT
                osint_vulns = self._analyze_osint_data(osint_data, domain)
                vulnerabilities.extend(osint_vulns)
            
            # 6. Email Harvesting from DNS and OSINT
            emails = self._extract_emails(dns_records, whois_info, osint_data if config.scan_type != ScanType.PASSIVE else {})
            if emails:
                info['discovered_emails'] = list(emails)
                if len(emails) > 5:
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="Email Address Disclosure",
                            description=f"Multiple email addresses ({len(emails)}) discovered through DNS and OSINT enumeration.",
                            severity=SeverityLevel.LOW,
                            confidence=0.9,
                            affected_urls=[domain],
                            evidence={'email_count': len(emails), 'sample_emails': list(emails)[:5]},
                            remediation="Consider using role-based email addresses and privacy protection services.",
                        )
                    )
            
        except Exception as e:
            errors.append(f"DNS enumeration failed: {str(e)}")
        
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
    
    async def _enumerate_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Enumerate various DNS record types."""
        records = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10
        
        for record_type in self.record_types:
            try:
                if record_type == 'DMARC':
                    # DMARC is a TXT record at _dmarc subdomain
                    answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
                else:
                    answers = resolver.resolve(domain, record_type)
                
                records[record_type] = []
                for rdata in answers:
                    records[record_type].append(str(rdata))
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
                continue
        
        return records
    
    def _check_dns_vulnerabilities(self, dns_records: Dict, domain: str) -> List[Vulnerability]:
        """Check for DNS-related vulnerabilities."""
        vulnerabilities = []
        
        # Check for missing SPF record
        txt_records = dns_records.get('TXT', [])
        has_spf = any('v=spf1' in record for record in txt_records)
        if not has_spf and dns_records.get('MX'):
            vulnerabilities.append(
                Vulnerability(
                    module=self.name,
                    name="Missing SPF Record",
                    description=f"Domain {domain} has MX records but no SPF record, allowing email spoofing.",
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.9,
                    affected_urls=[domain],
                    evidence={'mx_records': dns_records.get('MX', [])},
                    remediation="Add an SPF TXT record to specify authorized mail servers.",
                    references=["https://tools.ietf.org/html/rfc7208"],
                )
            )
        
        # Check for missing DMARC record
        dmarc_records = dns_records.get('DMARC', [])
        if not dmarc_records and dns_records.get('MX'):
            vulnerabilities.append(
                Vulnerability(
                    module=self.name,
                    name="Missing DMARC Record",
                    description=f"Domain {domain} lacks DMARC policy, reducing email security.",
                    severity=SeverityLevel.LOW,
                    confidence=0.9,
                    affected_urls=[domain],
                    remediation="Implement DMARC policy to prevent email spoofing and phishing.",
                    references=["https://tools.ietf.org/html/rfc7489"],
                )
            )
        
        # Check for wildcard DNS
        try:
            random_subdomain = f"random-{datetime.now().timestamp()}.{domain}"
            socket.gethostbyname(random_subdomain)
            vulnerabilities.append(
                Vulnerability(
                    module=self.name,
                    name="Wildcard DNS Enabled",
                    description=f"Domain {domain} has wildcard DNS enabled, which may lead to subdomain takeover.",
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.8,
                    affected_urls=[domain],
                    remediation="Review wildcard DNS configuration and disable if not necessary.",
                )
            )
        except socket.gaierror:
            pass
        
        # Check for DNS server version disclosure
        if dns_records.get('TXT'):
            for txt in dns_records['TXT']:
                if 'version' in txt.lower() or 'bind' in txt.lower():
                    vulnerabilities.append(
                        Vulnerability(
                            module=self.name,
                            name="DNS Server Version Disclosure",
                            description="DNS server version information is exposed in TXT records.",
                            severity=SeverityLevel.LOW,
                            confidence=0.7,
                            affected_urls=[domain],
                            evidence={'txt_record': txt},
                            remediation="Remove version information from DNS TXT records.",
                        )
                    )
        
        return vulnerabilities
    
    async def _enumerate_subdomains(self, domain: str) -> Set[str]:
        """Enumerate subdomains through various methods."""
        subdomains = set()
        
        # 1. Brute force common subdomains
        tasks = []
        for subdomain in self.common_subdomains:
            tasks.append(self._check_subdomain(f"{subdomain}.{domain}"))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if result and not isinstance(result, Exception):
                subdomains.add(result)
        
        # 2. Certificate Transparency logs
        ct_subdomains = await self._query_certificate_transparency(domain)
        subdomains.update(ct_subdomains)
        
        return subdomains
    
    async def _check_subdomain(self, subdomain: str) -> Optional[str]:
        """Check if a subdomain exists."""
        try:
            socket.gethostbyname(subdomain)
            return subdomain
        except socket.gaierror:
            return None
    
    async def _query_certificate_transparency(self, domain: str) -> Set[str]:
        """Query Certificate Transparency logs for subdomains."""
        subdomains = set()
        
        try:
            # Query crt.sh
            response = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name and '*' not in name:
                        subdomains.add(name.lower())
        except Exception:
            pass
        
        return subdomains
    
    async def _check_subdomain_takeover(self, subdomains: List[str]) -> List[Vulnerability]:
        """Check for potential subdomain takeover vulnerabilities."""
        vulnerabilities = []
        
        # Common CNAME patterns indicating potential takeover
        takeover_signatures = {
            'amazonaws.com': 'AWS S3',
            'azurewebsites.net': 'Azure',
            'cloudapp.net': 'Azure',
            'trafficmanager.net': 'Azure',
            'blob.core.windows.net': 'Azure',
            'cloudfront.net': 'CloudFront',
            'fastly.net': 'Fastly',
            'herokuapp.com': 'Heroku',
            'github.io': 'GitHub Pages',
            'gitlab.io': 'GitLab Pages',
            'surge.sh': 'Surge.sh',
            'bitbucket.io': 'Bitbucket',
            'ghost.io': 'Ghost',
            'shopify.com': 'Shopify',
            'tumblr.com': 'Tumblr',
            'wordpress.com': 'WordPress',
        }
        
        for subdomain in subdomains:
            try:
                # Check CNAME records
                answers = dns.resolver.resolve(subdomain, 'CNAME')
                for rdata in answers:
                    cname = str(rdata.target)
                    
                    # Check for potential takeover
                    for signature, service in takeover_signatures.items():
                        if signature in cname:
                            # Try to connect and check for takeover indicators
                            try:
                                response = requests.get(f"http://{subdomain}", timeout=5)
                                if response.status_code == 404 or 'NoSuchBucket' in response.text:
                                    vulnerabilities.append(
                                        Vulnerability(
                                            module=self.name,
                                            name=f"Potential Subdomain Takeover - {service}",
                                            description=f"Subdomain {subdomain} points to {service} but appears unclaimed.",
                                            severity=SeverityLevel.HIGH,
                                            confidence=0.8,
                                            affected_urls=[subdomain],
                                            evidence={'cname': cname, 'service': service},
                                            remediation=f"Either claim the {service} resource or remove the DNS record.",
                                            references=[
                                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"
                                            ]
                                        )
                                    )
                            except Exception:
                                pass
                            break
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _attempt_zone_transfer(self, domain: str) -> Optional[str]:
        """Attempt DNS zone transfer."""
        try:
            # Get NS records
            ns_records = dns.resolver.resolve(domain, 'NS')
            
            for ns in ns_records:
                ns_name = str(ns.target)
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_name, domain, timeout=5)
                    )
                    
                    # If successful, return zone data
                    zone_text = []
                    for name, node in zone.nodes.items():
                        zone_text.append(f"{name} {node.to_text(name)}")
                    
                    return '\n'.join(zone_text)
                    
                except Exception:
                    continue
                    
        except Exception:
            pass
        
        return None
    
    async def _get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information for the domain."""
        whois_data = {}
        
        try:
            w = whois.whois(domain)
            
            whois_data = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers if w.name_servers else [],
                'status': w.status,
                'emails': w.emails if w.emails else [],
                'organization': w.org,
                'privacy_protected': bool(w.org and 'privacy' in str(w.org).lower()),
            }
            
        except Exception:
            pass
        
        return whois_data
    
    async def _gather_osint_data(self, domain: str) -> Dict[str, Any]:
        """Gather OSINT data from various sources."""
        osint_data = {}
        
        for source_name, url_template in self.osint_sources.items():
            try:
                url = url_template.format(domain=domain)
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    osint_data[source_name] = response.json() if 'json' in response.headers.get('content-type', '') else response.text
                    
            except Exception:
                continue
        
        return osint_data
    
    def _analyze_osint_data(self, osint_data: Dict, domain: str) -> List[Vulnerability]:
        """Analyze OSINT data for vulnerabilities."""
        vulnerabilities = []
        
        # Check for exposed sensitive paths in Wayback Machine
        if 'wayback' in osint_data:
            sensitive_paths = [
                '.git', '.env', 'config.php', 'wp-config', 'admin', 
                'backup', '.bak', 'database', '.sql', '.zip'
            ]
            
            exposed_paths = []
            for entry in osint_data.get('wayback', []):
                if isinstance(entry, list) and len(entry) > 0:
                    url = entry[0]
                    for sensitive in sensitive_paths:
                        if sensitive in url:
                            exposed_paths.append(url)
            
            if exposed_paths:
                vulnerabilities.append(
                    Vulnerability(
                        module=self.name,
                        name="Historical Sensitive Path Exposure",
                        description=f"Sensitive paths were historically accessible on {domain}.",
                        severity=SeverityLevel.MEDIUM,
                        confidence=0.7,
                        affected_urls=exposed_paths[:10],  # Limit to 10 examples
                        evidence={'path_count': len(exposed_paths)},
                        remediation="Review and ensure sensitive paths are properly protected.",
                    )
                )
        
        return vulnerabilities
    
    def _extract_emails(self, dns_records: Dict, whois_info: Dict, osint_data: Dict) -> Set[str]:
        """Extract email addresses from various sources."""
        emails = set()
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        
        # From DNS TXT records
        for txt in dns_records.get('TXT', []):
            emails.update(email_pattern.findall(txt))
        
        # From WHOIS
        emails.update(whois_info.get('emails', []))
        
        # From OSINT data
        for source_data in osint_data.values():
            if isinstance(source_data, str):
                emails.update(email_pattern.findall(source_data))
        
        return emails
