import dns.resolver
import socket
import whois
import requests
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import ssl
from urllib.parse import urlparse

class DNSInspector:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Common DNS configurations to check
        self.expected_records = {
            'spf': 'v=spf1',
            'dmarc': 'v=DMARC1',
            'dkim': 'v=DKIM1'
        }

    async def inspect(self, url):
        """
        Perform comprehensive DNS analysis of the given URL with enhanced checks
        """
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            if not domain:
                return {"error": "Invalid URL format"}

            # Gather all DNS information asynchronously with timeouts
            tasks = [
                self._get_a_records(domain),
                self._get_aaaa_records(domain),
                self._get_mx_records(domain),
                self._get_ns_records(domain),
                self._get_txt_records(domain),
                self._get_whois_info(domain),
                self._check_dnssec(domain)
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            analysis_result = {
                "domain": domain,
                "timestamp": datetime.utcnow().isoformat(),
                "a_records": results[0] if not isinstance(results[0], Exception) else [],
                "aaaa_records": results[1] if not isinstance(results[1], Exception) else [],
                "mx_records": results[2] if not isinstance(results[2], Exception) else [],
                "ns_records": results[3] if not isinstance(results[3], Exception) else [],
                "txt_records": results[4] if not isinstance(results[4], Exception) else [],
                "whois_info": results[5] if not isinstance(results[5], Exception) else {},
                "dnssec": results[6] if not isinstance(results[6], Exception) else {"enabled": False},
                "analysis": {},
                "risk_score": 0,
                "warnings": [],
                "recommendations": []
            }

            # Analyze results and generate recommendations
            self._analyze_results(analysis_result)
            
            return analysis_result

        except Exception as e:
            return {
                "error": f"DNS inspection failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat(),
                "risk_score": 100,
                "warnings": [f"Critical DNS inspection error: {str(e)}"]
            }

    async def _get_a_records(self, domain):
        """Get IPv4 addresses"""
        try:
            loop = asyncio.get_event_loop()
            records = await loop.run_in_executor(
                self.executor,
                lambda: [str(r) for r in self.resolver.resolve(domain, 'A')]
            )
            return records
        except Exception as e:
            return []

    async def _get_aaaa_records(self, domain):
        """Get IPv6 addresses"""
        try:
            loop = asyncio.get_event_loop()
            records = await loop.run_in_executor(
                self.executor,
                lambda: [str(r) for r in self.resolver.resolve(domain, 'AAAA')]
            )
            return records
        except Exception:
            return []

    async def _get_mx_records(self, domain):
        """Get mail server records"""
        try:
            loop = asyncio.get_event_loop()
            records = await loop.run_in_executor(
                self.executor,
                lambda: [(str(r.exchange), r.preference) for r in self.resolver.resolve(domain, 'MX')]
            )
            return records
        except Exception:
            return []

    async def _get_ns_records(self, domain):
        """Get nameserver records"""
        try:
            loop = asyncio.get_event_loop()
            records = await loop.run_in_executor(
                self.executor,
                lambda: [str(r) for r in self.resolver.resolve(domain, 'NS')]
            )
            return records
        except Exception:
            return []

    async def _get_txt_records(self, domain):
        """Get TXT records"""
        try:
            loop = asyncio.get_event_loop()
            records = await loop.run_in_executor(
                self.executor,
                lambda: [str(r) for r in self.resolver.resolve(domain, 'TXT')]
            )
            return records
        except Exception:
            return []

    async def _get_whois_info(self, domain):
        """Get WHOIS information"""
        try:
            loop = asyncio.get_event_loop()
            whois_info = await loop.run_in_executor(self.executor, whois.whois, domain)
            return {
                'registrar': whois_info.registrar,
                'creation_date': str(whois_info.creation_date),
                'expiration_date': str(whois_info.expiration_date),
                'name_servers': whois_info.name_servers if isinstance(whois_info.name_servers, list) else []
            }
        except Exception:
            return {}

    async def _check_dnssec(self, domain):
        """Check DNSSEC configuration"""
        try:
            loop = asyncio.get_event_loop()
            dnskey_records = await loop.run_in_executor(
                self.executor,
                lambda: self.resolver.resolve(domain, 'DNSKEY')
            )
            
            return {
                'enabled': bool(dnskey_records),
                'num_keys': len(dnskey_records) if dnskey_records else 0
            }
        except Exception:
            return {'enabled': False}

    def _analyze_results(self, result):
        """Analyze DNS results and generate recommendations"""
        warnings = []
        recommendations = []
        risk_score = 0

        # Check DNSSEC
        if not result['dnssec']['enabled']:
            warnings.append("DNSSEC is not enabled")
            recommendations.append("Enable DNSSEC for enhanced DNS security")
            risk_score += 20

        # Check nameservers
        if len(result['ns_records']) < 2:
            warnings.append("Less than 2 nameservers found")
            recommendations.append("Configure at least 2 nameservers for redundancy")
            risk_score += 15

        # Check MX records
        if not result['mx_records']:
            warnings.append("No MX records found")
            recommendations.append("Configure MX records for email handling")
            risk_score += 10

        # Check TXT records for SPF and DMARC
        txt_records_str = ' '.join(result['txt_records']).lower()
        if 'v=spf1' not in txt_records_str:
            warnings.append("No SPF record found")
            recommendations.append("Add SPF record to prevent email spoofing")
            risk_score += 15
        if 'v=dmarc1' not in txt_records_str:
            warnings.append("No DMARC record found")
            recommendations.append("Add DMARC record to enhance email security")
            risk_score += 15

        # Update result with analysis
        result['analysis'] = {
            'security_rating': 'poor' if risk_score > 50 else 'fair' if risk_score > 25 else 'good',
            'warnings': warnings,
            'recommendations': recommendations
        }
        result['risk_score'] = risk_score
        result['warnings'] = warnings
        result['recommendations'] = recommendations
