import shodan
import socket
from urllib.parse import urlparse
import asyncio
import ssl
import json
from datetime import datetime
import re

class ShodanScanner:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)
        
        # Known vulnerability patterns
        self.vuln_patterns = {
            'high_risk': [
                'remote code execution',
                'authentication bypass',
                'sql injection',
                'command injection',
                'arbitrary code execution'
            ],
            'medium_risk': [
                'cross-site scripting',
                'information disclosure',
                'directory traversal',
                'denial of service'
            ],
            'low_risk': [
                'cross-site request forgery',
                'clickjacking',
                'version disclosure'
            ]
        }
        
        # Common vulnerable services and versions
        self.vulnerable_services = {
            'apache': ['2.4.49', '2.4.50'],
            'nginx': ['1.16.1', '1.17.0'],
            'openssh': ['7.2p1', '7.2p2'],
            'mysql': ['5.5.', '5.6.', '5.7.'],
            'php': ['5.', '7.0.', '7.1.', '7.2.']
        }

    async def scan(self, domain):
        """
        Enhanced intelligence gathering about the target server using Shodan
        """
        result = {
            'timestamp': datetime.utcnow().isoformat(),
            'ip': None,
            'hostname': None,
            'ports': [],
            'vulnerabilities': [],
            'server_info': {
                'os': None,
                'services': [],
                'protocols': [],
                'certificates': [],
                'technologies': []
            },
            'security_issues': [],
            'exposure_score': None,  # Changed from 0 to None (will be set only on success)
            'risk_factors': [],
            'recommendations': [],
            'raw_data': {}
        }

        try:
            # THE FIX: No need to parse the input again. It's already a domain.
            if not domain:
                return {"error": "Invalid domain format", "scan_status": "failed"}

            # Resolve IP address with enhanced error handling
            ip = await self._resolve_domain(domain)
            if not ip:
                return {"error": "Could not resolve domain", "scan_status": "failed"}

            result['ip'] = ip
            result['hostname'] = domain

            # Get Shodan host information
            loop = asyncio.get_event_loop()
            host = await loop.run_in_executor(None, self.api.host, ip)
            result['raw_data'] = host

            # Enhanced port analysis
            await self._analyze_ports(host, result)
            
            # Enhanced vulnerability analysis
            await self._analyze_vulnerabilities(host, result)
            
            # Enhanced service analysis
            await self._analyze_services(host, result)
            
            # SSL/TLS analysis
            await self._analyze_ssl_certificates(host, result)
            
            # Technology stack analysis
            self._analyze_technologies(host, result)
            
            # Calculate exposure score (only on successful scan)
            self._calculate_exposure_score(result)
            
            # Generate security recommendations
            self._generate_recommendations(result)
            
            # Mark scan as successful
            result['scan_status'] = 'success'

        except shodan.APIError as e:
            error_str = str(e).lower()
            
            # Provide detailed error information based on the error type
            if '401' in error_str or 'invalid api key' in error_str:
                result['error'] = f"Shodan API error: Invalid API key"
                result['error_details'] = "Your API key is not valid. Please check your .env file."
                result['scan_status'] = 'failed'
                result['exposure_score'] = None  # Don't set score on auth failure
                
            elif '403' in error_str or 'access denied' in error_str:
                result['error'] = f"Shodan API error: Access denied (403 Forbidden)"
                result['error_details'] = (
                    f"Shodan denied access to IP {ip}. This is common for:\n"
                    "  • Major tech companies (Google, Facebook, Amazon, etc.)\n"
                    "  • Government/military infrastructure\n"
                    "  • IPs flagged for protection\n"
                    "  • Free API tier limitations"
                )
                result['scan_status'] = 'access_denied'
                result['exposure_score'] = None  # Don't set score - we couldn't scan
                result['suggestions'] = [
                    "Try scanning a different target (e.g., your own server)",
                    "Test with scanme.nmap.org (a legal test target)",
                    "Check if your API plan supports this target",
                    "Some targets are deliberately blocked by Shodan"
                ]
                
            elif '404' in error_str or 'no information' in error_str:
                result['error'] = f"Shodan API error: No information available"
                result['error_details'] = f"IP {ip} is not indexed in Shodan's database yet."
                result['scan_status'] = 'not_found'
                result['exposure_score'] = 0  # Not found = no known exposure
                
            elif '429' in error_str or 'rate limit' in error_str:
                result['error'] = f"Shodan API error: Rate limit exceeded"
                result['error_details'] = "You've made too many requests. Wait a few minutes and try again."
                result['scan_status'] = 'rate_limited'
                result['exposure_score'] = None  # Don't set score on rate limit
                
            else:
                result['error'] = f"Shodan API error: {str(e)}"
                result['error_details'] = "An unexpected error occurred during the scan."
                result['scan_status'] = 'failed'
                result['exposure_score'] = None  # Don't set score on unknown error
                
        except Exception as e:
            result['error'] = f"Scanning error: {str(e)}"
            result['error_details'] = "An unexpected error occurred during the scan."
            result['scan_status'] = 'failed'
            result['exposure_score'] = None  # Don't set score on exception

        return result

    async def _resolve_domain(self, domain):
        """Enhanced domain resolution with multiple attempts"""
        try:
            loop = asyncio.get_event_loop()
            for _ in range(3):  # Try up to 3 times
                try:
                    ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
                    return ip
                except socket.gaierror:
                    await asyncio.sleep(1)
            return None
        except Exception:
            return None

    async def _analyze_ports(self, host, result):
        """Enhanced port analysis with service identification"""
        result['ports'] = host.get('ports', [])
        
        # Analyze each port and its service
        for port in result['ports']:
            service_data = next((item for item in host.get('data', []) if item.get('port') == port), None)
            if service_data:
                service = {
                    'port': port,
                    'service': service_data.get('product', 'unknown'),
                    'version': service_data.get('version', 'unknown'),
                    'protocol': service_data.get('transport', 'unknown'),
                    'state': 'open'
                }
                
                # Check for vulnerable service versions
                if service['service'].lower() in self.vulnerable_services:
                    vulnerable_versions = self.vulnerable_services[service['service'].lower()]
                    if any(service['version'].startswith(v) for v in vulnerable_versions):
                        result['security_issues'].append({
                            'type': 'vulnerable_service',
                            'service': service['service'],
                            'version': service['version'],
                            'port': port,
                            'severity': 'high'
                        })
                
                result['server_info']['services'].append(service)

    async def _analyze_vulnerabilities(self, host, result):
        """Enhanced vulnerability analysis with severity classification"""
        vulns = host.get('vulns', [])
        
        for vuln_id in vulns:
            try:
                # Get detailed vulnerability information
                vuln_info = await self._get_vulnerability_details(vuln_id)
                
                # Classify vulnerability severity
                severity = self._classify_vulnerability_severity(vuln_info)
                
                # Add to vulnerabilities list
                result['vulnerabilities'].append({
                    'id': vuln_id,
                    'title': vuln_info.get('title', 'Unknown'),
                    'description': vuln_info.get('description', 'No description available'),
                    'severity': severity,
                    'cvss_score': vuln_info.get('cvss', 0),
                    'references': vuln_info.get('references', []),
                    'solution': vuln_info.get('solution', 'No solution provided')
                })
                
                # Update risk factors
                result['risk_factors'].append({
                    'type': 'vulnerability',
                    'details': f"{vuln_id} ({severity} severity)"
                })
                
            except Exception as e:
                result['vulnerabilities'].append({
                    'id': vuln_id,
                    'error': f"Error fetching vulnerability details: {str(e)}"
                })

    async def _analyze_services(self, host, result):
        """Enhanced service analysis"""
        for item in host.get('data', []):
            # Analyze service configuration
            if 'product' in item:
                service = {
                    'name': item.get('product', 'unknown'),
                    'version': item.get('version', 'unknown'),
                    'port': item.get('port', 0),
                    'protocol': item.get('transport', 'unknown'),
                    'configuration': {}
                }
                
                # Check for common misconfigurations
                if 'opts' in item:
                    service['configuration'] = item['opts']
                    self._check_service_misconfigurations(service, result)
                
                # Only append if we have meaningful service data
                if service['name'] != 'unknown':
                    result['server_info']['services'].append(service)
            
            # Analyze operating system information
            if 'os' in item:
                result['server_info']['os'] = item['os']
                
            # Analyze protocols
            if 'transport' in item and item['transport'] not in result['server_info']['protocols']:
                result['server_info']['protocols'].append(item['transport'])

    async def _analyze_ssl_certificates(self, host, result):
        """Enhanced SSL/TLS certificate analysis"""
        for item in host.get('data', []):
            if 'ssl' in item:
                cert_info = item['ssl'].get('cert', {})
                
                # Extract certificate details
                certificate = {
                    'subject': cert_info.get('subject', {}),
                    'issuer': cert_info.get('issuer', {}),
                    'expires': cert_info.get('expires', ''),
                    'valid': False,
                    'issues': []
                }
                
                # Validate certificate
                try:
                    # Check expiration
                    expires = datetime.strptime(certificate['expires'], '%Y-%m-%d %H:%M:%S')
                    if expires < datetime.now():
                        certificate['issues'].append('Certificate has expired')
                    elif (expires - datetime.now()).days < 30:
                        certificate['issues'].append('Certificate expires soon')
                    
                    # Check cipher strength
                    if 'cipher' in item['ssl']:
                        cipher = item['ssl']['cipher']
                        if cipher.get('bits', 0) < 128:
                            certificate['issues'].append('Weak cipher strength')
                    
                    certificate['valid'] = len(certificate['issues']) == 0
                    
                except Exception as e:
                    certificate['issues'].append(f'Certificate validation error: {str(e)}')
                
                result['server_info']['certificates'].append(certificate)

    def _analyze_technologies(self, host, result):
        """Analyze technology stack and known vulnerabilities"""
        technologies = set()
        
        # Extract technologies from headers and banners
        for item in host.get('data', []):
            if 'http' in item:
                headers = item['http'].get('headers', {})
                
                # Server software
                if 'server' in headers:
                    technologies.add(f"Server: {headers['server']}")
                
                # Programming language/framework
                if 'x-powered-by' in headers:
                    technologies.add(f"Powered by: {headers['x-powered-by']}")
                
                # Web server modules
                if 'x-mod-pagespeed' in headers:
                    technologies.add('Module: PageSpeed')
                
            # Extract from banner
            if 'banner' in item:
                banner = item['banner'].lower()
                if 'php' in banner:
                    technologies.add('PHP')
                if 'nginx' in banner:
                    technologies.add('Nginx')
                if 'apache' in banner:
                    technologies.add('Apache')
        
        result['server_info']['technologies'] = list(technologies)

    def _check_service_misconfigurations(self, service, result):
        """Check for common service misconfigurations"""
        config = service.get('configuration', {})
        service_name = service.get('name', '').lower()
        
        # Skip if no service name
        if not service_name or service_name == 'unknown':
            return
        
        # Database misconfigurations
        if service_name in ['mysql', 'mongodb', 'redis']:
            if not config.get('requires_auth', True):
                result['security_issues'].append({
                    'type': 'misconfiguration',
                    'service': service['name'],
                    'details': 'No authentication required',
                    'severity': 'critical'
                })
        
        # SSH misconfigurations
        if service_name == 'openssh':
            if config.get('protocol_version', '2') == '1':
                result['security_issues'].append({
                    'type': 'misconfiguration',
                    'service': 'SSH',
                    'details': 'Using outdated SSH protocol version 1',
                    'severity': 'high'
                })

    def _calculate_exposure_score(self, result):
        """Calculate server exposure score based on findings"""
        score = 0
        
        # Add points for open ports
        score += len(result['ports']) * 2
        
        # Add points for vulnerabilities
        for vuln in result['vulnerabilities']:
            if vuln.get('severity') == 'critical':
                score += 25
            elif vuln.get('severity') == 'high':
                score += 15
            elif vuln.get('severity') == 'medium':
                score += 10
            elif vuln.get('severity') == 'low':
                score += 5
        
        # Add points for security issues
        for issue in result['security_issues']:
            if issue['severity'] == 'critical':
                score += 20
            elif issue['severity'] == 'high':
                score += 15
            elif issue['severity'] == 'medium':
                score += 10
            elif issue['severity'] == 'low':
                score += 5
        
        # Cap the score at 100
        result['exposure_score'] = min(score, 100)

    def _generate_recommendations(self, result):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Vulnerability-based recommendations
        for vuln in result['vulnerabilities']:
            if vuln.get('severity') in ['critical', 'high']:
                recommendations.append({
                    'priority': 'high',
                    'category': 'vulnerability',
                    'title': f"Fix {vuln['id']}",
                    'description': vuln.get('solution', 'Update affected software'),
                    'details': vuln.get('description', '')
                })
        
        # Service-based recommendations
        for service in result['server_info']['services']:
            service_name = service.get('name', '').lower()
            service_version = service.get('version', 'unknown')
            
            if service_name in self.vulnerable_services:
                recommendations.append({
                    'priority': 'medium',
                    'category': 'service',
                    'title': f"Update {service.get('name', 'service')}",
                    'description': f"Current version {service_version} may be vulnerable",
                    'details': 'Update to the latest stable version'
                })
        
        # Certificate-based recommendations
        for cert in result['server_info']['certificates']:
            if not cert['valid']:
                recommendations.append({
                    'priority': 'high',
                    'category': 'ssl',
                    'title': 'Fix SSL/TLS Issues',
                    'description': 'SSL certificate has issues',
                    'details': '\n'.join(cert['issues'])
                })
        
        result['recommendations'] = sorted(
            recommendations,
            key=lambda x: {'high': 0, 'medium': 1, 'low': 2}[x['priority']]
        )

    async def _get_vulnerability_details(self, vuln_id):
        """Get detailed vulnerability information"""
        try:
            loop = asyncio.get_event_loop()
            vuln_info = await loop.run_in_executor(
                None,
                self.api.exploits.search,
                f"vuln:{vuln_id}"
            )
            
            if vuln_info['matches']:
                return vuln_info['matches'][0]
            return {'description': 'No details available'}
            
        except Exception:
            return {'description': 'Error fetching details'}

    def _classify_vulnerability_severity(self, vuln_info):
        """Classify vulnerability severity based on description and CVSS score"""
        description = vuln_info.get('description', '').lower()
        cvss_score = float(vuln_info.get('cvss', 0))
        
        # Check for critical patterns
        if any(pattern in description for pattern in self.vuln_patterns['high_risk']) or cvss_score >= 9.0:
            return 'critical'
        elif any(pattern in description for pattern in self.vuln_patterns['medium_risk']) or cvss_score >= 7.0:
            return 'high'
        elif any(pattern in description for pattern in self.vuln_patterns['low_risk']) or cvss_score >= 4.0:
            return 'medium'
        else:
            return 'low'