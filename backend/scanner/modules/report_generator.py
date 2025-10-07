from urllib.parse import urlparse
import re

class ReportGenerator:
    def __init__(self):
        self.trusted_domains = {
            'google.com', 'www.google.com',
            'github.com', 'www.github.com',
            'instagram.com', 'www.instagram.com',
            'facebook.com', 'www.facebook.com',
            'twitter.com', 'www.twitter.com',
            'linkedin.com', 'www.linkedin.com',
            'microsoft.com', 'www.microsoft.com',
            'apple.com', 'www.apple.com',
            'amazon.com', 'www.amazon.com',
            'youtube.com', 'www.youtube.com'
        }

        # Patterns that indicate suspicious URLs
        self.suspicious_patterns = [
            r'[0-9a-f]{32}',  # Long hexadecimal strings
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',  # UUIDs
            r'[^a-zA-Z0-9-_./]',  # Special characters in path
            r'(?:[^a-zA-Z0-9]|^)(admin|login|signin|account|password|reset|verify)(?:[^a-zA-Z0-9]|$)',  # Sensitive endpoints
            r'[a-zA-Z0-9]{25,}',  # Very long random-looking strings
            r'(?:[^a-zA-Z0-9]|^)(scam|hack|crack|free|win|crypto|wallet|verify)(?:[^a-zA-Z0-9]|$)'  # Suspicious keywords
        ]

    def _is_trusted_domain(self, url):
        """Check if the domain is in the trusted list and the URL is not suspicious"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Check if base domain is trusted
            is_trusted_base = domain in self.trusted_domains or any(domain.endswith('.' + td) for td in self.trusted_domains)
            
            if not is_trusted_base:
                return False
                
            # Check for suspicious patterns in the URL
            full_url = url.lower()
            
            # If path is longer than 50 characters, consider it suspicious
            if len(path) > 50:
                return False
                
            # Check for suspicious patterns
            for pattern in self.suspicious_patterns:
                if re.search(pattern, path):
                    return False
                    
            # Check for excessive subdomains (more than 3 levels)
            if domain.count('.') > 3:
                return False
                
            # Check for numeric or random-looking subdomains
            subdomains = domain.split('.')[:-2]  # Exclude main domain and TLD
            for subdomain in subdomains:
                if re.match(r'^[0-9]+$', subdomain):  # Purely numeric subdomain
                    return False
                if len(subdomain) > 20:  # Unusually long subdomain
                    return False
                if re.match(r'^[a-f0-9]{8,}$', subdomain):  # Hex-looking subdomain
                    return False
            
            return True
            
        except:
            return False

    def generate(self, url, link_analysis, dns_analysis, browser_analysis, shodan_analysis):
        """Generate a comprehensive security report"""
        is_trusted = self._is_trusted_domain(url)
        
        # Calculate weighted component scores
        browser_score = browser_analysis.get('risk_score', 0)
        dns_score = dns_analysis.get('risk_score', 0)
        link_score = link_analysis.get('risk_score', 0)
        server_score = shodan_analysis.get('exposure_score', 0)

        # For trusted domains with suspicious URLs, increase the scores
        if not is_trusted and any(domain in urlparse(url).netloc for domain in self.trusted_domains):
            browser_score += 40  # Significant penalty for suspicious URL on trusted domain
            link_score += 40
            
        # Calculate overall score with weighted components
        overall_score = (
            browser_score * 0.4 +  # Browser analysis weight
            dns_score * 0.2 +      # DNS analysis weight
            link_score * 0.2 +     # Link analysis weight
            server_score * 0.2     # Server analysis weight
        )

        # Determine risk level based on domain trust and score
        if is_trusted:
            if overall_score < 20:
                risk_level = "Safe"
            elif overall_score < 40:
                risk_level = "Low Risk"
            else:
                risk_level = "Medium Risk"
        else:
            if overall_score < 20:
                risk_level = "Safe"
            elif overall_score < 40:
                risk_level = "Low Risk"
            elif overall_score < 60:
                risk_level = "Medium Risk"
            elif overall_score < 80:
                risk_level = "High Risk"
            else:
                risk_level = "Critical Risk"

        # Collect security issues
        security_issues = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }

        # Add browser security issues
        for warning in browser_analysis.get('warnings', []):
            if any(critical in warning.lower() for critical in ['critical', 'severe', 'high']):
                security_issues['critical'].append({
                    'category': 'Browser',
                    'description': warning
                })
            else:
                security_issues['low'].append({
                    'category': 'Browser',
                    'description': warning
                })

        # Add DNS security issues (with reduced severity for trusted domains)
        for warning in dns_analysis.get('warnings', []):
            if is_trusted:
                security_issues['low'].append({
                    'category': 'DNS',
                    'description': warning
                })
            else:
                if 'DNSSEC' in warning:
                    security_issues['high'].append({
                        'category': 'DNS',
                        'description': warning
                    })
                else:
                    security_issues['medium'].append({
                        'category': 'DNS',
                        'description': warning
                    })

        # Add link analysis issues
        for warning in link_analysis.get('warnings', []):
            if any(critical in warning.lower() for critical in ['ssl', 'https', 'certificate']):
                security_issues['high'].append({
                    'category': 'URL/SSL',
                    'description': warning
                })
            else:
                security_issues['low'].append({
                    'category': 'URL/SSL',
                    'description': warning
                })

        # Generate recommendations
        recommendations = []
        
        # Add critical recommendations first
        if not is_trusted:
            if dns_analysis.get('dnssec', {}).get('enabled') is False:
                recommendations.append({
                    'category': 'DNS',
                    'priority': 'High',
                    'suggestion': 'Enable DNSSEC for enhanced DNS security'
                })

        # Add security header recommendations
        missing_headers = [
            header for header, config in browser_analysis.get('security_headers', {}).items()
            if not config.get('present')
        ]
        
        for header in missing_headers:
            if not is_trusted or header in ['Content-Security-Policy', 'Strict-Transport-Security']:
                recommendations.append({
                    'category': 'Security Headers',
                    'priority': 'Medium',
                    'suggestion': f'Implement {header} security header'
                })

        # Generate key findings
        key_findings = []
        if link_analysis.get('ssl_info', {}).get('valid'):
            key_findings.append('Valid SSL certificate')
        else:
            key_findings.append('Invalid SSL certificate')
            
        if missing_headers:
            key_findings.append(f"Missing critical security headers: {', '.join(missing_headers)}")
        else:
            key_findings.append('All critical security headers present')

        # Generate critical issues summary
        critical_issues = []
        for issue in security_issues['critical'] + security_issues['high']:
            critical_issues.append(issue['description'])
        critical_issues = critical_issues[:3]  # Limit to top 3 issues

        # Add suspicious URL warning if applicable
        if not is_trusted and any(domain in urlparse(url).netloc for domain in self.trusted_domains):
            critical_issues.insert(0, "Suspicious URL pattern detected on trusted domain")
            key_findings.insert(0, "Suspicious URL pattern detected")

        # Update verdict for suspicious URLs
        if not is_trusted and any(domain in urlparse(url).netloc for domain in self.trusted_domains):
            verdict = 'Suspicious URL on Trusted Domain'
        else:
            verdict = 'Safe' if is_trusted and overall_score < 40 else 'Potentially Unsafe'

        return {
            'metadata': {
                'url': url,
                'timestamp': browser_analysis.get('timestamp'),
                'scan_duration': browser_analysis.get('scan_duration')
            },
            'detailed_analysis': {
                'browser_analysis': browser_analysis,
                'dns_analysis': dns_analysis,
                'link_analysis': link_analysis,
                'server_analysis': shodan_analysis
            },
            'risk_assessment': {
                'overall_score': overall_score,
                'risk_level': risk_level,
                'component_scores': {
                    'browser_analysis': browser_score,
                    'dns_analysis': dns_score,
                    'link_analysis': link_score,
                    'server_analysis': server_score
                }
            },
            'security_issues': security_issues,
            'recommendations': recommendations,
            'summary': {
                'verdict': verdict,
                'security_score': max(0, min(100, 100 - overall_score)),
                'confidence_level': 'High' if is_trusted else 'Medium',
                'critical_issues': critical_issues,
                'key_findings': key_findings
            }
        }
