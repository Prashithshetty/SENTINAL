"""
Enhanced Link Analyzer with Web Crawling Capabilities
"""
import validators
import whois
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs
from typing import Set, List, Dict, Any
import requests
from bs4 import BeautifulSoup
import re
import asyncio
from collections import deque

class LinkAnalyzer:
    def __init__(self):
        # Categorized TLDs for better risk assessment
        self.tld_categories = {
            'high_risk': ['.xyz', '.top', '.work', '.loan', '.click', '.pw', '.cc', '.tk', '.ml', '.ga', '.cf'],
            'medium_risk': ['.info', '.biz', '.site', '.online', '.website'],
            'low_risk': ['.com', '.org', '.net', '.edu', '.gov', '.mil']
        }
        # Initialize reputation check endpoints (can be expanded)
        self.reputation_apis = {
            'google_safe_browsing': 'https://safebrowsing.googleapis.com/v4/threatMatches:find',
            'virus_total': 'https://www.virustotal.com/vtapi/v2/url/report'
        }
        
        # Crawler state
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.urls_with_params: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []

    async def crawl(self, start_url: str, max_depth: int = 3, max_urls: int = 50) -> Dict[str, Any]:
        """
        Crawl a website starting from start_url and discover all URLs in the same domain.
        
        Args:
            start_url: Starting URL to crawl
            max_depth: Maximum depth to crawl (default: 3)
            max_urls: Maximum number of URLs to discover (default: 50)
            
        Returns:
            Dictionary containing discovered URLs, forms, and statistics
        """
        print(f"[*] Starting web crawler for: {start_url}")
        print(f"[*] Max depth: {max_depth}, Max URLs: {max_urls}")
        
        # Reset state
        self.visited_urls.clear()
        self.discovered_urls.clear()
        self.urls_with_params.clear()
        self.forms.clear()
        
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc
        
        # Queue structure: (url, depth)
        queue = deque([(start_url, 0)])
        self.discovered_urls.add(start_url)
        
        crawl_stats = {
            'pages_crawled': 0,
            'urls_discovered': 0,
            'forms_found': 0,
            'urls_with_parameters': 0,
            'errors': []
        }
        
        while queue and len(self.visited_urls) < max_urls:
            current_url, depth = queue.popleft()
            
            # Skip if already visited or depth exceeded
            if current_url in self.visited_urls or depth > max_depth:
                continue
            
            print(f"[*] Crawling [{depth}/{max_depth}]: {current_url}")
            
            try:
                # Mark as visited
                self.visited_urls.add(current_url)
                crawl_stats['pages_crawled'] += 1
                
                # Fetch the page
                response = requests.get(
                    current_url,
                    headers={'User-Agent': 'SENTINEL-Crawler/1.0'},
                    timeout=10,
                    allow_redirects=True
                )
                
                # Only process HTML content
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' not in content_type.lower():
                    continue
                
                # Parse HTML
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Extract all links
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    absolute_url = urljoin(current_url, href)
                    
                    # Parse and validate URL
                    parsed_url = urlparse(absolute_url)
                    
                    # Only crawl URLs from the same domain
                    if parsed_url.netloc != base_domain:
                        continue
                    
                    # Remove fragments
                    clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    if parsed_url.query:
                        clean_url += f"?{parsed_url.query}"
                    
                    # Check if URL has parameters (potential injection points)
                    if parsed_url.query:
                        self.urls_with_params.add(clean_url)
                        crawl_stats['urls_with_parameters'] += 1
                    
                    # Add to discovered URLs and queue
                    if clean_url not in self.discovered_urls:
                        self.discovered_urls.add(clean_url)
                        crawl_stats['urls_discovered'] += 1
                        
                        # Add to queue if we haven't reached max depth
                        if depth < max_depth and len(self.visited_urls) < max_urls:
                            queue.append((clean_url, depth + 1))
                
                # Extract forms (important for testing injection vulnerabilities)
                forms = soup.find_all('form')
                for form in forms:
                    form_data = self._extract_form_data(form, current_url)
                    if form_data:
                        self.forms.append(form_data)
                        crawl_stats['forms_found'] += 1
                
                # Small delay to be respectful
                await asyncio.sleep(0.5)
                
            except requests.exceptions.RequestException as e:
                crawl_stats['errors'].append(f"Error crawling {current_url}: {str(e)}")
                print(f"[!] Error crawling {current_url}: {str(e)}")
            except Exception as e:
                crawl_stats['errors'].append(f"Unexpected error at {current_url}: {str(e)}")
                print(f"[!] Unexpected error at {current_url}: {str(e)}")
        
        print(f"[+] Crawling complete!")
        print(f"    - Pages crawled: {crawl_stats['pages_crawled']}")
        print(f"    - Total URLs discovered: {len(self.discovered_urls)}")
        print(f"    - URLs with parameters: {len(self.urls_with_params)}")
        print(f"    - Forms found: {len(self.forms)}")
        
        return {
            'start_url': start_url,
            'base_domain': base_domain,
            'discovered_urls': sorted(list(self.discovered_urls)),
            'urls_with_parameters': sorted(list(self.urls_with_params)),
            'forms': self.forms,
            'statistics': crawl_stats
        }
    
    def _extract_form_data(self, form, page_url: str) -> Dict[str, Any]:
        """Extract data from an HTML form."""
        form_action = form.get('action', '')
        form_method = form.get('method', 'get').upper()
        
        # Resolve relative URLs
        if form_action:
            form_action = urljoin(page_url, form_action)
        else:
            form_action = page_url
        
        # Extract all input fields
        inputs = []
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_data = {
                'name': input_tag.get('name', ''),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value', '')
            }
            if input_data['name']:  # Only add if it has a name
                inputs.append(input_data)
        
        return {
            'url': form_action,
            'method': form_method,
            'inputs': inputs,
            'found_on_page': page_url
        }

    async def analyze(self, url):
        """
        Analyze URL for legitimacy and security concerns with enhanced checks.
        This is the original analysis function - kept for backward compatibility.
        """
        result = {
            'is_valid_url': False,
            'domain_age': None,
            'ssl_info': {
                'valid': False,
                'cert_chain': [],
                'issues': []
            },
            'domain_info': {},
            'reputation': {
                'score': 0,
                'sources': {}
            },
            'redirect_chain': [],
            'risk_score': 0,
            'warnings': [],
            'confidence_level': 'unknown'
        }

        try:
            # Basic URL validation
            if not validators.url(url):
                result['warnings'].append("Invalid URL format")
                return result

            result['is_valid_url'] = True
            parsed_url = urlparse(url)
            domain = parsed_url.netloc

            # Check domain age
            try:
                w = whois.whois(domain)
                if w.creation_date:
                    creation_date = w.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    domain_age = (datetime.now() - creation_date).days
                    result['domain_age'] = domain_age
                    result['domain_info'] = {
                        'registrar': w.registrar,
                        'creation_date': str(w.creation_date),
                        'expiration_date': str(w.expiration_date),
                        'registered_to': w.name
                    }
                    
                    # Check if domain is too new (less than 30 days)
                    if domain_age < 30:
                        result['warnings'].append("Domain is very new")
                        result['risk_score'] += 20
            except Exception as e:
                result['warnings'].append(f"Could not verify domain age: {str(e)}")
                result['risk_score'] += 10

            # Enhanced TLD Check
            tld = '.' + domain.split('.')[-1].lower()
            if tld in self.tld_categories['high_risk']:
                result['warnings'].append(f"High-risk TLD detected: {tld}")
                result['risk_score'] += 25
            elif tld in self.tld_categories['medium_risk']:
                result['warnings'].append(f"Medium-risk TLD detected: {tld}")
                result['risk_score'] += 10
            elif tld not in self.tld_categories['low_risk']:
                result['warnings'].append(f"Uncommon TLD detected: {tld}")
                result['risk_score'] += 5

            # Enhanced SSL Certificate Validation
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        result['ssl_info']['valid'] = True
                        
                        # Validate certificate chain
                        cert_chain = self._validate_cert_chain(ssock)
                        result['ssl_info']['cert_chain'] = cert_chain
                        
                        # Check certificate strength
                        cipher = ssock.cipher()
                        if cipher[0] not in ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256']:
                            result['ssl_info']['issues'].append(f"Weak cipher suite: {cipher[0]}")
                            result['risk_score'] += 10
                        
                        # Check certificate expiration
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
                        days_until_expiry = (not_after - datetime.now()).days
                        if days_until_expiry < 30:
                            result['ssl_info']['issues'].append(f"Certificate expires in {days_until_expiry} days")
                            result['risk_score'] += 15
            except Exception as e:
                result['warnings'].append(f"SSL validation error: {str(e)}")
                result['risk_score'] += 30

            # Enhanced Website Access Check
            try:
                session = requests.Session()
                response = session.head(url, allow_redirects=True, timeout=5)
                
                # Analyze response headers
                security_headers = {
                    'Strict-Transport-Security': 'HSTS not enabled',
                    'Content-Security-Policy': 'CSP not configured',
                    'X-Content-Type-Options': 'MIME-type sniffing protection missing',
                    'X-Frame-Options': 'Clickjacking protection missing'
                }
                
                for header, warning in security_headers.items():
                    if header.lower() not in response.headers:
                        result['warnings'].append(warning)
                        result['risk_score'] += 5

                # Analyze redirect chain
                if response.history:
                    result['redirect_chain'] = [{'url': r.url, 'status_code': r.status_code} for r in response.history]
                    if len(response.history) > 2:
                        result['warnings'].append(f"Multiple redirects detected: {len(response.history)}")
                        result['risk_score'] += 15
                    
                    # Check for mixed content in redirects
                    for redirect in response.history:
                        if redirect.url.startswith('http://'):
                            result['warnings'].append("Mixed content: HTTP redirect in chain")
                            result['risk_score'] += 20
                            break
            except requests.exceptions.RequestException as e:
                result['warnings'].append(f"Could not access website: {str(e)}")
                result['risk_score'] += 25

            # Calculate confidence level based on available data
            confidence_factors = {
                'ssl_valid': result['ssl_info']['valid'],
                'domain_age_known': result['domain_age'] is not None,
                'no_critical_warnings': len([w for w in result['warnings'] if 'critical' in w.lower()]) == 0
            }
            result['confidence_level'] = self._calculate_confidence_level(confidence_factors)

            # Calculate final risk assessment with weighted factors
            result['risk_level'] = self._calculate_risk_level(
                result['risk_score'],
                ssl_valid=result['ssl_info']['valid'],
                domain_age=result['domain_age'],
                redirect_count=len(result['redirect_chain'])
            )

        except Exception as e:
            result['warnings'].append(f"Analysis error: {str(e)}")
            result['risk_score'] = 100
            result['risk_level'] = "High"

        return result

    def _validate_cert_chain(self, ssl_socket):
        """Validate the certificate chain"""
        cert_chain = []
        try:
            for cert in ssl_socket.get_peer_cert_chain():
                cert_info = {
                    'subject': dict(x[0] for x in cert.get_subject().get_components()),
                    'issuer': dict(x[0] for x in cert.get_issuer().get_components()),
                    'version': cert.get_version(),
                    'serial_number': cert.get_serial_number(),
                    'not_before': cert.get_notBefore(),
                    'not_after': cert.get_notAfter()
                }
                cert_chain.append(cert_info)
        except AttributeError:
            # Handle case where get_peer_cert_chain is not available
            pass
        return cert_chain

    def _calculate_confidence_level(self, factors):
        """Calculate confidence level of the analysis"""
        confidence_score = sum(1 for factor in factors.values() if factor)
        if confidence_score == len(factors):
            return "High"
        elif confidence_score >= len(factors) / 2:
            return "Medium"
        else:
            return "Low"

    def _calculate_risk_level(self, risk_score, **factors):
        """Calculate risk level with weighted factors"""
        # Apply weight adjustments based on factors
        if not factors.get('ssl_valid', True):
            risk_score *= 1.5
        
        if factors.get('domain_age', 0) and factors['domain_age'] < 30:
            risk_score *= 1.3
        
        if factors.get('redirect_count', 0) > 3:
            risk_score *= 1.2

        # Determine final risk level
        if risk_score < 20:
            return "Low"
        elif risk_score < 50:
            return "Medium"
        else:
            return "High"