import asyncio
import os
import json
import hashlib
import re
from urllib.parse import urlparse, urljoin
from pyppeteer import launch
from concurrent.futures import ThreadPoolExecutor

class BrowserChecker:
    def __init__(self):
        self.screenshot_dir = "screenshots"
        os.makedirs(self.screenshot_dir, exist_ok=True)
        
        # Known trusted domains
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
        
        # Known malicious patterns with fixed regex
        self.suspicious_patterns = {
            'scripts': [
                r'eval\s*\(\s*atob\s*\(',  # More specific eval pattern
                r'document\.write\s*\(\s*(?:unescape|decodeURIComponent)\s*\(',
                r'(?:escape|unescape)\s*\(\s*(?:eval|Function)\s*\(',
                r'String\.fromCharCode\s*\(\s*(?:\d{3,},\s*){3,}',  # Suspicious char codes
                r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}',  # Long hex sequences
                r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}'   # Long unicode sequences
            ],
            'urls': [
                r'data:text/html;base64,',
                r'javascript:[^a-z]',  # Suspicious javascript: URLs
                r'about:blank#',       # Suspicious about:blank usage
                r'jar:file:'           # Suspicious jar protocol
            ],
            'dom': [
                r'<iframe[^>]*style=[^>]*visibility:\s*hidden',
                r'<script[^>]*src=[^>]*\.ru/[^>]*>',  # Suspicious Russian domains
                r'<div[^>]*style=[^>]*position:\s*absolute[^>]*opacity:\s*0'
            ]
        }

    async def check(self, url):
        """Perform enhanced headless browser checks on the URL"""
        result = {
            'redirects': [],
            'final_url': url,
            'security_headers': {},
            'forms_found': [],
            'external_resources': [],
            'javascript_analysis': {
                'errors': [],
                'suspicious_patterns': [],
                'resource_loads': [],
                'ajax_requests': []
            },
            'dom_security': {
                'forms': [],
                'iframes': [],
                'scripts': [],
                'suspicious_elements': []
            },
            'content_security': {
                'mixed_content': [],
                'external_resources': [],
                'inline_scripts': []
            },
            'performance_metrics': {},
            'screenshot_path': None,
            'warnings': [],
            'risk_score': 0,
            'security_rating': 'unknown'
        }

        browser = None
        try:
            browser = await launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-software-rasterizer',
                    '--disable-web-security',
                    '--allow-running-insecure-content'
                ],
                handleSIGINT=False,
                handleSIGTERM=False,
                handleSIGHUP=False
            )
            
            page = await browser.newPage()
            await self._setup_monitoring(page, result)
            
            await page.setViewport({'width': 1920, 'height': 1080})
            await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36')

            try:
                response = await page.goto(url, {
                    'waitUntil': ['networkidle0', 'domcontentloaded'],
                    'timeout': 60000
                })
                
                if not response:
                    raise Exception("Failed to get response from page")

                result['final_url'] = page.url
                await self._analyze_security_headers(response, result)
                await self._analyze_page_content(page, result)
                await self._check_malicious_patterns(page, result)
                await self._analyze_forms(page, result)
                await self._analyze_resources(page, result)
                
                result['performance_metrics'] = await self._collect_performance_metrics(page)

                screenshot_path = os.path.join(self.screenshot_dir, f"{hashlib.md5(url.encode()).hexdigest()}.png")
                await page.screenshot({'path': screenshot_path, 'fullPage': True})
                result['screenshot_path'] = screenshot_path

            except Exception as e:
                result['warnings'].append(f"Page analysis error: {str(e)}")
                result['risk_score'] += 20

            self._calculate_security_score(result)

        except Exception as e:
            result['warnings'].append(f"Browser initialization error: {str(e)}")
            result['risk_score'] = 100
            result['security_rating'] = "Poor"

        finally:
            if browser:
                try:
                    await browser.close()
                except:
                    pass

        return result

    def _is_trusted_domain(self, url):
        """Check if the domain is in the trusted list"""
        try:
            domain = urlparse(url).netloc.lower()
            return domain in self.trusted_domains or any(domain.endswith('.' + td) for td in self.trusted_domains)
        except:
            return False

    async def _setup_monitoring(self, page, result):
        """Set up page monitoring"""
        await page.setRequestInterception(True)

        async def handle_request(req):
            try:
                url = req.url
                resourceType = req.resourceType
                
                if not url.startswith(result['final_url']):
                    result['content_security']['external_resources'].append({
                        'url': url,
                        'type': resourceType
                    })
                
                if url.startswith('http:') and result['final_url'].startswith('https:'):
                    result['content_security']['mixed_content'].append(url)
                
                await req.continue_()
            except Exception as e:
                result['warnings'].append(f"Request handling error: {str(e)}")
                try:
                    await req.continue_()
                except:
                    pass

        async def handle_response(res):
            try:
                if res.request.resourceType in ['xhr', 'fetch']:
                    result['javascript_analysis']['ajax_requests'].append({
                        'url': res.url,
                        'status': res.status
                    })
            except Exception as e:
                result['warnings'].append(f"Response handling error: {str(e)}")

        async def handle_console(msg):
            try:
                if msg.type == 'error':
                    result['javascript_analysis']['errors'].append(str(msg.text))
            except Exception as e:
                result['warnings'].append(f"Console handling error: {str(e)}")

        async def handle_error(err):
            try:
                result['javascript_analysis']['errors'].append(str(err))
            except Exception as e:
                result['warnings'].append(f"Error handling error: {str(e)}")

        page.on('request', lambda req: asyncio.ensure_future(handle_request(req)))
        page.on('response', lambda res: asyncio.ensure_future(handle_response(res)))
        page.on('console', lambda msg: asyncio.ensure_future(handle_console(msg)))
        page.on('pageerror', lambda err: asyncio.ensure_future(handle_error(err)))

    async def _analyze_security_headers(self, response, result):
        """Analyze security headers"""
        try:
            headers = response.headers
            security_headers = {
                'Content-Security-Policy': {'present': False, 'value': None},
                'X-Frame-Options': {'present': False, 'value': None},
                'X-Content-Type-Options': {'present': False, 'value': None},
                'X-XSS-Protection': {'present': False, 'value': None},
                'Strict-Transport-Security': {'present': False, 'value': None},
                'Referrer-Policy': {'present': False, 'value': None}
            }

            for header, config in security_headers.items():
                header_lower = header.lower()
                if header_lower in headers:
                    config['present'] = True
                    config['value'] = headers[header_lower]

            result['security_headers'] = security_headers
        except Exception as e:
            result['warnings'].append(f"Security headers analysis error: {str(e)}")

    async def _analyze_page_content(self, page, result):
        """Analyze page content"""
        try:
            sensitive_inputs = await page.evaluate('''() => {
                return Array.from(document.querySelectorAll('input')).filter(input => {
                    return ['password', 'credit-card', 'card-number', 'ssn'].some(type => 
                        input.type === type || input.name.toLowerCase().includes(type) || input.id.toLowerCase().includes(type)
                    );
                }).map(input => ({
                    type: input.type,
                    name: input.name,
                    id: input.id,
                    secure: input.type === 'password' && input.parentElement.tagName === 'FORM' && window.location.protocol === 'https:'
                }));
            }''')
            
            for input_field in sensitive_inputs:
                if not input_field['secure']:
                    result['warnings'].append(f"Insecure sensitive input field found: {input_field['name']}")
        except Exception as e:
            result['warnings'].append(f"Page content analysis error: {str(e)}")

    async def _check_malicious_patterns(self, page, result):
        """Check for malicious patterns"""
        try:
            content = await page.content()
            
            for pattern_type, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    try:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            result['javascript_analysis']['suspicious_patterns'].append({
                                'type': pattern_type,
                                'pattern': pattern,
                                'match': match.group(0)
                            })
                    except Exception as e:
                        result['warnings'].append(f"Pattern matching error ({pattern}): {str(e)}")
        except Exception as e:
            result['warnings'].append(f"Malicious pattern check error: {str(e)}")

    async def _analyze_forms(self, page, result):
        """Analyze forms"""
        try:
            forms = await page.evaluate('''() => {
                return Array.from(document.forms).map(form => ({
                    action: form.action,
                    method: form.method,
                    has_csrf: Array.from(form.elements).some(el => 
                        el.name && (
                            el.name.toLowerCase().includes('csrf') ||
                            el.name.toLowerCase().includes('token') ||
                            el.name.toLowerCase().includes('nonce')
                        )
                    ),
                    secure_action: form.action.startsWith('https:'),
                    inputs: Array.from(form.elements).map(el => ({
                        type: el.type,
                        name: el.name,
                        id: el.id
                    }))
                }));
            }''')
            
            result['forms_found'] = forms
            
            # Don't penalize trusted domains for missing CSRF tokens
            if not self._is_trusted_domain(result['final_url']):
                for form in forms:
                    if not form.get('secure_action'):
                        result['warnings'].append("Form submitting to non-HTTPS endpoint")
                    if not form.get('has_csrf'):
                        result['warnings'].append("Form missing CSRF protection")
        except Exception as e:
            result['warnings'].append(f"Form analysis error: {str(e)}")

    async def _analyze_resources(self, page, result):
        """Analyze external resources"""
        try:
            resources = await page.evaluate('''() => {
                return {
                    scripts: Array.from(document.scripts).map(s => s.src),
                    styles: Array.from(document.styleSheets).map(s => s.href),
                    images: Array.from(document.images).map(i => i.src),
                    iframes: Array.from(document.getElementsByTagName('iframe')).map(f => f.src)
                };
            }''')
            
            base_domain = urlparse(result['final_url']).netloc
            trusted_cdns = [
                'googleapis.com',
                'gstatic.com',
                'cloudflare.com',
                'jsdelivr.net',
                'unpkg.com',
                'jquery.com',
                'bootstrapcdn.com'
            ]
            
            for resource_type, urls in resources.items():
                for url in urls:
                    if url and not url.startswith('data:'):
                        try:
                            parsed_url = urlparse(urljoin(result['final_url'], url))
                            if parsed_url.netloc and parsed_url.netloc != base_domain:
                                # Don't penalize for loading resources from trusted CDNs
                                if not any(cdn in parsed_url.netloc for cdn in trusted_cdns):
                                    result['content_security']['external_resources'].append({
                                        'type': resource_type,
                                        'url': url
                                    })
                        except Exception as e:
                            result['warnings'].append(f"Resource URL parsing error: {str(e)}")
        except Exception as e:
            result['warnings'].append(f"Resource analysis error: {str(e)}")

    async def _collect_performance_metrics(self, page):
        """Collect performance metrics"""
        try:
            metrics = await page.evaluate('''() => {
                const performance = window.performance;
                const timing = performance.timing;
                return {
                    loadTime: timing.loadEventEnd - timing.navigationStart,
                    domContentLoaded: timing.domContentLoadedEventEnd - timing.navigationStart,
                    firstPaint: performance.getEntriesByType('paint')[0]?.startTime,
                    resourceCount: performance.getEntriesByType('resource').length
                }
            }''')
            return metrics
        except Exception as e:
            return {'error': str(e)}

    def _calculate_security_score(self, result):
        """Calculate security score with adjusted weights for legitimate sites"""
        try:
            score = 0
            is_trusted = self._is_trusted_domain(result['final_url'])
            
            # For trusted domains, we use a much more lenient scoring system
            if is_trusted:
                # Start with a very low base score
                score = 0
                
                # Only consider critical security issues for trusted domains
                critical_issues = [
                    len(result['content_security']['mixed_content']) * 10,  # Mixed content is always bad
                    len([p for p in result['javascript_analysis']['suspicious_patterns'] 
                         if 'eval(' in p['pattern'] or 'document.write(' in p['pattern']]) * 15,  # Only most serious patterns
                    len([e for e in result['javascript_analysis']['errors'] 
                         if 'security' in e.lower() or 'vulnerability' in e.lower()]) * 5  # Only security-related errors
                ]
                score += sum(critical_issues)
                
                # Cap the maximum score for trusted domains
                score = min(30, score)
            else:
                # Standard scoring for non-trusted domains
                base_score = 20
                score += base_score
                
                # Security headers (weighted by importance)
                critical_headers = ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security']
                important_headers = ['X-Content-Type-Options', 'X-XSS-Protection', 'Referrer-Policy']
                
                missing_critical = sum(1 for h in critical_headers 
                                     if not result['security_headers'][h]['present'])
                missing_important = sum(1 for h in important_headers 
                                      if not result['security_headers'][h]['present'])
                
                score += missing_critical * 8
                score += missing_important * 4
                
                # Mixed content (serious security issue)
                score += len(result['content_security']['mixed_content']) * 15
                
                # Suspicious patterns
                score += len(result['javascript_analysis']['suspicious_patterns']) * 10
                
                # JavaScript errors (minor impact)
                score += min(20, len(result['javascript_analysis']['errors']) * 2)
                
                # Form security
                if not is_trusted:
                    score += len([w for w in result['warnings'] if 'CSRF' in w]) * 5
                
                # External resources (with trusted CDN exception)
                external_resources = len([r for r in result['content_security']['external_resources']
                                       if not any(cdn in r['url'] for cdn in [
                                           'googleapis.com',
                                           'gstatic.com',
                                           'cloudflare.com',
                                           'jsdelivr.net',
                                           'unpkg.com',
                                           'jquery.com',
                                           'bootstrapcdn.com'
                                       ])])
                score += min(10, external_resources * 0.5)
            
            result['risk_score'] = min(100, score)
            
            # Adjusted security rating thresholds
            if is_trusted:
                # More lenient ratings for trusted domains
                if score < 10:
                    result['security_rating'] = "Safe"
                elif score < 20:
                    result['security_rating'] = "Low Risk"
                else:
                    result['security_rating'] = "Medium Risk"
            else:
                # Standard ratings for non-trusted domains
                if score < 15:
                    result['security_rating'] = "Safe"
                elif score < 30:
                    result['security_rating'] = "Low Risk"
                elif score < 50:
                    result['security_rating'] = "Medium Risk"
                elif score < 75:
                    result['security_rating'] = "High Risk"
                else:
                    result['security_rating'] = "Critical Risk"
                
        except Exception as e:
            result['warnings'].append(f"Security score calculation error: {str(e)}")
            result['risk_score'] = 100
            result['security_rating'] = "Error"
