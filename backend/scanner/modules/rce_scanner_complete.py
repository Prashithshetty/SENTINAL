"""
Complete implementation of the 4-phase RCE Scanner with:
- Phase 1: Web Crawling and Discovery
- Phase 2: Attack Surface Identification
- Phase 3: JavaScript Analysis
- Phase 4: Comprehensive Fuzzing and Testing

This file contains the additional methods to be added to rce_scanner.py
"""

# These methods should be added to the RCEScanner class in rce_scanner.py

async def _crawl_website(self, start_url: str, config: ScanConfig) -> CrawlResult:
    """
    Phase 1: Discovery and Mapping
    Crawl the website to discover all pages, forms, and parameters.
    """
    result = CrawlResult()
    visited = set()
    to_visit = deque([start_url])
    
    parsed_start = urlparse(start_url)
    base_domain = f"{parsed_start.scheme}://{parsed_start.netloc}"
    
    depth_map = {start_url: 0}
    pages_crawled = 0
    
    async with httpx.AsyncClient(
        verify=False, 
        follow_redirects=True, 
        timeout=self.crawl_timeout
    ) as client:
        while to_visit and pages_crawled < self.max_pages_to_crawl:
            current_url = to_visit.popleft()
            
            if current_url in visited:
                continue
                
            current_depth = depth_map.get(current_url, 0)
            if current_depth > self.max_crawl_depth:
                continue
            
            try:
                # Fetch the page
                resp = await client.get(current_url)
                if resp.status_code != 200:
                    continue
                
                visited.add(current_url)
                result.discovered_urls.add(current_url)
                pages_crawled += 1
                
                # Only process HTML content
                content_type = resp.headers.get("content-type", "").lower()
                if "text/html" not in content_type:
                    continue
                
                html = resp.text
                
                # Extract links
                link_extractor = LinkExtractor(current_url)
                link_extractor.feed(html)
                
                # Add discovered links to queue
                for link in link_extractor.links:
                    parsed_link = urlparse(link)
                    
                    # Only crawl same domain
                    if parsed_link.netloc != parsed_start.netloc:
                        continue
                    
                    # Remove fragments
                    clean_link = urlunparse((
                        parsed_link.scheme,
                        parsed_link.netloc,
                        parsed_link.path,
                        parsed_link.params,
                        parsed_link.query,
                        ""  # no fragment
                    ))
                    
                    if clean_link not in visited and clean_link not in depth_map:
                        depth_map[clean_link] = current_depth + 1
                        to_visit.append(clean_link)
                
                # Collect JavaScript files
                result.js_files.update(link_extractor.js_files)
                
                # Extract forms
                form_parser = FormParser()
                form_parser.feed(html)
                result.forms.extend(form_parser.forms)
                
                # Extract URL parameters
                parsed = urlparse(current_url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param_name, values in params.items():
                        if param_name not in result.url_parameters:
                            result.url_parameters[param_name] = []
                        result.url_parameters[param_name].extend(values)
                
            except Exception as e:
                # Log error but continue crawling
                continue
    
    return result


async def _analyze_javascript_files(self, js_files: List[str], base_url: str) -> List[str]:
    """
    Phase 2: JavaScript Analysis
    Analyze JavaScript files to find hidden API endpoints and parameters.
    """
    discovered_endpoints = []
    
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        for js_url in list(js_files)[:20]:  # Limit to 20 JS files
            try:
                resp = await client.get(js_url)
                if resp.status_code != 200:
                    continue
                
                js_content = resp.text
                
                # Search for endpoint patterns
                for pattern in self.js_endpoint_patterns:
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    for match in matches:
                        # Extract the URL from the match
                        if isinstance(match, tuple):
                            endpoint = match[0] if match else ""
                        else:
                            endpoint = match
                        
                        # Clean and validate endpoint
                        endpoint = endpoint.strip()
                        if not endpoint or len(endpoint) < 2:
                            continue
                        
                        # Make absolute URL
                        if endpoint.startswith('/'):
                            full_url = urljoin(base_url, endpoint)
                        elif endpoint.startswith('http'):
                            full_url = endpoint
                        else:
                            continue
                        
                        # Check if it's in scope
                        parsed_endpoint = urlparse(full_url)
                        parsed_base = urlparse(base_url)
                        if parsed_endpoint.netloc == parsed_base.netloc:
                            discovered_endpoints.append(full_url)
                
            except Exception:
                continue
    
    return list(set(discovered_endpoints))


def _identify_attack_surfaces(self, crawl_result: CrawlResult, base_url: str) -> List[AttackSurface]:
    """
    Phase 2: Identify Attack Surfaces
    Convert discovered elements into testable attack surfaces.
    """
    surfaces = []
    
    # 1. Forms as attack surfaces
    for form in crawl_result.forms:
        action = form.action if form.action else base_url
        if not action.startswith(('http://', 'https://')):
            action = urljoin(base_url, action)
        
        surface = AttackSurface(
            url=action,
            surface_type="form",
            parameters=form.fields,
            method=form.method,
            metadata={"enctype": form.enctype}
        )
        surfaces.append(surface)
    
    # 2. URL parameters as attack surfaces
    for url in crawl_result.discovered_urls:
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            param_dict = {k: v[0] if v else "" for k, v in params.items()}
            
            surface = AttackSurface(
                url=url,
                surface_type="url_param",
                parameters=param_dict,
                method="GET",
                metadata={}
            )
            surfaces.append(surface)
    
    # 3. API endpoints from JS as attack surfaces
    for endpoint in crawl_result.api_endpoints:
        surface = AttackSurface(
            url=endpoint,
            surface_type="js_endpoint",
            parameters={},
            method="GET",
            metadata={"source": "javascript"}
        )
        surfaces.append(surface)
    
    return surfaces


async def _fuzz_attack_surface(
    self, 
    surface: AttackSurface, 
    config: ScanConfig,
    baseline_has_errors: bool
) -> List[Vulnerability]:
    """
    Phase 3: Active Fuzzing
    Test an attack surface with various payloads.
    """
    vulnerabilities = []
    
    # Test with SSTI payloads
    ssti_vulns = await self._test_surface_ssti(surface, baseline_has_errors)
    vulnerabilities.extend(ssti_vulns)
    
    # Test with command injection payloads
    cmd_vulns = await self._test_surface_command_injection(surface)
    vulnerabilities.extend(cmd_vulns)
    
    # Test with time-based payloads
    time_vulns = await self._test_surface_time_based(surface)
    vulnerabilities.extend(time_vulns)
    
    return vulnerabilities


async def _test_surface_ssti(
    self, 
    surface: AttackSurface,
    baseline_has_errors: bool
) -> List[Vulnerability]:
    """Test attack surface for SSTI vulnerabilities."""
    vulnerabilities = []
    
    if not surface.parameters:
        # No parameters to test
        return vulnerabilities
    
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        for param_name in list(surface.parameters.keys())[:5]:  # Limit params tested
            for ptype, payload, expected in self.ssti_payloads[:3]:  # Limit payloads
                test_params = surface.parameters.copy()
                test_params[param_name] = payload
                
                try:
                    if surface.method == "POST":
                        if surface.metadata.get("enctype") == "application/json":
                            resp = await client.post(surface.url, json=test_params)
                        else:
                            resp = await client.post(surface.url, data=test_params)
                    else:
                        resp = await client.get(surface.url, params=test_params)
                    
                    analysis = self._analyze_ssti_response(resp.text, expected)
                    
                    if analysis["is_vulnerable"]:
                        if baseline_has_errors:
                            analysis["confidence"] *= 0.8
                        
                        severity = SeverityLevel.CRITICAL if "sentinel_evaluated" in analysis["indicators"] else SeverityLevel.HIGH
                        
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"SSTI in {surface.surface_type} parameter '{param_name}'",
                                description=(
                                    f"Parameter '{param_name}' in {surface.surface_type} appears to be evaluated "
                                    "by a server-side template engine, indicating a potential RCE vector."
                                ),
                                severity=severity,
                                confidence=analysis["confidence"],
                                affected_urls=[surface.url],
                                evidence={
                                    "surface_type": surface.surface_type,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "payload_type": ptype,
                                    "expected": expected,
                                    "indicators": analysis.get("indicators", []),
                                    "engine_guess": analysis.get("engine_guess"),
                                    "response_snippet": resp.text[:500] if resp.text else "",
                                    "method": surface.method,
                                },
                                **self.SSTI_VULN_TEMPLATE
                            )
                        )
                        break  # Stop testing this param after finding vuln
                
                except Exception:
                    continue
    
    return vulnerabilities


async def _test_surface_command_injection(self, surface: AttackSurface) -> List[Vulnerability]:
    """Test attack surface for command injection vulnerabilities."""
    vulnerabilities = []
    
    if not surface.parameters:
        return vulnerabilities
    
    # Command injection indicators in response
    cmd_indicators = [
        "root:", "bin/bash", "uid=", "gid=", "groups=",
        "Windows", "Volume Serial Number", "Directory of"
    ]
    
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        for param_name in list(surface.parameters.keys())[:3]:
            for payload in self.rce_payload_categories["command_injection"][:3]:
                test_params = surface.parameters.copy()
                test_params[param_name] = payload
                
                try:
                    if surface.method == "POST":
                        resp = await client.post(surface.url, data=test_params)
                    else:
                        resp = await client.get(surface.url, params=test_params)
                    
                    # Check for command execution indicators
                    response_text = resp.text.lower() if resp.text else ""
                    matched_indicators = [ind for ind in cmd_indicators if ind.lower() in response_text]
                    
                    if matched_indicators:
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"Potential Command Injection in {surface.surface_type} parameter '{param_name}'",
                                description=(
                                    f"Parameter '{param_name}' may be vulnerable to command injection. "
                                    "Response contains command execution indicators."
                                ),
                                severity=SeverityLevel.CRITICAL,
                                confidence=0.85,
                                affected_urls=[surface.url],
                                evidence={
                                    "surface_type": surface.surface_type,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "indicators": matched_indicators,
                                    "response_snippet": resp.text[:500] if resp.text else "",
                                    "method": surface.method,
                                },
                                remediation=(
                                    "Never pass user input directly to system commands. "
                                    "Use parameterized APIs, input validation, and sandboxing."
                                ),
                                references=[
                                    "https://owasp.org/www-community/attacks/Command_Injection",
                                    "https://cwe.mitre.org/data/definitions/78.html",
                                ],
                                cwe_ids=["CWE-78"],
                            )
                        )
                        break
                
                except Exception:
                    continue
    
    return vulnerabilities


async def _test_surface_time_based(self, surface: AttackSurface) -> List[Vulnerability]:
    """Test attack surface for time-based vulnerabilities."""
    vulnerabilities = []
    
    if not surface.parameters:
        return vulnerabilities
    
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        for param_name in list(surface.parameters.keys())[:2]:
            # Get baseline timing
            baseline_times = []
            for _ in range(2):
                try:
                    start = time.time()
                    if surface.method == "POST":
                        await client.post(surface.url, data=surface.parameters)
                    else:
                        await client.get(surface.url, params=surface.parameters)
                    baseline_times.append(time.time() - start)
                except Exception:
                    continue
            
            if not baseline_times:
                continue
            
            avg_baseline = sum(baseline_times) / len(baseline_times)
            
            # Test time-based payloads
            for payload in self.rce_payload_categories["time_based"][:2]:
                test_params = surface.parameters.copy()
                test_params[param_name] = payload
                
                try:
                    start = time.time()
                    if surface.method == "POST":
                        await client.post(surface.url, data=test_params)
                    else:
                        await client.get(surface.url, params=test_params)
                    elapsed = time.time() - start
                    
                    # Check if response was significantly delayed
                    if elapsed > (avg_baseline + 4.5):  # At least 4.5 seconds delay
                        vulnerabilities.append(
                            Vulnerability(
                                module=self.name,
                                name=f"Time-Based Injection in {surface.surface_type} parameter '{param_name}'",
                                description=(
                                    f"Parameter '{param_name}' exhibits time-based behavior indicating "
                                    "potential SQL injection or command injection vulnerability."
                                ),
                                severity=SeverityLevel.HIGH,
                                confidence=0.75,
                                affected_urls=[surface.url],
                                evidence={
                                    "surface_type": surface.surface_type,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "baseline_time": f"{avg_baseline:.2f}s",
                                    "delayed_time": f"{elapsed:.2f}s",
                                    "delay_difference": f"{elapsed - avg_baseline:.2f}s",
                                    "method": surface.method,
                                },
                                remediation=(
                                    "Use parameterized queries for databases. "
                                    "Validate and sanitize all user input. "
                                    "Implement proper error handling without exposing timing information."
                                ),
                                references=[
                                    "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                                    "https://cwe.mitre.org/data/definitions/89.html",
                                ],
                                cwe_ids=["CWE-89", "CWE-78"],
                            )
                        )
                        break
                
                except Exception:
                    continue
    
    return vulnerabilities


async def _generate_comprehensive_report(
    self,
    crawl_result: CrawlResult,
    attack_surfaces: List[AttackSurface],
    vulnerabilities: List[Vulnerability]
) -> Dict[str, Any]:
    """
    Phase 4: Generate comprehensive report with all findings.
    """
    report = {
        "discovery_phase": {
            "urls_discovered": len(crawl_result.discovered_urls),
            "forms_found": len(crawl_result.forms),
            "url_parameters_found": len(crawl_result.url_parameters),
            "js_files_analyzed": len(crawl_result.js_files),
            "api_endpoints_discovered": len(crawl_result.api_endpoints),
        },
        "attack_surface_phase": {
            "total_surfaces": len(attack_surfaces),
            "surface_types": {},
        },
        "testing_phase": {
            "vulnerabilities_found": len(vulnerabilities),
            "by_severity": {},
            "by_type": {},
        },
        "discovered_urls": list(crawl_result.discovered_urls)[:50],  # Limit for report size
        "api_endpoints": crawl_result.api_endpoints[:20],
    }
    
    # Count surface types
    for surface in attack_surfaces:
        stype = surface.surface_type
        report["attack_surface_phase"]["surface_types"][stype] = \
            report["attack_surface_phase"]["surface_types"].get(stype, 0) + 1
    
    # Count vulnerabilities by severity
    for vuln in vulnerabilities:
        severity = vuln.severity.value
        report["testing_phase"]["by_severity"][severity] = \
            report["testing_phase"]["by_severity"].get(severity, 0) + 1
        
        # Extract vulnerability type from name
        vuln_type = vuln.name.split()[0]  # First word usually indicates type
        report["testing_phase"]["by_type"][vuln_type] = \
            report["testing_phase"]["by_type"].get(vuln_type, 0) + 1
    
    return report
