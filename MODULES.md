# SENTINAL Scanner Modules

This document provides detailed information about each scanner module in the SENTINAL framework, including their purpose, functionality, and configuration options.

Note: The configuration code blocks shown below are examples. Some reference payload or wordlist files (for example, payloads/xss_payloads.txt). These files are not included by default in this repository; modules will run with built-in logic and defaults unless you supply custom files.

Some modules require optional dependencies (for example, sslyze, selenium, nmap). They are enabled only if the dependency is installed, as handled in backend/scanner/modules/__init__.py.

## Core Modules

### XSS Scanner

**Purpose**: Detect Cross-Site Scripting vulnerabilities in web applications.

**Description**: The XSS Scanner module identifies potential XSS vulnerabilities by injecting various payloads into input fields, URL parameters, and form submissions. It analyzes responses to detect successful script execution.

**Severity**: HIGH

**Features**:
- Detection of reflected, stored, and DOM-based XSS
- Advanced payload generation and mutation
- Context-aware injection techniques
- WAF bypass capabilities

**Configuration**:
```yaml
# Example configuration
xss_scanner:
  payloads_file: "payloads/xss_payloads.txt"
  check_dom: true
  check_reflected: true
  check_stored: true
  bypass_waf: true
  max_payloads: 50
```

### SQL Injection Scanner

**Purpose**: Detect SQL injection vulnerabilities in web applications.

**Description**: The SQL Injection Scanner module identifies potential SQL injection vulnerabilities by injecting various SQL payloads into input fields, URL parameters, and form submissions. It analyzes responses to detect successful SQL injection.

**Severity**: CRITICAL

**Features**:
- Detection of error-based, boolean-based, time-based, and UNION-based SQL injection
- Support for multiple database types (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Blind SQL injection detection
- Automated exploitation capabilities

**Configuration**:
```yaml
# Example configuration
sql_injection:
  payloads_file: "payloads/sql_payloads.txt"
  check_error_based: true
  check_boolean_based: true
  check_time_based: true
  check_union_based: true
  dbms_detection: true
  max_payloads: 30
```

### Command Injection Scanner

**Purpose**: Detect command injection vulnerabilities in web applications.

**Description**: The Command Injection Scanner module identifies potential command injection vulnerabilities by injecting various OS command payloads into input fields, URL parameters, and form submissions. It analyzes responses to detect successful command execution.

**Severity**: CRITICAL

**Features**:
- Detection of OS command injection
- Support for multiple operating systems (Windows, Linux, macOS)
- Blind command injection detection
- Advanced payload generation and mutation

**Configuration**:
```yaml
# Example configuration
command_injection:
  payloads_file: "payloads/command_payloads.txt"
  check_blind: true
  check_output: true
  os_detection: true
  max_payloads: 20
```

### SSRF Scanner

**Purpose**: Detect Server-Side Request Forgery vulnerabilities in web applications.

**Description**: The SSRF Scanner module identifies potential SSRF vulnerabilities by injecting various URL payloads into input fields, URL parameters, and form submissions. It analyzes responses to detect successful server-side requests.

**Severity**: HIGH

**Features**:
- Detection of SSRF vulnerabilities
- Support for multiple protocols (HTTP, HTTPS, FTP, file, etc.)
- Blind SSRF detection
- Advanced payload generation and mutation

**Configuration**:
```yaml
# Example configuration
ssrf_scanner:
  payloads_file: "payloads/ssrf_payloads.txt"
  check_blind: true
  check_output: true
  callback_server: "http://your-callback-server.com"
  max_payloads: 20
```

### RCE Scanner

**Purpose**: Detect Remote Code Execution vulnerabilities in web applications.

**Description**: The RCE Scanner module identifies potential RCE vulnerabilities by injecting various code execution payloads into input fields, URL parameters, and form submissions. It analyzes responses to detect successful code execution.

**Severity**: CRITICAL

**Features**:
- Detection of PHP, Python, Node.js, and other code execution vulnerabilities
- Support for multiple languages and environments
- Blind RCE detection
- Advanced payload generation and mutation

**Configuration**:
```yaml
# Example configuration
rce_scanner:
  payloads_file: "payloads/rce_payloads.txt"
  check_blind: true
  check_output: true
  language_detection: true
  max_payloads: 20
```

### HTTP Scanner

**Purpose**: Analyze HTTP security headers and configurations.

**Description**: The HTTP Scanner module analyzes HTTP responses to identify missing or misconfigured security headers, insecure cookies, and other HTTP-related security issues.

**Severity**: MEDIUM

**Features**:
- Security header analysis
- Cookie security analysis
- CORS configuration analysis
- HTTP method analysis

**Configuration**:
```yaml
# Example configuration
http_scanner:
  check_headers: true
  check_cookies: true
  check_cors: true
  check_methods: true
```

### SSL/TLS Scanner

**Purpose**: Analyze SSL/TLS configurations and vulnerabilities.

**Description**: The SSL/TLS Scanner module analyzes SSL/TLS configurations to identify weak ciphers, outdated protocols, certificate issues, and other SSL/TLS-related security issues.

**Severity**: MEDIUM

**Features**:
- Protocol version detection
- Cipher suite analysis
- Certificate validation
- Known vulnerability detection (BEAST, POODLE, Heartbleed, etc.)

**Configuration**:
```yaml
# Example configuration
ssl_scanner:
  check_protocols: true
  check_ciphers: true
  check_certificate: true
  check_vulnerabilities: true
```

### Information Disclosure Scanner

**Purpose**: Detect sensitive information exposure in web applications.

**Description**: The Information Disclosure Scanner module identifies potential information disclosure vulnerabilities by searching for sensitive files, error messages, comments, and other sources of information leakage.

**Severity**: LOW

**Features**:
- Sensitive file detection
- Error message analysis
- HTML comment analysis
- Directory listing detection

**Configuration**:
```yaml
# Example configuration
info_disclosure:
  check_files: true
  check_errors: true
  check_comments: true
  check_directory_listing: true
  wordlist: "wordlists/sensitive_files.txt"
```

### Content Discovery

**Purpose**: Discover hidden files and directories in web applications.

**Description**: The Content Discovery module identifies hidden files and directories by brute-forcing URLs based on common naming patterns and wordlists.

**Severity**: INFO

**Features**:
- Directory brute-forcing
- File extension brute-forcing
- Pattern-based discovery
- Recursive scanning

**Configuration**:
```yaml
# Example configuration
content_discovery:
  wordlist: "wordlists/directory_list.txt"
  extensions: ["", ".php", ".html", ".txt", ".bak", ".old", ".backup"]
  recursive: true
  max_depth: 3
  follow_redirects: true
```

## Auxiliary Modules

### DNS Enumeration

**Purpose**: Enumerate DNS records and subdomains.

**Description**: The DNS Enumeration module identifies DNS records and subdomains associated with the target domain.

**Features**:
- DNS record enumeration (A, AAAA, MX, NS, TXT, etc.)
- Subdomain brute-forcing
- Zone transfer attempts
- DNS cache analysis

### DNS Inspector

**Purpose**: Analyze DNS configurations and vulnerabilities.

**Description**: The DNS Inspector module analyzes DNS configurations to identify misconfigurations and vulnerabilities.

**Features**:
- DNS configuration analysis
- DNSSEC validation
- DNS cache poisoning tests
- DNS amplification tests

### Link Analyzer

**Purpose**: Analyze links and URLs in web applications.

**Description**: The Link Analyzer module analyzes links and URLs to identify potential security issues and information leakage.

**Features**:
- Link extraction and analysis
- External domain identification
- URL parameter analysis
- JavaScript URL analysis

### Browser Checker

**Purpose**: Check browser-based vulnerabilities and configurations.

**Description**: The Browser Checker module uses a headless browser to identify client-side vulnerabilities and misconfigurations.

**Features**:
- JavaScript execution
- DOM analysis
- Client-side storage analysis
- Browser fingerprinting

### Shodan Scanner

**Purpose**: Leverage Shodan API for external reconnaissance.

**Description**: The Shodan Scanner module uses the Shodan API to gather information about the target from Shodan's database.

**Features**:
- IP information retrieval
- Open port identification
- Service fingerprinting
- Vulnerability correlation

### CVE Mapper

**Purpose**: Map discovered technologies and fingerprints to known CVEs via NVD.

**Description**: The CVE Mapper queries the NVD to find known vulnerabilities relevant to detected products and versions (from headers, banners, and module outputs). It enriches scan results with CVSS scores and references where applicable.

**Features**:
- NVD query and result parsing
- CVSS score and severity mapping
- Reference aggregation and deduplication

**Dependencies**:
- Optional: nvdlib. The module loads only if the dependency is installed.

### Authenticated Scanner

**Purpose**: Execute limited, authenticated workflows against targets that require login.

**Description**: The Authenticated Scanner uses a headless browser to automate login and maintain a session to support authenticated checks and route discovery that can be leveraged by other modules.

**Features**:
- Login form automation
- Session cookie handling
- Simple authenticated crawl

**Dependencies**:
- Optional: selenium, webdriver-manager, and a compatible browser/driver. The module loads only if these dependencies are installed.

### Network Scanner

**Purpose**: Scan network services and ports.

**Description**: The Network Scanner module scans network services and ports to identify open ports, running services, and potential vulnerabilities.

**Features**:
- Port scanning
- Service fingerprinting
- Banner grabbing
- Version detection

### Report Generator

**Purpose**: Generate comprehensive security reports.

**Description**: The Report Generator module combines results from multiple modules to generate comprehensive security reports.

**Features**:
- Vulnerability aggregation
- Severity classification
- Remediation recommendations
- Executive summary generation

## Extending SENTINAL with Custom Modules

You can create custom scanner modules by extending the `BaseScannerModule` class:

```python
from backend.scanner.base_module import BaseScannerModule, ScanConfig, ScanResult, Vulnerability, SeverityLevel

class CustomScanner(BaseScannerModule):
    """Custom vulnerability scanner module."""
    
    def __init__(self):
        super().__init__(
            name="custom_scanner",
            description="Custom vulnerability scanner",
            version="1.0.0",
            author="Your Name",
            scan_type=ScanType.PASSIVE  # or ACTIVE or AGGRESSIVE
        )
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Implement the scanning logic."""
        # Initialize result
        result = self._create_result()
        
        try:
            # Implement your scanning logic here
            # ...
            
            # Add vulnerabilities if found
            if vulnerability_found:
                vuln = Vulnerability(
                    module=self.name,
                    name="Custom Vulnerability",
                    description="Description of the vulnerability",
                    severity=SeverityLevel.MEDIUM,
                    affected_urls=[config.target],
                    evidence={"details": "Evidence details"}
                )
                result.vulnerabilities.append(vuln)
            
            # Mark as successful
            result.success = True
            
        except Exception as e:
            result.success = False
            result.errors.append(str(e))
        
        return result
```

Register your custom module in `backend/scanner/modules/__init__.py`:

```python
from .custom_scanner import CustomScanner

# Update the SCANNER_MODULES dictionary
SCANNER_MODULES = {
    # ... existing modules ...
    "custom_scanner": CustomScanner
}
