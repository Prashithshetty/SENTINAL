# 🛡️ SENTINEL - AI-Powered Vulnerability Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104.1-009688?style=for-the-badge&logo=fastapi)
![AI](https://img.shields.io/badge/AI-Gemini%202.0%20Flash-purple?style=for-the-badge&logo=google)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**A comprehensive, AI-enhanced vulnerability scanner with intelligent analysis and actionable insights**

[Features](#-features) • [Installation](#-installation) • [API Documentation](#-api-documentation) • [Usage](#-usage) • [Modules](#-scanner-modules) • [Quick Start](#-quick-start)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [API Documentation](#-api-documentation)
- [Scanner Modules](#-scanner-modules)
- [Comprehensive Scanning](#-comprehensive-scanning)
- [Usage Examples](#-usage-examples)
- [AI Integration](#-ai-integration)
- [Security Considerations](#-security-considerations)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Overview

SENTINEL is an advanced, enterprise-grade vulnerability scanner that combines traditional security testing with cutting-edge **Gemini 2.0 Flash AI** capabilities. It provides comprehensive security assessments through a powerful RESTful API with intelligent analysis, making vulnerability detection and remediation more effective than ever.

### Why SENTINEL?

- **🤖 AI-Powered Intelligence**: Leverages Google's Gemini 2.0 Flash for context-aware vulnerability analysis
- **🔍 Comprehensive Coverage**: 11+ specialized scanner modules for thorough security assessment
- **⚡ High Performance**: Asynchronous scanning with concurrent module execution
- **📊 Real-time Monitoring**: Live scan progress tracking via API
- **🎯 Smart Prioritization**: AI-driven risk assessment and vulnerability ranking
- **💡 Actionable Insights**: Detailed remediation recommendations with step-by-step guidance
- **🌐 Modern API**: RESTful API with OpenAPI/Swagger documentation
- **🔒 Enterprise Ready**: Rate limiting, authentication support, and production-ready architecture

---

## ✨ Features

### Core Capabilities

- **Multi-Module Scanning**: Execute multiple security tests simultaneously
- **Flexible Scan Types**: Passive, Active, and Aggressive scanning modes
- **Real-time Progress**: Track scan execution with live progress updates
- **Vulnerability Database**: SQLite-based storage with comprehensive vulnerability tracking
- **AI Analysis**: Intelligent vulnerability explanations and risk assessments
- **Export & Reporting**: Generate detailed security reports
- **Rate Limiting**: Built-in protection against overwhelming target systems
- **Concurrent Scanning**: Support for multiple simultaneous scans

### AI-Enhanced Features

- **Vulnerability Explanations**: Natural language descriptions of security issues
- **Risk Assessment**: AI-powered security posture evaluation
- **Remediation Guidance**: Step-by-step fixing instructions
- **Priority Recommendations**: Focus on what matters most
- **Compliance Mapping**: Regulatory requirement alignment

---

## 🏗️ Architecture

```
SENTINEL/
├── backend/
│   ├── api/                    # FastAPI application
│   │   ├── main.py            # API endpoints & routing
│   │   └── models/            # Database models
│   │       ├── scan.py        # Scan model
│   │       ├── vulnerability.py # Vulnerability model
│   │       └── report.py      # Report model
│   ├── core/                   # Core functionality
│   │   ├── config.py          # Configuration management
│   │   ├── database.py        # Database setup
│   │   └── ai_analyzer.py     # Gemini AI integration
│   └── scanner/                # Scanner engine
│       ├── engine.py          # Orchestration engine
│       ├── base_module.py     # Base scanner class
│       └── modules/           # Scanner modules
│           ├── http_scanner.py
│           ├── dns_enumeration.py
│           ├── ssl_scanner.py
│           ├── network_scanner.py
│           ├── xss_scanner.py
│           ├── sql_injection.py
│           ├── command_injection.py
│           ├── content_discovery.py
│           ├── info_disclosure.py
│           ├── cve_mapper.py
│           └── authenticated_scanner.py
├── logs/                       # Application logs
├── reports/                    # Generated reports
├── scan_results/              # Scan data storage
├── .env                       # Environment configuration
├── requirements.txt           # Python dependencies
└── run_api.py                # Server startup script
```

---

## 🔧 Installation

### Prerequisites

- **Python**: 3.8 or higher
- **pip**: Python package manager
- **Gemini API Key**: Free at [Google AI Studio](https://makersuite.google.com/app/apikey)

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/SENTINEL.git
   cd SENTINEL
   ```

2. **Create virtual environment** (recommended)
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # Linux/Mac
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   
   Create a `.env` file in the root directory:
   ```env
   # API Configuration
   API_HOST=0.0.0.0
   API_PORT=8000
   DEBUG=false
   
   # AI Integration
   GEMINI_API_KEY=your_gemini_api_key_here
   
   # Security Settings
   ENABLE_INJECTION_TESTING=true
   ALLOW_ACTIVE_SCANNING=true
   REQUIRE_CONSENT=false
   
   # External API Keys
   SHODAN_API_KEY=your_shodan_api_key_here
   
   # Scan Configuration
   MAX_CONCURRENT_SCANS=5
   SCAN_TIMEOUT_SECONDS=3600
   RATE_LIMIT_REQUESTS_PER_MINUTE=60
   MAX_SCAN_DEPTH=3
   
   # Database
   DATABASE_URL=sqlite:///./sentinel.db
   ```

5. **Initialize the database**
   ```bash
   python -c "from backend.core.database import init_db; init_db()"
   ```

6. **Start the server**
   ```bash
   python run_api.py
   ```

7. **Access the API**
   - **API Base URL**: http://localhost:8000
   - **Interactive API Documentation (Swagger)**: http://localhost:8000/docs
   - **Alternative API Documentation (ReDoc)**: http://localhost:8000/redoc

---

## 🚀 Quick Start

### Interactive Command Line Interface

SENTINEL includes a powerful command-line interface for easy testing:

```bash
# Run the interactive CLI
python sentinal.py
```

**Available Options:**
- **10. Comprehensive Scan** - Full reconnaissance + vulnerability scanning (all 11 modules)
- **11. Shodan Search** - Internet reconnaissance via Shodan
- **12. DNS Inspector** - DNS enumeration and analysis
- **13. Link Analyzer** - Link and content analysis
- **14. Browser Checker** - Headless browser analysis
- **15. Generate Report** - Combined reconnaissance report

### Comprehensive Scan Example

```bash
# Start comprehensive scan
python sentinal.py
# Select option 10
# Enter target: example.com
```

**What happens during comprehensive scan:**
1. **Stage 1**: Reconnaissance (DNS, Shodan, Browser, Link analysis)
2. **Stage 2**: Active vulnerability scanning (all 11 modules)
3. **Stage 3**: AI-powered analysis and reporting

### API Quick Start

```bash
# Create a comprehensive scan via API
curl -X POST "http://localhost:8000/api/v1/scans" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "modules": [
      "http_scanner", "dns_enumeration", "ssl_scanner", 
      "network_scanner", "content_discovery", "info_disclosure",
      "sql_injection", "xss_scanner", "command_injection",
      "cve_mapper", "authenticated_scanner"
    ],
    "scan_type": "active"
  }'

# Check scan status
curl "http://localhost:8000/api/v1/scans/{scan_id}"

# Get results
curl "http://localhost:8000/api/v1/scans/{scan_id}/results"

# Get AI analysis
curl -X POST "http://localhost:8000/api/v1/scans/{scan_id}/analyze"
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `API_HOST` | API server host | `0.0.0.0` | No |
| `API_PORT` | API server port | `8000` | No |
| `DEBUG` | Enable debug mode | `false` | No |
| `GEMINI_API_KEY` | Gemini AI API key | - | **Yes** |
| `SHODAN_API_KEY` | Shodan API key for reconnaissance | - | **Yes** |
| `ENABLE_INJECTION_TESTING` | Allow injection tests | `true` | No |
| `ALLOW_ACTIVE_SCANNING` | Enable active scanning | `true` | No |
| `REQUIRE_CONSENT` | Require scan consent | `false` | No |
| `MAX_CONCURRENT_SCANS` | Max parallel scans | `5` | No |
| `SCAN_TIMEOUT_SECONDS` | Scan timeout | `3600` | No |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | Rate limit | `60` | No |
| `MAX_SCAN_DEPTH` | Max crawl depth | `3` | No |
| `DATABASE_URL` | Database connection | `sqlite:///./sentinel.db` | No |

### Scan Types

- **PASSIVE**: Non-intrusive information gathering (safe for production)
- **ACTIVE**: Active probing and testing (requires authorization)
- **AGGRESSIVE**: Intensive testing with exploitation attempts (use with caution)

---

## 📚 API Documentation

### Base URL

```
http://localhost:8000
```

### Interactive Documentation

SENTINEL provides interactive API documentation powered by Swagger UI and ReDoc:

- **Swagger UI**: http://localhost:8000/docs - Try out API endpoints directly from your browser
- **ReDoc**: http://localhost:8000/redoc - Clean, responsive API documentation

### Authentication

Currently, the API does not require authentication. In production, implement proper authentication mechanisms (JWT, API keys, OAuth2, etc.).

---

## 🔌 API Endpoints

### System Endpoints

#### Health Check
```http
GET /health
```

**Description**: Check API health and status

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "active_scans": 2,
  "modules_loaded": 10
}
```

#### Root Endpoint
```http
GET /
```

**Description**: Get API information

**Response**:
```json
{
  "name": "SENTINEL Vulnerability Scanner",
  "version": "1.0.0",
  "status": "operational",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

---

### Scanner Module Endpoints

#### List All Modules
```http
GET /api/v1/modules
```

**Description**: Get all available scanner modules

**Response**:
```json
{
  "modules": {
    "http_scanner": {
      "name": "HTTP Security Scanner",
      "description": "Analyzes HTTP headers and security configurations",
      "scan_type": "passive",
      "requires_auth": false
    },
    "dns_enumeration": {
      "name": "DNS Enumeration",
      "description": "Discovers DNS records and subdomains",
      "scan_type": "passive",
      "requires_auth": false
    }
  },
  "total": 10
}
```

#### Get Module Information
```http
GET /api/v1/modules/{module_name}
```

**Parameters**:
- `module_name` (path): Name of the module

**Response**:
```json
{
  "name": "XSS Scanner",
  "description": "Detects Cross-Site Scripting vulnerabilities",
  "scan_type": "active",
  "requires_auth": false,
  "capabilities": ["xss_detection", "payload_testing"],
  "version": "1.0.0"
}
```

---

### Scan Management Endpoints

#### Create New Scan
```http
POST /api/v1/scans
```

**Description**: Create and start a new vulnerability scan

**Request Body**:
```json
{
  "target": "https://example.com",
  "modules": [
    "http_scanner",
    "dns_enumeration",
    "ssl_scanner",
    "xss_scanner"
  ],
  "scan_type": "passive",
  "config": {
    "timeout": 3600,
    "rate_limit": 10,
    "max_depth": 3
  },
  "auth": {
    "username": "admin",
    "password": "password"
  },
  "metadata": {
    "description": "Security assessment",
    "tags": ["production", "web-app"]
  }
}
```

**Parameters**:
- `target` (required): Target URL or IP address
- `modules` (required): Array of module names to execute
- `scan_type` (optional): `passive`, `active`, or `aggressive` (default: `passive`)
- `config` (optional): Scan configuration object
- `auth` (optional): Authentication credentials
- `metadata` (optional): Additional metadata

**Response**:
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "created",
  "target": "https://example.com",
  "modules": ["http_scanner", "dns_enumeration", "ssl_scanner", "xss_scanner"],
  "message": "Scan created and queued for execution"
}
```

#### List All Scans
```http
GET /api/v1/scans?skip=0&limit=10&status=completed&target=example.com
```

**Query Parameters**:
- `skip` (optional): Number of records to skip (default: 0)
- `limit` (optional): Maximum records to return (default: 10, max: 100)
- `status` (optional): Filter by status (`pending`, `running`, `completed`, `failed`, `cancelled`)
- `target` (optional): Filter by target (partial match)

**Response**:
```json
{
  "total": 45,
  "skip": 0,
  "limit": 10,
  "scans": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "target": "https://example.com",
      "status": "completed",
      "scan_type": "passive",
      "created_at": "2024-01-15T10:00:00.000Z",
      "started_at": "2024-01-15T10:00:05.000Z",
      "completed_at": "2024-01-15T10:15:30.000Z",
      "total_vulnerabilities": 12,
      "critical_count": 2,
      "high_count": 3,
      "medium_count": 5,
      "low_count": 2,
      "info_count": 0
    }
  ]
}
```

#### Get Scan Details
```http
GET /api/v1/scans/{scan_id}
```

**Parameters**:
- `scan_id` (path): Scan identifier

**Response**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "target": "https://example.com",
  "status": "running",
  "progress": 65.5,
  "current_module": "xss_scanner",
  "started_at": "2024-01-15T10:00:05.000Z",
  "modules": ["http_scanner", "dns_enumeration", "ssl_scanner", "xss_scanner"],
  "scan_type": "passive",
  "config": {
    "timeout": 3600,
    "rate_limit": 10,
    "max_depth": 3
  }
}
```

#### Get Scan Results
```http
GET /api/v1/scans/{scan_id}/results
```

**Parameters**:
- `scan_id` (path): Scan identifier

**Response**:
```json
{
  "scan": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "target": "https://example.com",
    "status": "completed",
    "started_at": "2024-01-15T10:00:05.000Z",
    "completed_at": "2024-01-15T10:15:30.000Z",
    "duration": "15m 25s"
  },
  "vulnerabilities": [
    {
      "id": "vuln-001",
      "module": "xss_scanner",
      "name": "Reflected XSS",
      "description": "Cross-site scripting vulnerability found in search parameter",
      "severity": "high",
      "confidence": 0.95,
      "cvss_score": 7.5,
      "cve_ids": [],
      "cwe_ids": ["CWE-79"],
      "affected_urls": ["https://example.com/search?q=<script>"],
      "evidence": {
        "payload": "<script>alert(1)</script>",
        "response": "Reflected in HTML context"
      },
      "remediation": "Implement proper input validation and output encoding",
      "references": [
        "https://owasp.org/www-community/attacks/xss/"
      ]
    }
  ],
  "modules": [
    {
      "module_name": "http_scanner",
      "started_at": "2024-01-15T10:00:05.000Z",
      "completed_at": "2024-01-15T10:02:30.000Z",
      "success": true,
      "vulnerabilities_found": 3,
      "errors": [],
      "warnings": ["Missing security header: X-Frame-Options"],
      "info": ["Server: nginx/1.18.0"],
      "statistics": {
        "requests_made": 15,
        "headers_analyzed": 12
      }
    }
  ]
}
```

#### Get Scan Vulnerabilities
```http
GET /api/v1/scans/{scan_id}/vulnerabilities?severity=high&module=xss_scanner&skip=0&limit=50
```

**Parameters**:
- `scan_id` (path): Scan identifier
- `severity` (query, optional): Filter by severity (`critical`, `high`, `medium`, `low`, `info`)
- `module` (query, optional): Filter by module name
- `skip` (query, optional): Number of records to skip (default: 0)
- `limit` (query, optional): Maximum records to return (default: 50, max: 200)

**Response**:
```json
{
  "total": 8,
  "skip": 0,
  "limit": 50,
  "vulnerabilities": [
    {
      "id": "vuln-001",
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "module": "xss_scanner",
      "name": "Reflected XSS",
      "severity": "high",
      "confidence": 0.95,
      "cvss_score": 7.5,
      "risk_score": 85.5,
      "affected_urls": ["https://example.com/search"],
      "timestamp": "2024-01-15T10:10:00.000Z"
    }
  ]
}
```

#### Cancel Scan
```http
DELETE /api/v1/scans/{scan_id}
```

**Parameters**:
- `scan_id` (path): Scan identifier

**Response**:
```json
{
  "message": "Scan 550e8400-e29b-41d4-a716-446655440000 cancelled successfully"
}
```

#### Get Active Scans
```http
GET /api/v1/scans/active
```

**Description**: Get list of currently running scans

**Response**:
```json
{
  "active_scans": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "target": "https://example.com",
      "status": "running",
      "progress": 45.5,
      "modules": ["http_scanner", "xss_scanner"],
      "started_at": "2024-01-15T10:00:05.000Z"
    }
  ],
  "total": 1
}
```

#### Get Scan History
```http
GET /api/v1/scans/history?limit=10
```

**Query Parameters**:
- `limit` (optional): Maximum records to return (default: 10, max: 50)

**Response**:
```json
{
  "history": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "target": "https://example.com",
      "status": "completed",
      "modules": ["http_scanner", "xss_scanner"],
      "started_at": "2024-01-15T10:00:05.000Z",
      "completed_at": "2024-01-15T10:15:30.000Z",
      "total_vulnerabilities": 12,
      "vulnerabilities_by_severity": {
        "critical": 2,
        "high": 3,
        "medium": 5,
        "low": 2,
        "info": 0
      }
    }
  ],
  "limit": 10
}
```

---

### Statistics Endpoints

#### Get Vulnerability Statistics
```http
GET /api/v1/stats/vulnerabilities
```

**Description**: Get aggregated vulnerability statistics

**Response**:
```json
{
  "severity_distribution": {
    "critical": 15,
    "high": 42,
    "medium": 78,
    "low": 123,
    "info": 56
  },
  "top_modules": [
    {
      "module": "xss_scanner",
      "count": 45
    },
    {
      "module": "sql_injection",
      "count": 32
    }
  ],
  "common_vulnerabilities": [
    {
      "name": "Missing Security Headers",
      "count": 89
    },
    {
      "name": "Reflected XSS",
      "count": 34
    }
  ]
}
```

---

### AI Analysis Endpoints

#### Analyze Scan with AI
```http
POST /api/v1/scans/{scan_id}/analyze
```

**Parameters**:
- `scan_id` (path): Scan identifier

**Description**: Get comprehensive AI analysis of scan results

**Response**:
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "analysis": {
    "executive_summary": "The scan identified 12 vulnerabilities across multiple categories. Critical issues include SQL injection and XSS vulnerabilities that require immediate attention.",
    "risk_assessment": {
      "overall_risk": "high",
      "risk_score": 8.5,
      "factors": [
        "Multiple high-severity vulnerabilities",
        "Public-facing application",
        "Sensitive data exposure risk"
      ]
    },
    "priority_actions": [
      {
        "priority": 1,
        "action": "Fix SQL injection in login form",
        "severity": "critical",
        "estimated_effort": "2-4 hours"
      },
      {
        "priority": 2,
        "action": "Implement XSS protection in search functionality",
        "severity": "high",
        "estimated_effort": "4-6 hours"
      }
    ],
    "recommendations": [
      "Implement Content Security Policy (CSP)",
      "Enable security headers (X-Frame-Options, X-Content-Type-Options)",
      "Use parameterized queries for database operations",
      "Implement input validation and output encoding"
    ],
    "compliance_notes": {
      "owasp_top_10": ["A03:2021 - Injection", "A07:2021 - XSS"],
      "pci_dss": ["Requirement 6.5.1", "Requirement 6.5.7"]
    }
  }
}
```

#### Explain Vulnerability with AI
```http
POST /api/v1/vulnerabilities/{vuln_id}/explain
```

**Parameters**:
- `vuln_id` (path): Vulnerability identifier

**Description**: Get AI-powered explanation of a specific vulnerability

**Response**:
```json
{
  "vulnerability_id": "vuln-001",
  "explanation": {
    "description": "This Cross-Site Scripting (XSS) vulnerability allows attackers to inject malicious scripts into web pages viewed by other users.",
    "impact": "Attackers can steal session cookies, redirect users to malicious sites, or modify page content.",
    "exploitation": "An attacker can craft a malicious URL containing JavaScript code.",
    "remediation": {
      "immediate": [
        "Implement output encoding for all user-supplied data",
        "Use Content Security Policy (CSP) headers",
        "Enable HttpOnly flag on session cookies"
      ],
      "long_term": [
        "Implement a Web Application Firewall (WAF)",
        "Regular security testing and code reviews"
      ]
    },
    "references": [
      "https://owasp.org/www-community/attacks/xss/"
    ]
  }
}
```

---

## 🔍 Scanner Modules

SENTINEL includes 11 specialized scanner modules:

### 1. HTTP Security Scanner
- **Type**: Passive
- **Module Name**: `http_scanner`
- **Description**: Analyzes HTTP headers and security configurations
- **Detects**:
  - Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
  - Insecure cookie configurations
  - Server information disclosure
  - HTTP methods allowed

### 2. DNS Enumeration
- **Type**: Passive
- **Module Name**: `dns_enumeration`
- **Description**: Discovers DNS records and subdomains
- **Detects**:
  - DNS records (A, AAAA, MX, TXT, etc.)
  - Subdomain enumeration
  - Zone transfer vulnerabilities
  - DNS misconfigurations

### 3. SSL/TLS Scanner
- **Type**: Passive
- **Module Name**: `ssl_scanner`
- **Description**: Analyzes SSL/TLS configurations
- **Detects**:
  - Weak cipher suites
  - Certificate issues
  - Protocol vulnerabilities
  - SSL/TLS misconfigurations

### 4. Network Scanner
- **Type**: Active
- **Module Name**: `network_scanner`
- **Description**: Port and service discovery
- **Detects**:
  - Open ports
  - Running services
  - Service versions
  - Network topology

### 5. XSS Scanner
- **Type**: Active
- **Module Name**: `xss_scanner`
- **Description**: Detects Cross-Site Scripting vulnerabilities
- **Detects**:
  - Reflected XSS
  - Stored XSS
  - DOM-based XSS
  - XSS in various contexts

### 6. SQL Injection Scanner
- **Type**: Active
- **Module Name**: `sql_injection`
- **Description**: Identifies SQL injection vulnerabilities
- **Detects**:
  - Error-based SQL injection
  - Boolean-based blind SQL injection
  - Time-based blind SQL injection
  - Union-based SQL injection

### 7. Command Injection Scanner
- **Type**: Active
- **Module Name**: `command_injection`
- **Description**: Detects OS command injection vulnerabilities
- **Detects**:
  - Direct command injection
  - Blind command injection
  - Command chaining
  - Shell metacharacter injection

### 8. Content Discovery
- **Type**: Active
- **Module Name**: `content_discovery`
- **Description**: Discovers hidden files and directories
- **Detects**:
  - Backup files
  - Configuration files
  - Admin panels
  - Hidden directories

### 9. Information Disclosure Scanner
- **Type**: Passive
- **Module Name**: `info_disclosure`
- **Description**: Identifies sensitive information exposure
- **Detects**:
  - Error messages
  - Debug information
  - API keys in source
  - Sensitive comments

### 10. CVE Mapper
- **Type**: Passive
- **Module Name**: `cve_mapper`
- **Description**: Maps detected technologies to known CVEs
- **Detects**:
  - Known vulnerabilities
  - Outdated software versions
  - Security advisories
  - Patch requirements

### 11. Authenticated Scanner
- **Type**: Active
- **Module Name**: `authenticated_scanner`
- **Description**: Tests authenticated functionality
- **Detects**:
  - Authentication bypass
  - Session management issues
  - Authorization flaws
  - Privilege escalation

### 12. OSINT Footprint Module
- **Type**: Passive
- **Module Name**: `osint_footprint`
- **Description**: Open Source Intelligence gathering
- **Detects**:
  - Social media presence
  - Public information exposure
  - Technology stack identification
  - Employee information

---

## 🎯 Comprehensive Scanning

### All 11 Modules Enabled by Default

SENTINEL now includes **comprehensive scanning capabilities** with all scanner modules enabled by default:

#### **Core Security Modules**
- **HTTP Security Scanner** - Headers, cookies, server analysis
- **DNS Enumeration** - Subdomain discovery, DNS records
- **SSL/TLS Scanner** - Certificate analysis, cipher suites
- **Network Scanner** - Port scanning, service detection

#### **Vulnerability Testing Modules**
- **SQL Injection Scanner** - Database injection testing
- **XSS Scanner** - Cross-site scripting detection
- **Command Injection Scanner** - OS command injection testing
- **Content Discovery** - Hidden files and directories
- **Information Disclosure** - Sensitive data exposure

#### **Advanced Analysis Modules**
- **CVE Mapper** - Known vulnerability mapping
- **Authenticated Scanner** - Authenticated functionality testing
- **OSINT Footprint** - Public intelligence gathering

### Scan Types Available

- **PASSIVE**: Safe reconnaissance (DNS, headers, SSL analysis)
- **ACTIVE**: Comprehensive vulnerability testing (all modules)
- **AGGRESSIVE**: Intensive testing with exploitation attempts

### Configuration for Comprehensive Scans

```env
# Enable all scanning capabilities
ENABLE_INJECTION_TESTING=true
ALLOW_ACTIVE_SCANNING=true
REQUIRE_CONSENT=false

# Required API keys
SHODAN_API_KEY=your_shodan_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here
```

---

## 💻 Usage Examples

### Example 1: Basic Passive Scan (cURL)

```bash
curl -X POST "http://localhost:8000/api/v1/scans" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "modules": ["http_scanner", "dns_enumeration", "ssl_scanner"],
    "scan_type": "passive"
  }'
```

### Example 2: Active Scan with Configuration (cURL)

```bash
curl -X POST "http://localhost:8000/api/v1/scans" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://testsite.com",
    "modules": ["xss_scanner", "sql_injection", "command_injection"],
    "scan_type": "active",
    "config": {
      "timeout": 7200,
      "rate_limit": 5,
      "max_depth": 2
    },
    "metadata": {
      "description": "Penetration test",
      "tester": "Security Team"
    }
  }'
```

### Example 3: Check Scan Status (cURL)

```bash
curl "http://localhost:8000/api/v1/scans/550e8400-e29b-41d4-a716-446655440000"
```

### Example 4: Get Scan Results (cURL)

```bash
curl "http://localhost:8000/api/v1/scans/550e8400-e29b-41d4-a716-446655440000/results"
```

### Example 5: Get AI Analysis (cURL)

```bash
curl -X POST "http://localhost:8000/api/v1/scans/550e8400-e29b-41d4-a716-446655440000/analyze"
```

### Example 6: Filter Vulnerabilities (cURL)

```bash
curl "http://localhost:8000/api/v1/scans/550e8400-e29b-41d4-a716-446655440000/vulnerabilities?severity=high&module=xss_scanner"
```

### Python Example

```python
import requests
import time
import json

# Base URL
BASE_URL = "http://localhost:8000"

# Create scan
response = requests.post(
    f"{BASE_URL}/api/v1/scans",
    json={
        "target": "https://example.com",
        "modules": ["http_scanner", "dns_enumeration", "xss_scanner"],
        "scan_type": "passive"
    }
)

scan_data = response.json()
scan_id = scan_data["scan_id"]
print(f"✓ Scan created: {scan_id}")

# Poll for completion
while True:
    status_response = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}")
    status_data = status_response.json()
    status = status_data["status"]
    progress = status_data.get("progress", 0)
    
    print(f"Status: {status} - Progress: {progress}%")
    
    if status in ["completed", "failed", "cancelled"]:
        break
    
    time.sleep(5)

# Get results
if status == "completed":
    results_response = requests.get(f"{BASE_URL}/api/v1/scans/{scan_id}/results")
    results = results_response.json()
    
    print(f"\n✓ Scan completed!")
    print(f"Found {len(results['vulnerabilities'])} vulnerabilities")
    
    # Display vulnerabilities by severity
    severity_counts = {}
    for vuln in results['vulnerabilities']:
        severity = vuln['severity']
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print("\nVulnerabilities by severity:")
    for severity, count in severity_counts.items():
        print(f"  {severity.upper()}: {count}")
    
    # Get AI analysis
    print("\n🤖 Getting AI analysis...")
    analysis_response = requests.post(f"{BASE_URL}/api/v1/scans/{scan_id}/analyze")
    analysis = analysis_response.json()
    
    print(f"\nExecutive Summary:")
    print(analysis['analysis']['executive_summary'])
    
    print(f"\nTop Priority Actions:")
    for action in analysis['analysis']['priority_actions'][:3]:
        print(f"  {action['priority']}. {action['action']} ({action['severity']})")

else:
    print(f"\n✗ Scan {status}")
```

### JavaScript/Node.js Example

```javascript
const axios = require('axios');

const BASE_URL = 'http://localhost:8000';

async function runScan() {
  try {
    // Create scan
    const scanResponse = await axios.post(`${BASE_URL}/api/v1/scans`, {
      target: 'https://example.com',
      modules: ['http_scanner', 'dns_enumeration', 'xss_scanner'],
      scan_type: 'passive'
    });
    
    const scanId = scanResponse.data.scan_id;
    console.log(`✓ Scan created: ${scanId}`);
    
    // Poll for completion
    let status = 'pending';
    while (!['completed', 'failed', 'cancelled'].includes(status)) {
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      const statusResponse = await axios.get(`${BASE_URL}/api/v1/scans/${scanId}`);
      status = statusResponse.data.status;
      const progress = statusResponse.data.progress || 0;
      
      console.log(`Status: ${status} - Progress: ${progress}%`);
    }
    
    // Get results
    if (status === 'completed') {
      const resultsResponse = await axios.get(`${BASE_URL}/api/v1/scans/${scanId}/results`);
      const results = resultsResponse.data;
      
      console.log(`\n✓ Scan completed!`);
      console.log(`Found ${results.vulnerabilities.length} vulnerabilities`);
      
      // Get AI analysis
      const analysisResponse = await axios.post(`${BASE_URL}/api/v1/scans/${scanId}/analyze`);
      const analysis = analysisResponse.data;
      
      console.log(`\nAI Analysis:`);
      console.log(analysis.analysis.executive_summary);
    }
  } catch (error) {
    console.error('Error:', error.message);
  }
}

runScan();
```

---

## 🤖 AI Integration

SENTINEL leverages **Google's Gemini 2.0 Flash** for intelligent vulnerability analysis:

### Features

1. **Vulnerability Explanations**: Natural language descriptions of security issues
2. **Risk Assessment**: Context-aware security posture evaluation
3. **Remediation Guidance**: Step-by-step fixing instructions
4. **Priority Recommendations**: Focus on critical issues first
5. **Compliance Mapping**: Regulatory requirement alignment

### Configuration

Set your Gemini API key in `.env`:

```env
GEMINI_API_KEY=your_api_key_here
```

Get a free API key at [Google AI Studio](https://makersuite.google.com/app/apikey)

### Usage

The AI features are automatically available through the API:

- **Full Scan Analysis**: `POST /api/v1/scans/{scan_id}/analyze`
- **Vulnerability Explanation**: `POST /api/v1/vulnerabilities/{vuln_id}/explain`

### Benefits

- **Faster Triage**: Quickly understand vulnerability impact
- **Better Decisions**: AI-powered risk prioritization
- **Learning Tool**: Educational explanations for security teams
- **Compliance**: Map findings to regulatory requirements

---

## 🔒 Security Considerations

### Important Guidelines

⚠️ **Always obtain proper authorization before scanning any target**

1. **Legal Compliance**
   - Only scan systems you own or have explicit permission to test
   - Comply with local laws and regulations
   - Respect terms of service and acceptable use policies

2. **Scan Type Selection**
   - Use **PASSIVE** mode for initial assessments
   - Use **ACTIVE** mode only with authorization
   - Use **AGGRESSIVE** mode only in controlled environments

3. **Rate Limiting**
   - Configure appropriate rate limits to avoid overwhelming targets
   - Monitor scan impact on target systems
   - Adjust concurrency based on target capacity

4. **Data Protection**
   - Secure your Gemini API key
   - Protect scan results and vulnerability data
   - Implement access controls in production
   - Encrypt sensitive data at rest and in transit

5. **Responsible Disclosure**
   - Follow responsible disclosure practices
   - Report vulnerabilities to affected parties
   - Allow reasonable time for remediation

### Production Deployment

For production use:

1. **Enable Authentication**: Implement API authentication (JWT, API keys, OAuth2)
2. **Use HTTPS**: Enable TLS/SSL for API communication
3. **Database Security**: Use PostgreSQL with proper access controls
4. **Rate Limiting**: Configure appropriate rate limits
5. **Logging & Monitoring**: Implement comprehensive logging
6. **Input Validation**: Validate all API inputs
7. **CORS Configuration**: Restrict allowed origins
8. **Environment Variables**: Never commit `.env` files

---

## 🐛 Troubleshooting

### Common Issues

#### 1. API Connection Failed

**Problem**: Cannot connect to the API

**Solutions**:
```bash
# Check if server is running
curl http://localhost:8000/health

# Verify port is not in use
netstat -ano | findstr :8000  # Windows
lsof -i :8000                 # Linux/Mac

# Check firewall settings
# Ensure port 8000 is allowed
```

#### 2. AI Features Not Working

**Problem**: AI analysis returns errors

**Solutions**:
- Verify Gemini API key in `.env` file
- Check internet connection
- Monitor API rate limits
- Verify API key is valid at [Google AI Studio](https://makersuite.google.com/app/apikey)

```bash
# Test API key
curl -H "Content-Type: application/json" \
  -d '{"contents":[{"parts":[{"text":"Hello"}]}]}' \
  "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent?key=YOUR_API_KEY"
```

#### 3. Scan Failures

**Problem**: Scans fail or timeout

**Solutions**:
- Check target accessibility
- Verify network connectivity
- Review module compatibility
- Increase timeout in configuration
- Check logs in `logs/` directory

```bash
# View recent logs
tail -f logs/sentinel.log

# Check scan timeout setting
grep SCAN_TIMEOUT .env
```

#### 4. Database Errors

**Problem**: Database connection or query errors

**Solutions**:
```bash
# Reinitialize database
python -c "from backend.core.database import init_db; init_db()"

# Check database file permissions
ls -la sentinel.db

# Backup and recreate database
mv sentinel.db sentinel.db.backup
python -c "from backend.core.database import init_db; init_db()"
```

#### 5. Module Import Errors

**Problem**: Scanner modules fail to load

**Solutions**:
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Check for missing dependencies
python -c "from backend.scanner.modules import SCANNER_MODULES; print(SCANNER_MODULES.keys())"

# Install optional dependencies
pip install python-nmap sslyze selenium
```

### Debug Mode

Enable debug mode for detailed logging:

```env
DEBUG=true
```

Then restart the server:

```bash
python run_api.py
```

---

## 📊 Performance Optimization

### Tips for Better Performance

1. **Concurrent Scans**: Adjust `MAX_CONCURRENT_SCANS` based on your system resources
2. **Rate Limiting**: Balance between speed and target protection
3. **Module Selection**: Only run necessary modules
4. **Timeout Configuration**: Set appropriate timeouts for your targets
5. **Database**: Consider PostgreSQL for production workloads

### Resource Requirements

- **Minimum**: 2 CPU cores, 4GB RAM
- **Recommended**: 4 CPU cores, 8GB RAM
- **Production**: 8+ CPU cores, 16GB+ RAM

---

## 🔄 Integration Examples

### CI/CD Integration

#### GitHub Actions

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run SENTINEL Scan
        run: |
          curl -X POST "https://sentinel.example.com/api/v1/scans" \
            -H "Content-Type: application/json" \
            -d '{
              "target": "${{ github.event.repository.html_url }}",
              "modules": ["http_scanner", "xss_scanner"],
              "scan_type": "passive"
            }'
```

#### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    def response = sh(
                        script: """
                            curl -X POST "http://sentinel:8000/api/v1/scans" \
                              -H "Content-Type: application/json" \
                              -d '{"target": "${env.TARGET_URL}", "modules": ["http_scanner"]}'
                        """,
                        returnStdout: true
                    ).trim()
                    
                    def scanId = readJSON(text: response).scan_id
                    echo "Scan ID: ${scanId}"
                }
            }
        }
    }
}
```

### Webhook Integration

Configure webhooks to receive scan completion notifications:

```python
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/webhook/scan-complete', methods=['POST'])
def scan_complete():
    data = request.json
    scan_id = data['scan_id']
    status = data['status']
    
    if status == 'completed':
        # Get results
        results = requests.get(
            f"http://localhost:8000/api/v1/scans/{scan_id}/results"
        ).json()
        
        # Process results
        critical_vulns = [
            v for v in results['vulnerabilities'] 
            if v['severity'] == 'critical'
        ]
        
        if critical_vulns:
            # Send alert
            send_alert(f"Critical vulnerabilities found: {len(critical_vulns)}")
    
    return {'status': 'ok'}

if __name__ == '__main__':
    app.run(port=5000)
```

---

## 📈 Roadmap

### Planned Features

- [ ] **Authentication & Authorization**: JWT-based API authentication
- [ ] **WebSocket Support**: Real-time scan updates
- [ ] **Advanced Reporting**: PDF/HTML report generation
- [ ] **Scheduled Scans**: Cron-based automated scanning
- [ ] **Plugin System**: Custom scanner module support
- [ ] **Multi-tenancy**: Support for multiple organizations
- [ ] **Cloud Deployment**: Docker & Kubernetes support
- [ ] **Enhanced AI**: GPT-4 integration option
- [ ] **Compliance Reports**: OWASP, PCI-DSS, HIPAA templates
- [ ] **API Rate Limiting**: Per-user rate limits
- [ ] **Notification System**: Email/Slack/Discord alerts
- [ ] **Dashboard UI**: Web-based management interface

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Ways to Contribute

1. **Report Bugs**: Open an issue with detailed information
2. **Suggest Features**: Share your ideas for improvements
3. **Submit Pull Requests**: Fix bugs or add features
4. **Improve Documentation**: Help make docs clearer
5. **Write Tests**: Increase test coverage

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/SENTINEL.git
cd SENTINEL

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-asyncio black flake8

# Run tests
pytest

# Format code
black backend/

# Lint code
flake8 backend/
```

### Pull Request Guidelines

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 SENTINEL

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Acknowledgments

- **Google Gemini AI**: Powered by Gemini 2.0 Flash for intelligent analysis
- **FastAPI**: Modern, fast web framework for building APIs
- **OWASP**: Security testing methodologies and best practices
- **Community**: Contributors and security researchers

---

## 📧 Support & Contact

### Getting Help

- **Documentation**: http://localhost:8000/docs (when server is running)
- **Issues**: [GitHub Issues](https://github.com/yourusername/SENTINEL/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/SENTINEL/discussions)

### Security Issues

If you discover a security vulnerability, please email security@example.com instead of using the issue tracker.

---

## 📚 Additional Resources

### Documentation

- [API Reference](http://localhost:8000/docs) - Interactive API documentation
- [Scanner Modules Guide](docs/modules.md) - Detailed module documentation
- [Configuration Guide](docs/configuration.md) - Advanced configuration options
- [Deployment Guide](docs/deployment.md) - Production deployment instructions

### Related Projects

- [OWASP ZAP](https://www.zaproxy.org/) - Web application security scanner
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner
- [Burp Suite](https://portswigger.net/burp) - Web security testing toolkit

### Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Security Academy](https://portswigger.net/web-security)
- [HackerOne](https://www.hackerone.com/resources)

---

<div align="center">

**⚠️ DISCLAIMER**

This tool is for authorized security testing only. Users are responsible for complying with all applicable laws and regulations. Unauthorized access to computer systems is illegal.

---

**🚀 Ready to enhance your security posture with AI-powered vulnerability scanning!**

Made with ❤️ by the SENTINEL Team

[⬆ Back to Top](#️-sentinel---ai-powered-vulnerability-scanner)

</div>
