# SENTINAL Security Scanner

![SENTINAL Logo](https://via.placeholder.com/800x200?text=SENTINAL+Security+Scanner)

## Overview

SENTINAL is an advanced vulnerability assessment framework designed for comprehensive security testing of web applications and services. It provides a modular, extensible architecture for detecting various security vulnerabilities, including XSS, SQL injection, command injection, SSRF, and more.

## Features

- Comprehensive Vulnerability Detection: Scan for a wide range of security vulnerabilities
- Modular Architecture: Easily extensible with new scanner modules
- Multiple Scan Modes: Passive, Active, and Aggressive scanning options
- Professional CLI Interface: User-friendly command-line interface with rich formatting
- Detailed Reporting: Generate comprehensive vulnerability reports
- Proof of Concept Generation: Automatically generate PoC exploits for discovered vulnerabilities
- API Integration: Integrate with other security tools and workflows

## Security Modules

SENTINAL includes the following vulnerability assessment modules:

| Module | Description | Risk Level |
|--------|-------------|------------|
| XSS Scanner | Cross-Site Scripting vulnerability detection | HIGH |
| SQL Injection | SQL injection vulnerability detection | CRITICAL |
| Command Injection | OS command injection detection | CRITICAL |
| SSRF Scanner | Server-Side Request Forgery detection | HIGH |
| RCE Scanner | Remote Code Execution vulnerability detection | CRITICAL |
| HTTP Scanner | HTTP security headers and configuration analysis | MEDIUM |
| SSL/TLS Scanner | SSL/TLS configuration and vulnerability analysis | MEDIUM |
| Info Disclosure | Sensitive information exposure detection | LOW |
| Content Discovery | Hidden files and directories discovery | INFO |

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Prashithshetty/SENTINAL.git
cd SENTINAL

# Install dependencies (preferred if requirements.txt exists)
pip install -r requirements.txt
```

If requirements.txt is not present, install core dependencies manually:
```bash
pip install rich python-dotenv httpx requests fastapi uvicorn pydantic pydantic-settings SQLAlchemy beautifulsoup4 dnspython shodan
```

Set optional environment variables as needed (for external integrations and PoC generation):
```bash
# Shodan integration
export SHODAN_API_KEY=your_api_key

# LLM-powered PoC generation (optional)
export HUGGINGFACE_API_KEY=your_api_key
export USE_LM_STUDIO=true
export LM_STUDIO_API_URL=http://localhost:1234/v1
```

### Basic Usage

```bash
# Run the professional CLI interface
python cli.py

# Run the simple CLI interface
python sentinal.py
# Then select the module from the menu
```

Run the API server:

```bash
python run_api.py
# API docs available at http://localhost:8001/docs
```

## Documentation

- Installation Guide: INSTALLATION.md
- Usage Guide: USAGE.md
- Scanner Modules: MODULES.md
- Architecture: ARCHITECTURE.md
- Contributing: CONTRIBUTING.md

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

SENTINAL is designed for legitimate security testing with proper authorization. Unauthorized scanning of systems you do not own or have explicit permission to test is illegal and unethical. Always obtain proper authorization before conducting security assessments.
