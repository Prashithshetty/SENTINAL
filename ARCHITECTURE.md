# SENTINAL Architecture

This document provides a coherent overview of the SENTINAL security scanner's architecture, including core components, data flow, and integrations. It reflects the current repository structure and code.

## System Overview

SENTINAL is a modular vulnerability assessment framework with:
- CLI interfaces for local operation
- A FastAPI backend for programmatic access
- A core scanner engine orchestrating multiple scanning modules
- Optional AI-powered PoC reporting

Top-level entry points:
- cli.py — professional, rich TUI CLI
- sentinal.py — simple CLI
- run_api.py — API server bootstrap for the FastAPI app in backend/api/main.py

Key packages:
- backend/scanner — scanning engine, base contract, and modules
- backend/core — configuration, database, AI/POC helpers
- backend/api — FastAPI application and models

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      User Interfaces                         │
│                                                             │
│  CLI (cli.py, sentinal.py)          FastAPI (run_api.py)    │
└─────────┬─────────────────────────────────────┬─────────────┘
          │                                     │
          ▼                                     ▼
┌─────────────────────────────────────────────────────────────┐
│                      Core Components                         │
│                                                             │
│  Scanner Engine (backend/scanner/engine.py)                 │
│  Configuration   (backend/core/config.py)                   │
│  Database        (backend/core/database.py)                 │
└─────────┬─────────────────────────────────────┬─────────────┘
          │                                     │
          ▼                                     ▼
┌─────────────────────────────────────────────────────────────┐
│                      Scanner Modules                         │
│ backend/scanner/modules/                                     │
│  - http_scanner.py            - sql_injection.py             │
│  - xss_scanner.py             - command_injection.py         │
│  - ssrf_scanner.py            - rce_scanner.py               │
│  - ssl_scanner.py             - network_scanner*.py          │
│  - info_disclosure.py         - content_discovery.py         │
│  - dns_enumeration.py         - dns_inspector.py             │
│  - browser_checker.py         - link_analyzer.py             │
│  - shodan_scanner.py          - report_generator.py          │
└─────────────────────────────────────────────────────────────┘
          │                                     │
          ▼                                     ▼
┌─────────────────────────────────────────────────────────────┐
│                    Support Services                          │
│  - PoC Generator (backend/scanner/poc_generator.py)          │
│  - AI Analyzer (backend/core/ai_analyzer.py)                 │
│  - HF PoC Reporter (backend/core/hf_poc_reporter.py)         │
└─────────────────────────────────────────────────────────────┘
```

Note: For network scanning, an alternative implementation may be used if `nmap` is unavailable (see backend/scanner/modules/__init__.py).

## Core Components

### 1) Scanner Engine (backend/scanner/engine.py)

Responsibilities:
- Module initialization and registry consumption (SCANNER_MODULES)
- Scan job lifecycle management (ScanJob, ScanStatus)
- Concurrency and grouping by scan type (PASSIVE/ACTIVE/AGGRESSIVE)
- Aggregation and deduplication of vulnerabilities
- Result shaping for UI/API consumption

Important types:
- ScanJob: tracks job metadata, status, results, and progress
- ScanType: PASSIVE, ACTIVE, AGGRESSIVE (influences module execution)
- Vulnerability and SeverityLevel: standardized result model

Exports:
- scanner_engine: a global engine instance used by CLI and API

### 2) Configuration (backend/core/config.py)

- Centralized settings via pydantic-settings
- Feature flags and module toggles
- Directory initialization (reports, scan_results, logs)
- Derived lists: settings.scan_modules (enabled modules)

Relevant environment variables include:
- MAX_CONCURRENT_SCANS, SCAN_TIMEOUT_SECONDS, RATE_LIMIT_REQUESTS_PER_MINUTE, MAX_SCAN_DEPTH
- REQUIRE_CONSENT and others controlling behavior and integrations

### 3) Database (backend/core/database.py)

- Database session and initialization helpers (SQLite by default)
- Used by the API layer to persist scans, modules, and vulnerabilities

## API Layer

File: backend/api/main.py
- FastAPI app exposing endpoints to:
  - List available modules
  - Create scans, monitor active jobs, retrieve results
  - Serve vulnerability stats and AI-assisted analysis
- Background execution of scans with result persistence
- Error handling and CORS configured

Run with:
- python run_api.py
- Docs at http://localhost:8001/docs

## Scanner Modules

All modules are registered in:
- backend/scanner/modules/__init__.py (SCANNER_MODULES dict)

Module categories include:
- Injection: xss_scanner, sql_injection, command_injection, ssrf_scanner, rce_scanner
- Configuration/Headers: http_scanner, ssl_scanner
- Discovery/Information: content_discovery, info_disclosure, dns_enumeration, dns_inspector, link_analyzer
- External/OSINT: shodan_scanner
- Utilities: browser_checker, report_generator
- Network: network_scanner or fallback implementation

Base contract:
- backend/scanner/base_module.py defines BaseScannerModule, ScanConfig, ScanResult, Vulnerability, SeverityLevel, ScanType

Example: http_scanner performs header analysis, cookie checks, CORS evaluation, method probing, and mixed content checks (with context-aware logic for APIs/admin/static pages).

## Support Services

- backend/scanner/poc_generator.py — generates structured proof-of-concepts for detected issues
- backend/core/ai_analyzer.py — higher-level AI analysis for vulnerability sets
- backend/core/hf_poc_reporter.py — HuggingFace/LM Studio integration for PoC reporting

## Data Flow

1) Initiation
- CLI or API layer constructs ScanConfig and requests scanner_engine.create_scan(...)

2) Execution
- scanner_engine.execute_scan(scan_id)
- Modules grouped by ScanType (passive/active/aggressive)
- Concurrency via asyncio with semaphores, configurable limits

3) Aggregation
- Deduplication and sorting of Vulnerabilities by SeverityLevel
- Result enriched with per-module statistics and overall counts

4) Output
- CLI displays structured summaries and saves JSON to scan_results/
- API returns JSON payloads; optional DB persistence of scans/modules/vulns

## Asynchronous Execution

- Extensive use of asyncio for non-blocking network I/O
- Concurrency controls per group type and module behavior
- Timeout handling and structured error propagation per module

## Configuration and Feature Flags

- Defaults provided in backend/core/config.py, override via .env
- Feature flags enable/disable categories (e.g., authenticated scanning, CVE mapping)
- Some modules gracefully degrade if optional dependencies are not installed

## Security Considerations

- Consent gating: settings.require_consent for active/aggressive modes
- Rate limiting: global and per-job controls
- Input validation and robust exception handling

## Directories and Files

- reports/ — human-readable reports and PoC artifacts (when generated)
- scan_results/ — JSON outputs from scans
- config/ — YAML configs (e.g., config/ssl_scanner.yaml)
- logs/ — runtime log output (if configured by environment)

## Future Enhancements

- Optional web UI on top of the API
- Distributed scan runners
- Additional module packs and signatures
- Extended AI-assisted triage and deduplication
