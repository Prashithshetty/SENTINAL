# SENTINAL Usage Guide

This guide provides detailed instructions for using the SENTINAL security scanner effectively.

## Getting Started

SENTINAL offers two main interfaces:
1. A professional CLI interface with rich formatting (`cli.py`)
2. A simpler command-line interface (`sentinal.py`)

## Using the Professional CLI Interface

The professional CLI interface provides a user-friendly, feature-rich experience with animated elements and detailed information.

### Launch the CLI

```bash
python cli.py
```

### Main Menu

The main menu displays:
- Available vulnerability assessment modules
- System commands
- Current status information

### Running a Scan

1. Select a module from the menu by entering its number
2. Enter the target URL when prompted
3. Select the scan intensity:
   - **Passive**: Non-intrusive reconnaissance only (minimal impact)
   - **Active**: Standard vulnerability testing (moderate impact)
   - **Aggressive**: Comprehensive payload testing (high impact)
4. Configure advanced parameters if needed
5. Confirm to start the scan

### Comprehensive Scan

To run all available modules:
1. Select option `0` from the main menu
2. Enter the target URL
3. Configure scan parameters
4. Confirm to start the comprehensive scan

### System Commands

- **[R]**: Review scan history and results
- **[C]**: Configure global scan parameters
- **[D]**: View documentation and usage guide
- **[S]**: View system statistics and performance
- **[X]**: Exit SENTINAL

Note: Commands [R] and [C] are currently in development in this build and may display placeholders rather than full functionality.

## Using the Simple CLI Interface

The simple CLI interface provides a more straightforward command-line experience.

### Launch the Simple CLI

```bash
python sentinal.py
```

### Running a Scan

1. Select a module from the menu by entering its number
2. Enter the target URL when prompted
3. Select the scan type (1-3)
4. Choose whether to enable debug mode
5. Wait for the scan to complete

### Additional Tools

The simple CLI also provides access to additional tools:
- Shodan Search
- DNS Inspector
- Link Analyzer
- Browser Checker
- Web Crawler
- Report Generator

## Scan Types Explained

### Passive Scan
- Non-intrusive reconnaissance
- No active exploitation attempts
- Safe for production environments
- Examples: HTTP header analysis, DNS enumeration, content discovery

### Active Scan
- Standard vulnerability testing
- Moderate payload injection
- Recommended for staging environments
- Examples: Basic XSS testing, SQL injection with safe payloads

### Aggressive Scan
- Comprehensive payload testing
- Full exploitation attempts
- Development environments only
- Examples: Advanced XSS payloads, extensive SQL injection tests

## Understanding Scan Results

Scan results include:
- **Vulnerability Summary**: Overview of detected vulnerabilities
- **Findings Breakdown**: Vulnerabilities categorized by severity
- **Detailed Vulnerabilities**: Specific information about each vulnerability
- **Module Results**: Performance and findings from each module
- **POC Reports**: Proof of concept exploitation details (if vulnerabilities are found)

### Severity Levels

- **CRITICAL**: Severe vulnerabilities that can lead to system compromise
- **HIGH**: Significant vulnerabilities that pose serious security risks
- **MEDIUM**: Moderate vulnerabilities that should be addressed
- **LOW**: Minor vulnerabilities with limited impact
- **INFO**: Informational findings that may not represent vulnerabilities

## Advanced Usage

### Custom Scan Configuration

You can customize scan parameters:
- **Timeout**: Maximum scan duration in seconds
- **Rate Limit**: Requests per second to avoid overwhelming the target
- **Max Depth**: How deep to crawl the target website
- **Debug Mode**: Enable verbose output for troubleshooting

### Using Environment Variables

Set environment variables to configure SENTINAL:

```bash
# Set Shodan API key for enhanced reconnaissance
export SHODAN_API_KEY=your_api_key_here

# Configure LLM for POC generation
export HUGGINGFACE_API_KEY=your_api_key_here
export USE_LM_STUDIO=true
export LM_STUDIO_API_URL=http://localhost:1234/v1
```

### Automating Scans

You can automate scans using scripts:

```python
import asyncio
from backend.scanner.engine import scanner_engine
from backend.scanner.base_module import ScanConfig, ScanType

async def run_automated_scan():
    # Create scan configuration
    config = ScanConfig(
        target="https://example.com",
        scan_type=ScanType.ACTIVE,
        timeout=3600,
        rate_limit=1,
        max_depth=3,
        debug=False
    )
    
    # Create scan job
    scan_job = await scanner_engine.create_scan(
        target="https://example.com",
        modules=["xss_scanner", "sql_injection"],
        config=config
    )
    
    # Execute scan
    completed_job = await scanner_engine.execute_scan(scan_job.id)
    
    # Get results
    results = scanner_engine.get_scan_results(completed_job.id)
    print(results)

# Run the automated scan
asyncio.run(run_automated_scan())
```

## Best Practices

1. **Start with Passive Scans**: Begin with non-intrusive scans before moving to more aggressive testing
2. **Obtain Permission**: Always get explicit permission before scanning any system
3. **Use Rate Limiting**: Avoid overwhelming the target system with too many requests
4. **Review Results Carefully**: Analyze findings to identify false positives
5. **Document Everything**: Keep records of all scan activities and findings
6. **Follow Up**: Address identified vulnerabilities and verify fixes

## Troubleshooting

### Common Issues

1. **Scan Timeouts**
   - Increase the timeout value in the scan configuration
   - Reduce the scan scope or depth

2. **Rate Limiting by Target**
   - Decrease the rate limit in the scan configuration
   - Add delays between requests

3. **False Positives**
   - Enable debug mode for more detailed information
   - Review the evidence provided for each vulnerability
   - Manually verify findings

4. **Module Failures**
   - Check the error messages in the scan results
   - Ensure all dependencies are installed correctly
   - Verify that the target is compatible with the module
