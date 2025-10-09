#!/usr/bin/env python3
"""Setup script for the Dynamic SQL Injection Scanner."""

import subprocess
import sys
import os
from pathlib import Path


def run_command(cmd, description):
    """Run a command and handle errors."""
    print(f"\n{description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ {description} completed successfully")
            if result.stdout:
                print(f"  Output: {result.stdout.strip()}")
            return True
        else:
            print(f"✗ {description} failed")
            if result.stderr:
                print(f"  Error: {result.stderr.strip()}")
            return False
    except Exception as e:
        print(f"✗ {description} failed with exception: {e}")
        return False


def check_python_version():
    """Check if Python version is 3.7+."""
    print("Checking Python version...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 7:
        print(f"✓ Python {version.major}.{version.minor}.{version.micro} is supported")
        return True
    else:
        print(f"✗ Python {version.major}.{version.minor} is not supported. Please use Python 3.7+")
        return False


def install_playwright():
    """Install Playwright and its dependencies."""
    print("\n" + "="*60)
    print("Setting up Playwright for Dynamic SQL Scanner")
    print("="*60)
    
    # Check if playwright is installed
    print("\nChecking Playwright installation...")
    try:
        import playwright
        print("✓ Playwright package is installed")
    except ImportError:
        print("✗ Playwright not found. Installing...")
        if not run_command("pip install playwright>=1.40.0", "Installing Playwright"):
            return False
    
    # Install Playwright browsers
    browsers = ['chromium', 'firefox', 'webkit']
    print("\nInstalling Playwright browsers...")
    
    for browser in browsers:
        if browser == 'chromium':
            # Chromium is required
            if not run_command(f"python -m playwright install {browser}", f"Installing {browser}"):
                print(f"✗ Failed to install {browser}. This is required for the scanner.")
                return False
        else:
            # Firefox and WebKit are optional
            run_command(f"python -m playwright install {browser}", f"Installing {browser} (optional)")
    
    # Install system dependencies
    print("\nInstalling system dependencies...")
    run_command("python -m playwright install-deps", "Installing system dependencies")
    
    return True


def verify_installation():
    """Verify that the dynamic scanner can run."""
    print("\n" + "="*60)
    print("Verifying Installation")
    print("="*60)
    
    # Test import
    print("\nTesting module imports...")
    try:
        from backend.scanner.modules.sql_injection_dynamic import SQLInjectionDynamicScanner
        print("✓ Dynamic SQL Scanner module imports successfully")
    except ImportError as e:
        print(f"✗ Failed to import Dynamic SQL Scanner: {e}")
        return False
    
    # Test Playwright
    print("\nTesting Playwright...")
    test_script = """
import asyncio
from playwright.async_api import async_playwright

async def test():
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto('https://example.com')
            title = await page.title()
            await browser.close()
            return title == "Example Domain"
    except Exception as e:
        print(f"Error: {e}")
        return False

result = asyncio.run(test())
print("SUCCESS" if result else "FAILED")
"""
    
    with open("_test_playwright.py", "w") as f:
        f.write(test_script)
    
    try:
        result = subprocess.run([sys.executable, "_test_playwright.py"], 
                              capture_output=True, text=True, timeout=30)
        if "SUCCESS" in result.stdout:
            print("✓ Playwright is working correctly")
            success = True
        else:
            print("✗ Playwright test failed")
            if result.stderr:
                print(f"  Error: {result.stderr}")
            success = False
    except subprocess.TimeoutExpired:
        print("✗ Playwright test timed out")
        success = False
    except Exception as e:
        print(f"✗ Playwright test failed: {e}")
        success = False
    finally:
        # Clean up test file
        try:
            os.remove("_test_playwright.py")
        except:
            pass
    
    return success


def create_example_config():
    """Create an example configuration file."""
    print("\n" + "="*60)
    print("Creating Example Configuration")
    print("="*60)
    
    config_content = """# Example configuration for Dynamic SQL Scanner
# Save this as 'scanner_config.yaml' or use in your Python scripts

# Target configuration
target:
  url: "https://juice-shop.herokuapp.com"  # Or your local instance
  scan_type: "ACTIVE"  # PASSIVE, ACTIVE, or AGGRESSIVE
  
# Scanner settings
scanner:
  timeout: 60  # Seconds
  rate_limit: 5  # Requests per second
  max_depth: 3  # Crawling depth
  
# Browser settings
browser:
  headless: true  # Run in headless mode
  viewport:
    width: 1920
    height: 1080
  
# Payload settings
payloads:
  max_per_param: 10  # Maximum payloads to test per parameter
  include_time_based: true  # Include time-based payloads
  include_boolean: true  # Include boolean-based payloads
  
# Output settings
output:
  verbose: true  # Detailed output
  save_report: true  # Save HTML report
  report_path: "./reports/sql_injection_report.html"
"""
    
    config_file = "scanner_config_example.yaml"
    with open(config_file, "w") as f:
        f.write(config_content)
    
    print(f"✓ Created example configuration file: {config_file}")
    return True


def print_usage_examples():
    """Print usage examples."""
    print("\n" + "="*60)
    print("Usage Examples")
    print("="*60)
    
    print("""
1. Test OWASP Juice Shop:
   python test_dynamic_sql_scanner.py

2. Quick scan in Python:
   ```python
   import asyncio
   from backend.scanner.modules.sql_injection_dynamic import SQLInjectionDynamicScanner
   from backend.scanner.base_module import ScanConfig, ScanType
   
   async def scan():
       scanner = SQLInjectionDynamicScanner()
       config = ScanConfig(
           target="https://your-target.com",
           scan_type=ScanType.ACTIVE
       )
       result = await scanner.scan(config)
       print(f"Found {len(result.vulnerabilities)} vulnerabilities")
   
   asyncio.run(scan())
   ```

3. Test specific endpoint:
   ```python
   config = ScanConfig(
       target="https://api.example.com/search?q=test",
       scan_type=ScanType.ACTIVE
   )
   ```

4. Aggressive scan with custom settings:
   ```python
   config = ScanConfig(
       target="https://example.com",
       scan_type=ScanType.AGGRESSIVE,
       timeout=120,
       rate_limit=10,
       max_depth=5
   )
   ```
""")


def main():
    """Main setup function."""
    print("="*60)
    print("Dynamic SQL Injection Scanner Setup")
    print("="*60)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install Playwright
    if not install_playwright():
        print("\n✗ Setup failed. Please fix the errors above and try again.")
        sys.exit(1)
    
    # Verify installation
    if not verify_installation():
        print("\n✗ Verification failed. Please check the errors above.")
        sys.exit(1)
    
    # Create example configuration
    create_example_config()
    
    # Print usage examples
    print_usage_examples()
    
    print("\n" + "="*60)
    print("✓ Setup completed successfully!")
    print("="*60)
    print("\nYou can now run the Dynamic SQL Scanner:")
    print("  python test_dynamic_sql_scanner.py")
    print("\nFor more information, see:")
    print("  docs/SQL_INJECTION_DYNAMIC_SCANNER.md")


if __name__ == "__main__":
    main()
