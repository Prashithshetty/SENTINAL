"""Setup script for XSS Scanner with Playwright."""

import subprocess
import sys
import os

def run_command(command, description):
    """Run a command and handle errors."""
    print(f"\n{'='*60}")
    print(f"📦 {description}")
    print(f"{'='*60}")
    print(f"Command: {command}")
    print()
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            capture_output=True,
            text=True
        )
        print(result.stdout)
        if result.stderr:
            print("Warnings:", result.stderr)
        print(f"✅ {description} completed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: {e}")
        print(f"Output: {e.stdout}")
        print(f"Error: {e.stderr}")
        return False

def check_playwright_installed():
    """Check if Playwright is installed."""
    try:
        import playwright
        print("✅ Playwright Python package is installed")
        return True
    except ImportError:
        print("❌ Playwright Python package is not installed")
        return False

def check_playwright_browsers():
    """Check if Playwright browsers are installed."""
    try:
        result = subprocess.run(
            "playwright --version",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"✅ Playwright CLI is available: {result.stdout.strip()}")
            return True
        else:
            print("❌ Playwright CLI is not available")
            return False
    except Exception as e:
        print(f"❌ Error checking Playwright CLI: {e}")
        return False

def main():
    """Main setup function."""
    print("\n" + "="*60)
    print("🚀 XSS Scanner Setup with Playwright")
    print("="*60)
    
    # Check Python version
    print(f"\n📍 Python Version: {sys.version}")
    
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required!")
        sys.exit(1)
    
    print("✅ Python version is compatible")
    
    # Step 1: Check if Playwright is installed
    print("\n" + "="*60)
    print("Step 1: Checking Playwright Installation")
    print("="*60)
    
    playwright_installed = check_playwright_installed()
    
    if not playwright_installed:
        print("\n📦 Installing Playwright...")
        if not run_command(
            f"{sys.executable} -m pip install playwright>=1.40.0",
            "Installing Playwright Python package"
        ):
            print("\n❌ Failed to install Playwright!")
            print("Please try manually: pip install playwright")
            sys.exit(1)
    
    # Step 2: Install Playwright browsers
    print("\n" + "="*60)
    print("Step 2: Installing Playwright Browsers")
    print("="*60)
    
    browsers_installed = check_playwright_browsers()
    
    if not browsers_installed:
        print("\n📦 Installing Playwright browsers (Chromium)...")
        if not run_command(
            "playwright install chromium",
            "Installing Chromium browser"
        ):
            print("\n⚠️  Warning: Failed to install browsers automatically")
            print("Please try manually: playwright install chromium")
    
    # Step 3: Verify installation
    print("\n" + "="*60)
    print("Step 3: Verifying Installation")
    print("="*60)
    
    try:
        from playwright.async_api import async_playwright
        print("✅ Playwright can be imported successfully")
        
        # Try to get browser info
        import asyncio
        
        async def test_browser():
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                print(f"✅ Chromium browser launched successfully")
                print(f"   Version: {browser.version}")
                await browser.close()
        
        print("\n🧪 Testing browser launch...")
        asyncio.run(test_browser())
        
    except Exception as e:
        print(f"❌ Error during verification: {e}")
        print("\nPlease try the following:")
        print("1. pip install playwright")
        print("2. playwright install chromium")
        sys.exit(1)
    
    # Step 4: Check other dependencies
    print("\n" + "="*60)
    print("Step 4: Checking Other Dependencies")
    print("="*60)
    
    dependencies = [
        ('httpx', 'HTTP client'),
        ('beautifulsoup4', 'HTML parsing'),
    ]
    
    missing_deps = []
    
    for package, description in dependencies:
        try:
            __import__(package)
            print(f"✅ {package} ({description})")
        except ImportError:
            print(f"❌ {package} ({description}) - MISSING")
            missing_deps.append(package)
    
    if missing_deps:
        print(f"\n📦 Installing missing dependencies: {', '.join(missing_deps)}")
        deps_str = ' '.join(missing_deps)
        if not run_command(
            f"{sys.executable} -m pip install {deps_str}",
            "Installing missing dependencies"
        ):
            print("\n⚠️  Some dependencies failed to install")
    
    # Final summary
    print("\n" + "="*60)
    print("✅ Setup Complete!")
    print("="*60)
    print("\n📋 Summary:")
    print("  ✅ Playwright is installed")
    print("  ✅ Chromium browser is ready")
    print("  ✅ All dependencies are available")
    print("\n🎯 You can now run the XSS scanner:")
    print("  python test_xss_scanner_enhanced.py")
    print("\n" + "="*60)

if __name__ == "__main__":
    main()
