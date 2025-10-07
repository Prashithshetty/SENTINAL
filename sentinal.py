import os
import asyncio
import json
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables from .env file at the very start
load_dotenv()

# --- Module Imports ---
from modules.browser_checker import BrowserChecker
from modules.dns_inspector import DNSInspector
from modules.link_analyzer import LinkAnalyzer
from modules.shodan_scanner import ShodanScanner
from modules.report_generator import ReportGenerator
# Import the existing scanner_engine INSTANCE, not the class
from backend.scanner.engine import scanner_engine


def print_menu():
    """Prints the main menu for the toolkit."""
    print("\n--- Sentinel Security Toolkit ---")
    print("0. Run Comprehensive Scan (All Modules)")
    print("6. Exit")


async def run_comprehensive_scan(url):
    """
    Runs a full reconnaissance and vulnerability scan against a target URL.
    """
    print(f"\n[+] Starting Comprehensive Scan for: {url}")
    print("-" * 40)

    # --- Stage 1: Run all reconnaissance modules concurrently ---
    print("[*] Stage 1: Running reconnaissance modules (DNS, Shodan, Browser, Link)...")
    
    browser_checker = BrowserChecker()
    dns_inspector = DNSInspector()
    link_analyzer = LinkAnalyzer()
    report_generator = ReportGenerator()
    
    shodan_api_key = os.getenv("SHODAN_API_KEY")
    if not shodan_api_key:
        print("[!] Warning: SHODAN_API_KEY not found. Skipping Shodan scan.")
        shodan_scanner = None
    else:
        shodan_scanner = ShodanScanner(api_key=shodan_api_key)

    tasks = [
        browser_checker.check(url),
        dns_inspector.inspect(urlparse(url).netloc),
        link_analyzer.analyze(url),
        shodan_scanner.scan(urlparse(url).netloc) if shodan_scanner else asyncio.sleep(0, result={"error": "Shodan API key not configured"})
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    browser_analysis, dns_analysis, link_analysis, shodan_analysis = results

    recon_report = report_generator.generate(
        url=url,
        link_analysis=link_analysis if not isinstance(link_analysis, Exception) else {"error": str(link_analysis)},
        dns_analysis=dns_analysis if not isinstance(dns_analysis, Exception) else {"error": str(dns_analysis)},
        browser_analysis=browser_analysis if not isinstance(browser_analysis, Exception) else {"error": str(browser_analysis)},
        shodan_analysis=shodan_analysis if not isinstance(shodan_analysis, Exception) else {"error": str(shodan_analysis)}
    )
    
    print("[+] Stage 1: Reconnaissance complete.")
    print("-" * 40)

    # --- Stage 2: Run the active vulnerability scanning engine ---
    print("[*] Stage 2: Running active vulnerability scanners...")
    
    try:
        # This is the correct multi-step logic from your original file
        available_modules = list(scanner_engine.get_available_modules().keys())
        if not available_modules:
            vulnerability_results = {"error": "No scanner modules available"}
        else:
            scan_job = await scanner_engine.create_scan(target=url, modules=available_modules)
            completed_job = await scanner_engine.execute_scan(scan_job.id)
            vulnerability_results = scanner_engine.get_scan_results(completed_job.id) or {"error": "Scan finished with no results."}
        
        print("[+] Stage 2: Vulnerability scan complete.")
    except Exception as e:
        vulnerability_results = {"error": f"Vulnerability scan failed: {str(e)}"}
        print(f"[!] Stage 2: Vulnerability scan failed: {e}")

    print("-" * 40)

    # --- Stage 3: Merge and present the final report ---
    print("\n[+] COMPREHENSIVE SCAN REPORT")
    print("=" * 40)

    final_report = {
        "target": url,
        "reconnaissance_and_analysis": recon_report,
        "active_vulnerability_scan": vulnerability_results
    }

    print(json.dumps(final_report, indent=4, default=str))
    print("=" * 40)
    print("[+] Comprehensive Scan Finished.")


async def main():
    """Main function to run the Sentinel tool."""
    while True:
        print_menu()
        try:
            choice = input("Enter your choice: ")
        except EOFError:
            print("\nGoodbye!")
            break

        if choice == '6':
            print("Exiting...")
            break
        elif choice == '0':
            url = input("Enter the target URL (e.g., https://example.com): ")
            await run_comprehensive_scan(url)
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")