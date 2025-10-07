import os
import asyncio
import json
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables from .env file at the very start
load_dotenv()

# --- Module Imports ---
from backend.scanner.modules.browser_checker import BrowserChecker
from backend.scanner.modules.dns_inspector import DNSInspector
from backend.scanner.modules.link_analyzer import LinkAnalyzer
from backend.scanner.modules.shodan_scanner import ShodanScanner
from backend.scanner.modules.report_generator import ReportGenerator
# Import the existing scanner_engine INSTANCE, not the class
from backend.scanner.engine import scanner_engine


def extract_domain(url):
    """
    Extract clean domain from URL, handling various input formats.
    Returns domain without protocol or path.
    """
    if not url:
        return None
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        # Remove port if present
        domain = domain.split(':')[0]
        return domain if domain else None
    except Exception:
        return None


def normalize_url(url):
    """
    Normalize URL to ensure it has a proper scheme.
    """
    if not url:
        return None
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    return url


def print_menu():
    """Prints the main menu for the toolkit."""
    print("\n--- Sentinel Security Toolkit ---")
    print("10. Comprehensive Scan (Recon + Vulnerability Engine)")
    print("11. Shodan Search")
    print("12. DNS Inspector")
    print("13. Link Analyzer")
    print("14. Browser Checker")
    print("15. Generate Report")
    print("0. Exit")


async def run_shodan_search():
    """Runs the Shodan search module."""
    try:
        target = input("Enter the target URL or domain (e.g., example.com or https://example.com): ").strip()
        domain = extract_domain(target)
        
        if not domain:
            print("Error: Invalid URL or domain format")
            return
        
        api_key = os.getenv("SHODAN_API_KEY", "").strip()
        if not api_key:
            print("Error: SHODAN_API_KEY environment variable is not set.")
            print("Set it via: setx SHODAN_API_KEY your_api_key (Windows) and restart your shell.")
            return
        
        scanner = ShodanScanner(api_key)
        result = await scanner.scan(domain)
        print(json.dumps(result, indent=2, default=str))
    except Exception as e:
        print(f"Error: {e}")


async def run_dns_inspector():
    """Runs the DNS inspector module."""
    try:
        url = input("Enter the URL or domain for DNS inspection (e.g., example.com or https://example.com): ").strip()
        domain = extract_domain(url)
        
        if not domain:
            print("Error: Invalid URL or domain format")
            return
        
        inspector = DNSInspector()
        result = await inspector.inspect(domain)
        print(json.dumps(result, indent=2, default=str))
    except Exception as e:
        print(f"Error: {e}")


async def run_link_analyzer():
    """Runs the link analyzer module."""
    try:
        url = input("Enter the URL for link analysis: ").strip()
        normalized_url = normalize_url(url)
        
        if not normalized_url:
            print("Error: Invalid URL format")
            return
        
        analyzer = LinkAnalyzer()
        result = await analyzer.analyze(normalized_url)
        print(json.dumps(result, indent=2, default=str))
    except Exception as e:
        print(f"Error: {e}")


async def run_browser_checker():
    """Runs the browser checker module."""
    try:
        url = input("Enter the URL to check in headless browser: ").strip()
        normalized_url = normalize_url(url)
        
        if not normalized_url:
            print("Error: Invalid URL format")
            return
        
        checker = BrowserChecker()
        result = await checker.check(normalized_url)
        print(json.dumps(result, indent=2, default=str))
    except Exception as e:
        print(f"Error: {e}")


async def run_generate_report():
    """Generates a combined report from all reconnaissance modules."""
    try:
        url = input("Enter the URL to generate a combined report for: ").strip()
        normalized_url = normalize_url(url)
        domain = extract_domain(url)
        
        if not normalized_url or not domain:
            print("Error: Invalid URL format")
            return

        # Initialize modules
        checker = BrowserChecker()
        inspector = DNSInspector()
        analyzer = LinkAnalyzer()
        report_gen = ReportGenerator()

        # Shodan requires API key; handle gracefully if missing
        api_key = os.getenv("SHODAN_API_KEY", "").strip()
        if not api_key:
            print("[!] Warning: SHODAN_API_KEY not found. Skipping Shodan scan.")
            shodan_scanner = None
        else:
            shodan_scanner = ShodanScanner(api_key)

        # Run analyses concurrently
        tasks = [
            checker.check(normalized_url),
            inspector.inspect(domain),
            analyzer.analyze(normalized_url),
            shodan_scanner.scan(domain) if shodan_scanner else asyncio.sleep(0, result={"error": "Shodan API key not configured"})
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        browser_analysis, dns_analysis, link_analysis, shodan_analysis = results

        # Generate report
        report = report_gen.generate(
            url=normalized_url,
            link_analysis=link_analysis if not isinstance(link_analysis, Exception) else {"error": str(link_analysis)},
            dns_analysis=dns_analysis if not isinstance(dns_analysis, Exception) else {"error": str(dns_analysis)},
            browser_analysis=browser_analysis if not isinstance(browser_analysis, Exception) else {"error": str(browser_analysis)},
            shodan_analysis=shodan_analysis if not isinstance(shodan_analysis, Exception) else {"error": str(shodan_analysis)}
        )

        print(json.dumps(report, indent=2, default=str))
    except Exception as e:
        print(f"Error: {e}")


async def run_comprehensive_scan():
    """Runs a full reconnaissance and vulnerability scan against a target URL."""
    try:
        url = input("Enter the target URL for comprehensive scan (e.g., example.com or https://example.com): ").strip()
        normalized_url = normalize_url(url)
        domain = extract_domain(url)

        if not normalized_url or not domain:
            print("Error: Invalid URL format. Please provide a valid URL or domain.")
            return

        print(f"\n[+] Starting Comprehensive Scan for: {normalized_url}")
        print(f"[+] Domain: {domain}")
        print("-" * 40)

        # --- Stage 1: Run all reconnaissance modules concurrently ---
        print("[*] Stage 1: Running reconnaissance modules (DNS, Shodan, Browser, Link)...")

        browser_checker = BrowserChecker()
        dns_inspector = DNSInspector()
        link_analyzer = LinkAnalyzer()
        report_generator = ReportGenerator()

        shodan_api_key = os.getenv("SHODAN_API_KEY")
        if not shodan_api_key or shodan_api_key == "your_shodan_api_key_here":
            print("[!] Warning: SHODAN_API_KEY not configured properly. Skipping Shodan scan.")
            shodan_scanner = None
        else:
            shodan_scanner = ShodanScanner(api_key=shodan_api_key)

        tasks = [
            browser_checker.check(normalized_url),
            dns_inspector.inspect(domain),
            link_analyzer.analyze(normalized_url),
            shodan_scanner.scan(domain) if shodan_scanner else asyncio.sleep(0, result={"error": "Shodan API key not configured"})
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        browser_analysis, dns_analysis, link_analysis, shodan_analysis = results

        # Handle exceptions in results
        if isinstance(shodan_analysis, Exception):
            shodan_analysis = {"error": f"Shodan scan failed: {str(shodan_analysis)}"}

        recon_report = report_generator.generate(
            url=normalized_url,
            link_analysis=link_analysis if not isinstance(link_analysis, Exception) else {"error": str(link_analysis)},
            dns_analysis=dns_analysis if not isinstance(dns_analysis, Exception) else {"error": str(dns_analysis)},
            browser_analysis=browser_analysis if not isinstance(browser_analysis, Exception) else {"error": str(browser_analysis)},
            shodan_analysis=shodan_analysis
        )

        print("[+] Stage 1: Reconnaissance complete.")
        print("-" * 40)

        # --- Stage 2: Run the active vulnerability scanning engine ---
        print("[*] Stage 2: Running active vulnerability scanners...")

        try:
            # Get all available modules
            available_modules = list(scanner_engine.get_available_modules().keys())
            print(f"[*] Available scanner modules: {', '.join(available_modules)}")
            
            if not available_modules:
                vulnerability_results = {"error": "No scanner modules available"}
            else:
                # Create scan with ACTIVE type for comprehensive scanning
                from backend.scanner.base_module import ScanType, ScanConfig
                
                config = ScanConfig(
                    target=normalized_url,
                    scan_type=ScanType.ACTIVE,  # Use ACTIVE for comprehensive scan
                    timeout=3600,
                    rate_limit=1,  # 1 request per second
                    max_depth=3
                )
                
                scan_job = await scanner_engine.create_scan(
                    target=normalized_url, 
                    modules=available_modules,
                    config=config
                )
                
                print(f"[*] Executing {len(available_modules)} scanner modules...")
                completed_job = await scanner_engine.execute_scan(scan_job.id)
                vulnerability_results = scanner_engine.get_scan_results(completed_job.id) or {"error": "Scan finished with no results."}

            print("[+] Stage 2: Vulnerability scan complete.")
        except Exception as e:
            vulnerability_results = {"error": f"Vulnerability scan failed: {str(e)}"}
            print(f"[!] Stage 2: Vulnerability scan failed: {e}")
            import traceback
            traceback.print_exc()

        print("-" * 40)

        # --- Stage 3: Merge and present the final report ---
        print("\n[+] COMPREHENSIVE SCAN REPORT")
        print("=" * 40)

        final_report = {
            "target": normalized_url,
            "domain": domain,
            "reconnaissance_and_analysis": recon_report,
            "active_vulnerability_scan": vulnerability_results
        }

        print(json.dumps(final_report, indent=4, default=str))
        print("=" * 40)
        print("[+] Comprehensive Scan Finished.")

    except Exception as e:
        print(f"Error in comprehensive scan: {e}")
        import traceback
        traceback.print_exc()


async def main():
    """Main function to run the Sentinel tool."""
    while True:
        print_menu()
        try:
            choice = input("Enter your choice: ").strip()
        except EOFError:
            print("\nGoodbye!")
            break

        if choice == "0":
            print("Goodbye!")
            break
        elif choice == "10":
            await run_comprehensive_scan()
        elif choice == "11":
            await run_shodan_search()
        elif choice == "12":
            await run_dns_inspector()
        elif choice == "13":
            await run_link_analyzer()
        elif choice == "14":
            await run_browser_checker()
        elif choice == "15":
            await run_generate_report()
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")