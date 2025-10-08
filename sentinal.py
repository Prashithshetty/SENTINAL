import os
import asyncio
import json
from urllib.parse import urlparse
from datetime import datetime
from pathlib import Path
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
from backend.scanner.base_module import ScanType, ScanConfig
from backend.core.config import settings


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


def save_scan_result(result: dict, scan_type: str, target: str = None):
    """
    Saves the scan result to a JSON file with intelligent naming.
    
    Args:
        result: The scan result dictionary
        scan_type: Type of scan (e.g., 'comprehensive', 'shodan', 'dns', etc.)
        target: Optional target URL/domain for better filename generation
    """
    try:
        # Ensure the scan_results directory exists
        results_dir = Path("scan_results")
        results_dir.mkdir(exist_ok=True)
        
        # Generate filename based on available information
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Try to get scan_id from result
        scan_id = result.get("id") or result.get("scan_id")
        
        if scan_id:
            filename = f"{scan_id}_{scan_type}.json"
        elif target:
            # Clean target for filename (remove protocol, replace special chars)
            clean_target = extract_domain(target) or target
            clean_target = clean_target.replace(':', '_').replace('/', '_').replace('.', '_')
            filename = f"{clean_target}_{scan_type}_{timestamp}.json"
        else:
            filename = f"{scan_type}_{timestamp}.json"
        
        file_path = results_dir / filename
        
        # Save the result with metadata
        output = {
            "scan_metadata": {
                "scan_type": scan_type,
                "timestamp": datetime.now().isoformat(),
                "target": target
            },
            "results": result
        }
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=4, default=str)
        
        print(f"\n[+] Scan result saved to: {file_path}")
        return str(file_path)
        
    except Exception as e:
        print(f"\n[!] Error saving scan result: {e}")
        return None


def print_menu():
    """Prints the main menu for the toolkit."""
    print("\n--- Sentinel Security Toolkit ---")
    print("0. Comprehensive Scan (All Modules)")
    
    # Dynamically list all available scanner modules
    modules = list(scanner_engine.get_available_modules().keys())
    for i, module_name in enumerate(modules):
        print(f"{i + 1}. Run '{module_name}' Module")

    # Add other tools
    offset = len(modules) + 1
    print(f"{offset}. Shodan Search")
    print(f"{offset + 1}. DNS Inspector")
    print(f"{offset + 2}. Link Analyzer")
    print(f"{offset + 3}. Browser Checker")
    print(f"{offset + 4}. Web Crawler")
    print(f"{offset + 5}. Generate Report")
    print(f"{offset + 6}. Exit")


async def run_individual_module(module_name: str):
    """Runs a single specified scanner module."""
    try:
        url = input(f"Enter the target URL for the '{module_name}' scan: ").strip()
        normalized_url = normalize_url(url)
        
        if not normalized_url:
            print("Error: Invalid URL format.")
            return

        print(f"\n[+] Starting '{module_name}' scan for: {normalized_url}")
        print("-" * 40)

        config = ScanConfig(
            target=normalized_url,
            scan_type=ScanType.ACTIVE,  # Run in active mode for thorough testing
            timeout=3600,
            rate_limit=1,
            max_depth=3
        )
        
        scan_job = await scanner_engine.create_scan(
            target=normalized_url,
            modules=[module_name],
            config=config
        )
        
        print(f"[*] Executing '{module_name}' module...")
        completed_job = await scanner_engine.execute_scan(scan_job.id)
        vulnerability_results = scanner_engine.get_scan_results(completed_job.id) or {"error": "Scan finished with no results."}
        
        print(json.dumps(vulnerability_results, indent=4, default=str))
        print("-" * 40)
        print(f"[+] '{module_name}' scan finished.")
        
        # Save the result
        save_scan_result(vulnerability_results, f"module_{module_name}", normalized_url)

    except Exception as e:
        print(f"Error running '{module_name}' scan: {e}")
        import traceback
        traceback.print_exc()


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
        
        # Save the result
        save_scan_result(result, "shodan", domain)
        
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
        
        # Save the result
        save_scan_result(result, "dns", domain)
        
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
        
        # Get API keys from settings
        api_keys = settings.reputation_api_keys
        analyzer = LinkAnalyzer(api_keys=api_keys)
        result = await analyzer.analyze(normalized_url)
        print(json.dumps(result, indent=2, default=str))
        
        # Save the result
        save_scan_result(result, "link_analysis", normalized_url)
        
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
        
        # Save the result
        save_scan_result(result, "browser_check", normalized_url)
        
    except Exception as e:
        print(f"Error: {e}")


async def run_web_crawler():
    """Runs the web crawler to discover URLs."""
    try:
        url = input("Enter the starting URL to crawl: ").strip()
        normalized_url = normalize_url(url)
        
        if not normalized_url:
            print("Error: Invalid URL format")
            return
        
        # Get crawl parameters
        try:
            max_depth = int(input("Enter maximum crawl depth (default: 3): ").strip() or "3")
            max_urls = int(input("Enter maximum URLs to discover (default: 50): ").strip() or "50")
        except ValueError:
            print("Invalid input. Using defaults: depth=3, max_urls=50")
            max_depth = 3
            max_urls = 50
        
        # Get API keys from settings
        api_keys = settings.reputation_api_keys
        crawler = LinkAnalyzer(api_keys=api_keys)
        result = await crawler.crawl(normalized_url, max_depth=max_depth, max_urls=max_urls)
        
        print("\n" + "=" * 60)
        print("CRAWL RESULTS")
        print("=" * 60)
        print(json.dumps(result, indent=2, default=str))
        
        # Save the result
        save_scan_result(result, "crawl", normalized_url)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


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
        # Get API keys from settings
        api_keys = settings.reputation_api_keys
        analyzer = LinkAnalyzer(api_keys=api_keys)
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
        
        # Save the report
        save_scan_result(report, "combined_report", normalized_url)
        
    except Exception as e:
        print(f"Error: {e}")


async def run_comprehensive_scan():
    """Runs a full reconnaissance and vulnerability scan with web crawling."""
    try:
        url = input("Enter the target URL for comprehensive scan (e.g., example.com or https://example.com): ").strip()
        normalized_url = normalize_url(url)
        domain = extract_domain(url)

        if not normalized_url or not domain:
            print("Error: Invalid URL format. Please provide a valid URL or domain.")
            return

        print(f"\n[+] Starting Comprehensive Scan for: {normalized_url}")
        print(f"[+] Domain: {domain}")
        print("-" * 60)

        # --- Stage 1: Web Crawling ---
        print("[*] Stage 1: Web Crawling - Discovering URLs and endpoints...")
        
        try:
            # Get API keys from settings
            api_keys = settings.reputation_api_keys
            crawler = LinkAnalyzer(api_keys=api_keys)
            crawl_result = await crawler.crawl(normalized_url, max_depth=3, max_urls=30)
            discovered_urls = crawl_result.get('discovered_urls', [normalized_url])
            urls_with_params = crawl_result.get('urls_with_parameters', [])
            forms = crawl_result.get('forms', [])
            
            print(f"[+] Stage 1 Complete:")
            print(f"    - Total URLs discovered: {len(discovered_urls)}")
            print(f"    - URLs with parameters: {len(urls_with_params)}")
            print(f"    - Forms found: {len(forms)}")
            
        except Exception as e:
            print(f"[!] Stage 1: Crawling failed: {e}")
            discovered_urls = [normalized_url]
            urls_with_params = []
            forms = []
            crawl_result = {"error": str(e)}
        
        print("-" * 60)

        # --- Stage 2: Run reconnaissance modules ---
        print("[*] Stage 2: Running reconnaissance modules (DNS, Shodan, Browser, Link)...")

        browser_checker = BrowserChecker()
        dns_inspector = DNSInspector()
        # Get API keys from settings
        api_keys = settings.reputation_api_keys
        link_analyzer = LinkAnalyzer(api_keys=api_keys)
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

        print("[+] Stage 2: Reconnaissance complete.")
        print("-" * 60)

        # --- Stage 3: Run vulnerability scanners on discovered URLs ---
        print("[*] Stage 3: Running active vulnerability scanners...")
        print(f"[*] Testing {len(discovered_urls)} discovered URLs for vulnerabilities...")

        try:
            # Get all available modules
            available_modules = list(scanner_engine.get_available_modules().keys())
            print(f"[*] Available scanner modules: {', '.join(available_modules)}")
            
            if not available_modules:
                vulnerability_results = {"error": "No scanner modules available"}
            else:
                # Prioritize URLs with parameters for injection testing
                priority_urls = urls_with_params if urls_with_params else discovered_urls[:10]
                
                print(f"[*] Priority testing on {len(priority_urls)} URLs with parameters/forms")
                
                all_vulnerabilities = []
                scan_results_by_url = {}
                
                # Scan each discovered URL
                for idx, test_url in enumerate(priority_urls, 1):
                    print(f"[*] [{idx}/{len(priority_urls)}] Scanning: {test_url}")
                    
                    config = ScanConfig(
                        target=test_url,
                        scan_type=ScanType.ACTIVE,
                        timeout=300,  # 5 minutes per URL
                        rate_limit=1,
                        max_depth=1  # Don't recurse for each URL
                    )
                    
                    try:
                        scan_job = await scanner_engine.create_scan(
                            target=test_url,
                            modules=available_modules,
                            config=config
                        )
                        
                        completed_job = await scanner_engine.execute_scan(scan_job.id)
                        url_results = scanner_engine.get_scan_results(completed_job.id)
                        
                        if url_results:
                            scan_results_by_url[test_url] = url_results
                            # Collect vulnerabilities
                            if 'vulnerabilities' in url_results:
                                all_vulnerabilities.extend(url_results['vulnerabilities'])
                    
                    except Exception as e:
                        print(f"[!] Error scanning {test_url}: {e}")
                        scan_results_by_url[test_url] = {"error": str(e)}
                
                vulnerability_results = {
                    "total_urls_scanned": len(priority_urls),
                    "total_vulnerabilities_found": len(all_vulnerabilities),
                    "vulnerabilities": all_vulnerabilities,
                    "scan_results_by_url": scan_results_by_url
                }

            print(f"[+] Stage 3: Vulnerability scan complete.")
            print(f"    - URLs scanned: {vulnerability_results.get('total_urls_scanned', 0)}")
            print(f"    - Vulnerabilities found: {vulnerability_results.get('total_vulnerabilities_found', 0)}")
            
        except Exception as e:
            vulnerability_results = {"error": f"Vulnerability scan failed: {str(e)}"}
            print(f"[!] Stage 3: Vulnerability scan failed: {e}")
            import traceback
            traceback.print_exc()

        print("-" * 60)

        # --- Stage 4: Merge and present the final report ---
        print("\n[+] COMPREHENSIVE SCAN REPORT")
        print("=" * 60)

        final_report = {
            "target": normalized_url,
            "domain": domain,
            "scan_timestamp": datetime.now().isoformat(),
            "crawl_results": crawl_result,
            "reconnaissance_and_analysis": recon_report,
            "active_vulnerability_scan": vulnerability_results,
            "summary": {
                "urls_discovered": len(discovered_urls),
                "urls_with_parameters": len(urls_with_params),
                "forms_found": len(forms),
                "total_vulnerabilities": vulnerability_results.get('total_vulnerabilities_found', 0)
            }
        }

        print(json.dumps(final_report, indent=4, default=str))
        print("=" * 60)
        print("[+] Comprehensive Scan Finished.")
        
        # Save the comprehensive scan result
        save_scan_result(final_report, "comprehensive", normalized_url)

    except Exception as e:
        print(f"Error in comprehensive scan: {e}")
        import traceback
        traceback.print_exc()


async def main():
    """Main function to run the Sentinel tool."""
    modules = list(scanner_engine.get_available_modules().keys())
    offset = len(modules) + 1

    while True:
        print_menu()
        try:
            choice = input("Enter your choice: ").strip()
            if not choice.isdigit():
                print("Invalid choice. Please enter a number.")
                continue
            
            choice = int(choice)

        except EOFError:
            print("\nGoodbye!")
            break

        if choice == 0:
            await run_comprehensive_scan()
        elif 1 <= choice <= len(modules):
            module_name = modules[choice - 1]
            await run_individual_module(module_name)
        elif choice == offset:
            await run_shodan_search()
        elif choice == offset + 1:
            await run_dns_inspector()
        elif choice == offset + 2:
            await run_link_analyzer()
        elif choice == offset + 3:
            await run_browser_checker()
        elif choice == offset + 4:
            await run_web_crawler()
        elif choice == offset + 5:
            await run_generate_report()
        elif choice == offset + 6:
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")