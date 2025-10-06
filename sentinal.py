import os
import asyncio
import json

# Module imports – using actual class names and methods
from modules.browser_checker import BrowserChecker
from modules.dns_inspector import DNSInspector
from modules.link_analyzer import LinkAnalyzer
from modules.shodan_scanner import ShodanScanner
from modules.report_generator import ReportGenerator


def print_menu():
    print("\n=== SENTINEL Tools ===")
    print("11. Shodan Search")
    print("12. DNS Inspector")
    print("13. Link Analyzer")
    print("14. Browser Checker")
    print("15. Generate Report")
    print("0. Exit")


async def run_shodan_search():
    try:
        target = input("Enter the target URL (e.g., https://example.com): ").strip()
        api_key = os.getenv("SHODAN_API_KEY", "").strip()
        if not api_key:
            print("Error: SHODAN_API_KEY environment variable is not set.")
            print("Set it via: setx SHODAN_API_KEY your_api_key (Windows) and restart your shell.")
            return
        scanner = ShodanScanner(api_key)
        result = await scanner.scan(target)
        print(json.dumps(result, indent=2, default=str))
    except Exception as e:
        print(f"Error: {e}")


async def run_dns_inspector():
    try:
        url = input("Enter the URL for DNS inspection (e.g., https://example.com): ").strip()
        inspector = DNSInspector()
        result = await inspector.inspect(url)
        print(json.dumps(result, indent=2, default=str))
    except Exception as e:
        print(f"Error: {e}")


async def run_link_analyzer():
    try:
        url = input("Enter the URL for link analysis: ").strip()
        analyzer = LinkAnalyzer()
        result = await analyzer.analyze(url)
        print(json.dumps(result, indent=2, default=str))
    except Exception as e:
        print(f"Error: {e}")


async def run_browser_checker():
    try:
        url = input("Enter the URL to check in headless browser: ").strip()
        checker = BrowserChecker()
        result = await checker.check(url)
        print(json.dumps(result, indent=2, default=str))
    except Exception as e:
        print(f"Error: {e}")


async def run_generate_report():
    try:
        url = input("Enter the URL to generate a combined report for: ").strip()

        # Initialize modules
        checker = BrowserChecker()
        inspector = DNSInspector()
        analyzer = LinkAnalyzer()

        # Shodan requires API key; handle gracefully if missing
        api_key = os.getenv("SHODAN_API_KEY", "").strip()
        shodan_scanner = ShodanScanner(api_key) if api_key else None

        # Run analyses concurrently
        tasks = [
            checker.check(url),
            inspector.inspect(url),
            analyzer.analyze(url),
            shodan_scanner.scan(url) if shodan_scanner else asyncio.sleep(0, result={})
        ]

        browser_analysis, dns_analysis, link_analysis, shodan_analysis = await asyncio.gather(*tasks, return_exceptions=False)

        # Generate report
        report_gen = ReportGenerator()
        report = report_gen.generate(
            url=url,
            link_analysis=link_analysis,
            dns_analysis=dns_analysis,
            browser_analysis=browser_analysis,
            shodan_analysis=shodan_analysis if isinstance(shodan_analysis, dict) else {}
        )

        print(json.dumps(report, indent=2, default=str))
    except Exception as e:
        print(f"Error: {e}")


async def main():
    while True:
        print_menu()
        choice = input("Enter your choice: ").strip()
        if choice == "0":
            print("Goodbye!")
            break
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
    asyncio.run(main())


