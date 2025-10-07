"""Scanner modules for vulnerability detection."""

# Import modules that don't require external dependencies first
from .http_scanner import HTTPSecurityScanner
from .dns_enumeration import DNSEnumerationModule
from .content_discovery import ContentDiscoveryModule
from .info_disclosure import InfoDisclosureScanner
from .xss_scanner import XSSScanner
from .command_injection import CommandInjectionScanner
from .sql_injection import SQLInjectionScanner
from .browser_checker import BrowserChecker
from .dns_inspector import DNSInspector
from .link_analyzer import LinkAnalyzer
from .report_generator import ReportGenerator
from .shodan_scanner import ShodanScanner

# Module registry - start with available modules
SCANNER_MODULES = {
    "http_scanner": HTTPSecurityScanner,
    "dns_enumeration": DNSEnumerationModule,
    "content_discovery": ContentDiscoveryModule,
    "info_disclosure": InfoDisclosureScanner,
    "xss_scanner": XSSScanner,
    "command_injection": CommandInjectionScanner,
    "sql_injection": SQLInjectionScanner,
    "browser_checker": BrowserChecker,
    "dns_inspector": DNSInspector,
    "link_analyzer": LinkAnalyzer,
    "report_generator": ReportGenerator,
    "shodan_scanner": ShodanScanner,
}

# Try to import modules with external dependencies
try:
    # First check if nmap is available
    import nmap
    # If nmap is available, use the original scanner
    from .network_scanner import NetworkScanner
    SCANNER_MODULES["network_scanner"] = NetworkScanner
except (ImportError, Exception) as e:
    # Use alternative scanner that doesn't require nmap
    try:
        from .network_scanner_alternative import NetworkScanner
        SCANNER_MODULES["network_scanner"] = NetworkScanner
        print("Using alternative network scanner (nmap-free)")
    except ImportError as e2:
        print(f"Neither network scanner available: {e}, {e2}")

try:
    from .ssl_scanner import SSLScanner
    SCANNER_MODULES["ssl_scanner"] = SSLScanner
except ImportError:
    pass  # SSLyze not installed

try:
    from .cve_mapper import CVEMapper
    SCANNER_MODULES["cve_mapper"] = CVEMapper
except ImportError:
    pass  # nvdlib not installed

try:
    from .authenticated_scanner import AuthenticatedScanner
    SCANNER_MODULES["authenticated_scanner"] = AuthenticatedScanner
except ImportError:
    pass  # Selenium not installed

__all__ = [
    "HTTPSecurityScanner",
    "DNSEnumerationModule",
    "ContentDiscoveryModule",
    "InfoDisclosureScanner",
    "XSSScanner",
    "CommandInjectionScanner",
    "SQLInjectionScanner",
    "BrowserChecker",
    "DNSInspector",
    "LinkAnalyzer",
    "ReportGenerator",
    "ShodanScanner",
    # Add the other scanners here as well
    "NetworkScanner",
    "SSLScanner",
    "CVEMapper",
    "AuthenticatedScanner",
    "SCANNER_MODULES",
]
