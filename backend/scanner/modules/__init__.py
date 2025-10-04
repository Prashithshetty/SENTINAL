"""Scanner modules for vulnerability detection."""

# Import modules that don't require external dependencies first
from .http_scanner import HTTPSecurityScanner
from .dns_enumeration import DNSEnumerationModule
from .content_discovery import ContentDiscoveryModule
from .info_disclosure import InfoDisclosureScanner
from .xss_scanner import XSSScanner
from .command_injection import CommandInjectionScanner
from .sql_injection import SQLInjectionScanner

# Module registry - start with available modules
SCANNER_MODULES = {
    "http_scanner": HTTPSecurityScanner,
    "dns_enumeration": DNSEnumerationModule,
    "content_discovery": ContentDiscoveryModule,
    "info_disclosure": InfoDisclosureScanner,
    "xss_scanner": XSSScanner,
    "command_injection": CommandInjectionScanner,
    "sql_injection": SQLInjectionScanner,
}

# Try to import modules with external dependencies
try:
    from .network_scanner import NetworkScanner
    SCANNER_MODULES["network_scanner"] = NetworkScanner
except ImportError:
    pass  # Nmap not installed

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
    "SCANNER_MODULES",
]
