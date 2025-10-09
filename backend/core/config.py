"""Configuration management for SENTINEL."""

from typing import Optional, List, Dict
from pydantic_settings import BaseSettings
from pydantic import Field, validator
import os
from pathlib import Path

class Settings(BaseSettings):
    """Application settings."""
    
    # Application
    app_name: str = Field(default="SENTINEL", env="APP_NAME")
    app_version: str = Field(default="1.0.0", env="APP_VERSION")
    debug: bool = Field(default=False, env="DEBUG")
    secret_key: str = Field(default="change-me-in-production", env="SECRET_KEY")
    
    # API Configuration
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    api_prefix: str = Field(default="/api/v1", env="API_PREFIX")
    
    # Database - Using SQLite for simplicity
    database_url: str = Field(default="sqlite:///./sentinel.db", env="DATABASE_URL")
    database_pool_size: int = Field(default=20, env="DATABASE_POOL_SIZE")
    database_max_overflow: int = Field(default=40, env="DATABASE_MAX_OVERFLOW")
    
    # Redis/Celery
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    celery_broker_url: str = Field(default="redis://localhost:6379/0", env="CELERY_BROKER_URL")
    celery_result_backend: str = Field(default="redis://localhost:6379/0", env="CELERY_RESULT_BACKEND")
    
    # Scanning Configuration
    max_concurrent_scans: int = Field(default=5, env="MAX_CONCURRENT_SCANS")
    scan_timeout_seconds: int = Field(default=3600, env="SCAN_TIMEOUT_SECONDS")
    rate_limit_requests_per_minute: int = Field(default=60, env="RATE_LIMIT_REQUESTS_PER_MINUTE")
    max_scan_depth: int = Field(default=3, env="MAX_SCAN_DEPTH")
    
    # XSS Scanner Configuration - NEW
    xss_passive_payload_limit: int = Field(default=5, env="XSS_PASSIVE_PAYLOAD_LIMIT")
    xss_active_payload_limit: int = Field(default=20, env="XSS_ACTIVE_PAYLOAD_LIMIT")
    xss_aggressive_payload_limit: int = Field(default=50, env="XSS_AGGRESSIVE_PAYLOAD_LIMIT")
    xss_enable_browser_testing: bool = Field(default=True, env="XSS_ENABLE_BROWSER_TESTING")
    
    # Link Analyzer Configuration
    link_analyzer_timeout: int = Field(default=10, env="LINK_ANALYZER_TIMEOUT")
    link_analyzer_max_depth: int = Field(default=3, env="LINK_ANALYZER_MAX_DEPTH")
    link_analyzer_max_urls: int = Field(default=50, env="LINK_ANALYZER_MAX_URLS")
    link_analyzer_respect_robots: bool = Field(default=False, env="LINK_ANALYZER_RESPECT_ROBOTS")
    link_analyzer_use_js_rendering: bool = Field(default=False, env="LINK_ANALYZER_USE_JS_RENDERING")
    link_analyzer_integrate_with_scanners: bool = Field(default=False, env="LINK_ANALYZER_INTEGRATE_WITH_SCANNERS")
    
    # Crawler Configuration
    crawler_user_agent: str = Field(default="SENTINEL-Crawler/1.0", env="CRAWLER_USER_AGENT")
    crawler_delay_seconds: float = Field(default=0.5, env="CRAWLER_DELAY_SECONDS")
    crawler_max_redirects: int = Field(default=10, env="CRAWLER_MAX_REDIRECTS")
    crawler_verify_ssl: bool = Field(default=False, env="CRAWLER_VERIFY_SSL")
    
    # Browser Configuration
    browser_headless: bool = Field(default=True, env="BROWSER_HEADLESS")
    browser_timeout: int = Field(default=30000, env="BROWSER_TIMEOUT")
    browser_wait_for_network_idle: bool = Field(default=True, env="BROWSER_WAIT_FOR_NETWORK_IDLE")
    
    # Vulnerability Testing Configuration
    vulnerability_test_timeout: int = Field(default=10, env="VULNERABILITY_TEST_TIMEOUT")
    open_redirect_test_enabled: bool = Field(default=True, env="OPEN_REDIRECT_TEST_ENABLED")
    header_injection_test_enabled: bool = Field(default=True, env="HEADER_INJECTION_TEST_ENABLED")
    crlf_injection_test_enabled: bool = Field(default=True, env="CRLF_INJECTION_TEST_ENABLED")
    
    # SSL Configuration
    ssl_validation_timeout: int = Field(default=10, env="SSL_VALIDATION_TIMEOUT")
    ssl_cert_expiry_warning_days: int = Field(default=30, env="SSL_CERT_EXPIRY_WARNING_DAYS")
    ssl_weak_cipher_penalty: int = Field(default=10, env="SSL_WEAK_CIPHER_PENALTY")
    
    # Security Settings
    require_consent: bool = Field(default=True, env="REQUIRE_CONSENT")
    allow_active_scanning: bool = Field(default=False, env="ALLOW_ACTIVE_SCANNING")
    jwt_secret_key: str = Field(default="your-jwt-secret-key", env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    # External API Keys
    shodan_api_key: Optional[str] = Field(default=None, env="SHODAN_API_KEY")
    virustotal_api_key: Optional[str] = Field(default=None, env="VIRUSTOTAL_API_KEY")
    vulners_api_key: Optional[str] = Field(default=None, env="VULNERS_API_KEY")
    nvd_api_key: Optional[str] = Field(default=None, env="NVD_API_KEY")
    gemini_api_key: Optional[str] = Field(default=None, env="GEMINI_API_KEY")
    google_safe_browsing_api_key: Optional[str] = Field(default=None, env="GOOGLE_SAFE_BROWSING_API_KEY")
    urlscan_api_key: Optional[str] = Field(default=None, env="URLSCAN_API_KEY")
    alienvault_otx_api_key: Optional[str] = Field(default=None, env="ALIENVAULT_OTX_API_KEY")
    
    # Storage
    reports_dir: Path = Field(default=Path("./reports"), env="REPORTS_DIR")
    scan_results_dir: Path = Field(default=Path("./scan_results"), env="SCAN_RESULTS_DIR")
    log_dir: Path = Field(default=Path("./logs"), env="LOG_DIR")
    
    # Authentication Scanner Configuration
    enable_auth_bruteforce_testing: bool = Field(default=False, env="ENABLE_AUTH_BRUTEFORCE_TESTING")
    auth_bruteforce_max_attempts: int = Field(default=50, env="AUTH_BRUTEFORCE_MAX_ATTEMPTS")
    auth_bruteforce_wordlist_path: Optional[str] = Field(default=None, env="AUTH_BRUTEFORCE_WORDLIST_PATH")
    auth_rate_limit_threshold_rps: int = Field(default=5, env="AUTH_RATE_LIMIT_THRESHOLD_RPS")
    auth_username_enum_sensitivity: float = Field(default=0.15, env="AUTH_USERNAME_ENUM_SENSITIVITY")
    auth_idle_timeout_seconds: int = Field(default=120, env="AUTH_IDLE_TIMEOUT_SECONDS")
    auth_common_logout_paths: List[str] = Field(
        default=["/logout", "/signout", "/sign-out", "/api/auth/logout", "/api/logout", "/auth/logout"],
        env="AUTH_COMMON_LOGOUT_PATHS"
    )
    use_lm_studio_analyzer: bool = Field(default=True, env="USE_LM_STUDIO_ANALYZER")
    
    # Feature Flags
    enable_authenticated_scanning: bool = Field(default=True, env="ENABLE_AUTHENTICATED_SCANNING")
    enable_injection_testing: bool = Field(default=False, env="ENABLE_INJECTION_TESTING")
    enable_osint_modules: bool = Field(default=True, env="ENABLE_OSINT_MODULES")
    enable_cve_mapping: bool = Field(default=True, env="ENABLE_CVE_MAPPING")
    
    class Config:
        env_file = ".env"
        case_sensitive = False
    
    @validator("reports_dir", "scan_results_dir", "log_dir", pre=True)
    def create_directories(cls, v):
        """Create directories if they don't exist."""
        path = Path(v)
        path.mkdir(parents=True, exist_ok=True)
        return path
    
    @property
    def scan_modules(self) -> List[str]:
        """Get list of enabled scan modules based on feature flags."""
        # Always enable core modules
        modules = [
            "http_scanner",
            "dns_enumeration",
            "content_discovery",
            "info_disclosure",
            "ssl_scanner",
            "network_scanner",
        ]
        
        # Always include injection testing modules for comprehensive scans
        # They will only run in ACTIVE/AGGRESSIVE mode anyway
        modules.extend([
            "sql_injection",
            "xss_scanner",
            "command_injection",
            "ssrf_scanner",
            "rce_scanner",
        ])
        
        if self.enable_osint_modules:
            modules.append("osint_footprint")
        
        if self.enable_cve_mapping:
            modules.append("cve_mapper")
        
        if self.enable_authenticated_scanning:
            modules.append("authenticated_scanner")
        
        return modules
    
    @property
    def reputation_api_keys(self) -> Dict[str, str]:
        """Get dictionary of reputation API keys for LinkAnalyzer."""
        keys = {}
        if self.google_safe_browsing_api_key:
            keys['google_safe_browsing'] = self.google_safe_browsing_api_key
        if self.virustotal_api_key:
            keys['virustotal'] = self.virustotal_api_key
        if self.urlscan_api_key:
            keys['urlscan'] = self.urlscan_api_key
        if self.alienvault_otx_api_key:
            keys['alienvault_otx'] = self.alienvault_otx_api_key
        return keys

# Create settings instance
settings = Settings()