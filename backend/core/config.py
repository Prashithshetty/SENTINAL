"""Configuration management for SENTINEL."""

from typing import Optional, List
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
    
    # Storage
    reports_dir: Path = Field(default=Path("./reports"), env="REPORTS_DIR")
    scan_results_dir: Path = Field(default=Path("./scan_results"), env="SCAN_RESULTS_DIR")
    log_dir: Path = Field(default=Path("./logs"), env="LOG_DIR")
    
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
        modules = [
            "network_scanner",
            "dns_enumeration",
            "ssl_scanner",
            "http_scanner",
            "content_discovery",
            "info_disclosure",
        ]
        
        if self.enable_injection_testing:
            modules.extend([
                "sql_injection",
                "xss_scanner",
                "command_injection",
            ])
        
        if self.enable_osint_modules:
            modules.append("osint_footprint")
        
        if self.enable_cve_mapping:
            modules.append("cve_mapper")
        
        if self.enable_authenticated_scanning:
            modules.append("authenticated_scanner")
        
        return modules

# Create settings instance
settings = Settings()
