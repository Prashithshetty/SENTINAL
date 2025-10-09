"""Base module interface for all scanner plugins."""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
import uuid

class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanType(Enum):
    """Types of scans."""
    PASSIVE = "passive"
    ACTIVE = "active"
    AGGRESSIVE = "aggressive"

@dataclass
class ScanConfig:
    """Configuration for a scan."""
    target: str
    scan_type: ScanType = ScanType.PASSIVE
    timeout: int = 300
    rate_limit: int = 10  # requests per second
    max_depth: int = 3
    follow_redirects: bool = True
    user_agent: str = "SENTINEL/1.0"
    proxy: Optional[str] = None
    cookies: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    auth: Optional[Dict[str, Any]] = None
    debug: bool = False  # Debug mode for verbose output
    custom_params: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    module: str = ""
    name: str = ""
    description: str = ""
    severity: SeverityLevel = SeverityLevel.INFO
    confidence: float = 0.0  # 0.0 to 1.0
    cvss_score: Optional[float] = None
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    affected_urls: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    false_positive: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanResult:
    """Results from a scan module."""
    module_name: str
    success: bool
    started_at: datetime
    completed_at: datetime
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    info: Dict[str, Any] = field(default_factory=dict)
    statistics: Dict[str, Any] = field(default_factory=dict)

class BaseScannerModule(ABC):
    """Base class for all scanner modules."""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.description = ""
        self.author = "SENTINEL"
        self.scan_type = ScanType.PASSIVE
        self.enabled = True
        
    @abstractmethod
    async def scan(self, config: ScanConfig) -> ScanResult:
        """
        Perform the scan.
        
        Args:
            config: Scan configuration
            
        Returns:
            ScanResult object containing vulnerabilities and metadata
        """
        pass
    
    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """
        Validate if the target is suitable for this module.
        
        Args:
            target: Target URL or IP
            
        Returns:
            True if target is valid for this module
        """
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """Get module information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "scan_type": self.scan_type.value,
            "enabled": self.enabled,
        }
    
    def requires_auth(self) -> bool:
        """Check if module requires authentication."""
        return False
    
    def get_required_permissions(self) -> List[str]:
        """Get required permissions for this module."""
        return []
    
    async def pre_scan(self, config: ScanConfig) -> bool:
        """
        Pre-scan checks and setup.
        
        Returns:
            True if pre-scan successful
        """
        return self.validate_target(config.target)
    
    async def post_scan(self, result: ScanResult) -> None:
        """Post-scan cleanup."""
        pass
