"""Scan-related database models."""

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, JSON,
    ForeignKey, Enum as SQLEnum, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
import uuid
import enum

from backend.core.database import Base
from backend.scanner.base_module import SeverityLevel, ScanType

class ScanStatus(enum.Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class Scan(Base):
    """Main scan table."""
    __tablename__ = "scans"
    
    # Primary key
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Basic information
    target = Column(String(500), nullable=False, index=True)
    scan_type = Column(SQLEnum(ScanType), default=ScanType.PASSIVE, nullable=False)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    
    # Timing
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    
    # Configuration
    config = Column(JSON, default={})
    modules_requested = Column(JSON, default=[])  # List of module names
    
    # Progress tracking
    progress = Column(Float, default=0.0)
    current_module = Column(String(100))
    
    # Results summary
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    
    # Metadata
    metadata = Column(JSON, default={})
    errors = Column(JSON, default=[])
    
    # User/Tenant information (for multi-tenancy)
    user_id = Column(String(36), index=True)  # Would be foreign key in production
    tenant_id = Column(String(36), index=True)  # For multi-tenancy
    
    # Relationships
    modules = relationship("ScanModule", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("ScanVulnerability", back_populates="scan", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_scan_user_status', 'user_id', 'status'),
        Index('idx_scan_tenant_created', 'tenant_id', 'created_at'),
        Index('idx_scan_target_date', 'target', 'created_at'),
    )
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'target': self.target,
            'scan_type': self.scan_type.value if self.scan_type else None,
            'status': self.status.value if self.status else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'progress': self.progress,
            'current_module': self.current_module,
            'total_vulnerabilities': self.total_vulnerabilities,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'info_count': self.info_count,
            'modules_requested': self.modules_requested,
            'config': self.config,
            'metadata': self.metadata,
            'errors': self.errors
        }

class ScanModule(Base):
    """Scan module execution results."""
    __tablename__ = "scan_modules"
    
    # Primary key
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Foreign key
    scan_id = Column(String(36), ForeignKey('scans.id'), nullable=False)
    
    # Module information
    module_name = Column(String(100), nullable=False)
    module_version = Column(String(20))
    
    # Execution details
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    success = Column(Boolean, default=False)
    
    # Results
    vulnerabilities_found = Column(Integer, default=0)
    errors = Column(JSON, default=[])
    warnings = Column(JSON, default=[])
    info = Column(JSON, default={})
    statistics = Column(JSON, default={})
    
    # Raw output (for debugging)
    raw_output = Column(Text)
    
    # Relationships
    scan = relationship("Scan", back_populates="modules")
    
    # Indexes
    __table_args__ = (
        Index('idx_module_scan_name', 'scan_id', 'module_name'),
    )
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'module_name': self.module_name,
            'module_version': self.module_version,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'success': self.success,
            'vulnerabilities_found': self.vulnerabilities_found,
            'errors': self.errors,
            'warnings': self.warnings,
            'info': self.info,
            'statistics': self.statistics
        }

class ScanVulnerability(Base):
    """Vulnerabilities found during scans."""
    __tablename__ = "scan_vulnerabilities"
    
    # Primary key
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Foreign key
    scan_id = Column(String(36), ForeignKey('scans.id'), nullable=False)
    
    # Vulnerability details
    module = Column(String(100), nullable=False)
    name = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(SQLEnum(SeverityLevel), nullable=False, index=True)
    confidence = Column(Float, default=1.0)
    
    # Scoring
    cvss_score = Column(Float)
    risk_score = Column(Float)  # Custom risk scoring
    
    # Identifiers
    cve_ids = Column(JSON, default=[])
    cwe_ids = Column(JSON, default=[])
    
    # Affected resources
    affected_urls = Column(JSON, default=[])
    affected_parameters = Column(JSON, default=[])
    
    # Evidence and proof
    evidence = Column(JSON, default={})
    request = Column(Text)  # HTTP request that triggered the vulnerability
    response = Column(Text)  # HTTP response showing the vulnerability
    
    # Remediation
    remediation = Column(Text)
    references = Column(JSON, default=[])
    
    # Status
    false_positive = Column(Boolean, default=False)
    verified = Column(Boolean, default=False)
    fixed = Column(Boolean, default=False)
    
    # Metadata
    metadata = Column(JSON, default={})
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")
    
    # Indexes
    __table_args__ = (
        Index('idx_vuln_scan_severity', 'scan_id', 'severity'),
        Index('idx_vuln_module', 'module'),
        Index('idx_vuln_name', 'name'),
        Index('idx_vuln_cve', 'cve_ids'),
    )
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'module': self.module,
            'name': self.name,
            'description': self.description,
            'severity': self.severity.value if self.severity else None,
            'confidence': self.confidence,
            'cvss_score': self.cvss_score,
            'risk_score': self.risk_score,
            'cve_ids': self.cve_ids,
            'cwe_ids': self.cwe_ids,
            'affected_urls': self.affected_urls,
            'affected_parameters': self.affected_parameters,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'references': self.references,
            'false_positive': self.false_positive,
            'verified': self.verified,
            'fixed': self.fixed,
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }
    
    def calculate_risk_score(self):
        """Calculate custom risk score based on multiple factors."""
        base_score = 0.0
        
        # Severity weight
        severity_weights = {
            SeverityLevel.CRITICAL: 10.0,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.0,
            SeverityLevel.LOW: 2.5,
            SeverityLevel.INFO: 1.0
        }
        base_score = severity_weights.get(self.severity, 0.0)
        
        # Adjust by confidence
        base_score *= self.confidence
        
        # Adjust by CVSS if available
        if self.cvss_score:
            base_score = (base_score + self.cvss_score) / 2
        
        # Increase if has CVE
        if self.cve_ids and len(self.cve_ids) > 0:
            base_score *= 1.2
        
        # Cap at 10
        self.risk_score = min(base_score, 10.0)
        return self.risk_score
