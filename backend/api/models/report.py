"""Report generation models."""

from sqlalchemy import (
    Column, String, Integer, Text, JSON, Boolean, DateTime,
    ForeignKey, Enum as SQLEnum, Index, LargeBinary
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum

from backend.core.database import Base

class ReportFormat(enum.Enum):
    """Report format types."""
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    MARKDOWN = "markdown"

class ReportStatus(enum.Enum):
    """Report generation status."""
    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"

class Report(Base):
    """Generated reports for scans."""
    __tablename__ = "reports"
    
    # Primary key
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Foreign key
    scan_id = Column(String(36), ForeignKey('scans.id'), nullable=False)
    
    # Report details
    name = Column(String(500), nullable=False)
    description = Column(Text)
    format = Column(SQLEnum(ReportFormat), nullable=False)
    status = Column(SQLEnum(ReportStatus), default=ReportStatus.PENDING, nullable=False)
    
    # Report configuration
    config = Column(JSON, default={})
    include_technical_details = Column(Boolean, default=True)
    include_remediation = Column(Boolean, default=True)
    include_evidence = Column(Boolean, default=True)
    executive_summary = Column(Text)
    
    # Filters applied
    severity_filter = Column(JSON, default=[])  # List of severities to include
    module_filter = Column(JSON, default=[])  # List of modules to include
    false_positive_excluded = Column(Boolean, default=True)
    
    # Generated content
    file_path = Column(String(500))
    file_size = Column(Integer)
    content = Column(LargeBinary)  # For small reports, store in DB
    
    # Metadata
    generated_at = Column(DateTime(timezone=True))
    generated_by = Column(String(100))  # User or system
    download_count = Column(Integer, default=0)
    
    # Timing
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # User/Tenant information
    user_id = Column(String(36), index=True)
    tenant_id = Column(String(36), index=True)
    
    # Indexes
    __table_args__ = (
        Index('idx_report_scan', 'scan_id'),
        Index('idx_report_user', 'user_id'),
        Index('idx_report_status', 'status'),
    )
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'name': self.name,
            'description': self.description,
            'format': self.format.value if self.format else None,
            'status': self.status.value if self.status else None,
            'config': self.config,
            'include_technical_details': self.include_technical_details,
            'include_remediation': self.include_remediation,
            'include_evidence': self.include_evidence,
            'executive_summary': self.executive_summary,
            'severity_filter': self.severity_filter,
            'module_filter': self.module_filter,
            'false_positive_excluded': self.false_positive_excluded,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'generated_at': self.generated_at.isoformat() if self.generated_at else None,
            'generated_by': self.generated_by,
            'download_count': self.download_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
