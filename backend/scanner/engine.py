"""Scanner Engine - Orchestrates and manages vulnerability scanning modules."""

import asyncio
import json
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import uuid
from concurrent.futures import ThreadPoolExecutor
import logging

from .base_module import (
    BaseScannerModule,
    ScanConfig,
    ScanResult,
    Vulnerability,
    SeverityLevel,
    ScanType
)
from .modules import SCANNER_MODULES
from ..core.config import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScanStatus(Enum):
    """Scan job status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class ScanJob:
    """Represents a scan job."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    modules: List[str] = field(default_factory=list)
    config: ScanConfig = field(default_factory=ScanConfig)
    status: ScanStatus = ScanStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    results: Dict[str, ScanResult] = field(default_factory=dict)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    progress: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

class ScannerEngine:
    """Main scanner engine that orchestrates vulnerability scanning."""
    
    def __init__(self):
        self.modules: Dict[str, BaseScannerModule] = {}
        self.active_scans: Dict[str, ScanJob] = {}
        self.scan_history: List[ScanJob] = []
        self.executor = ThreadPoolExecutor(max_workers=settings.max_concurrent_scans)
        self._initialize_modules()
    
    def _initialize_modules(self):
        """Initialize all scanner modules."""
        for module_name, module_class in SCANNER_MODULES.items():
            try:
                if module_name in settings.scan_modules:
                    self.modules[module_name] = module_class()
                    logger.info(f"Initialized module: {module_name}")
            except Exception as e:
                logger.error(f"Failed to initialize module {module_name}: {str(e)}")
    
    def get_available_modules(self) -> Dict[str, Dict[str, Any]]:
        """Get information about available scanner modules."""
        modules_info = {}
        for name, module in self.modules.items():
            modules_info[name] = module.get_info()
        return modules_info
    
    def validate_scan_request(self, target: str, modules: List[str], 
                            scan_type: ScanType = ScanType.PASSIVE) -> tuple[bool, List[str]]:
        """
        Validate a scan request.
        
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Validate target
        if not target:
            errors.append("Target is required")
        
        # Validate modules
        if not modules:
            errors.append("At least one module must be selected")
        else:
            for module_name in modules:
                if module_name not in self.modules:
                    errors.append(f"Module '{module_name}' not found")
                else:
                    module = self.modules[module_name]
                    if not module.validate_target(target):
                        errors.append(f"Target not valid for module '{module_name}'")
        
        # Check consent for active scanning
        if scan_type in [ScanType.ACTIVE, ScanType.AGGRESSIVE]:
            if settings.require_consent:
                # In production, this would check a consent database
                logger.warning("Active scanning requires explicit consent")
        
        return len(errors) == 0, errors
    
    async def create_scan(self, target: str, modules: List[str], 
                         config: Optional[ScanConfig] = None,
                         metadata: Optional[Dict[str, Any]] = None) -> ScanJob:
        """
        Create a new scan job.
        
        Args:
            target: Target URL or IP
            modules: List of module names to run
            config: Scan configuration
            metadata: Additional metadata
            
        Returns:
            ScanJob object
        """
        # Create default config if not provided
        if config is None:
            config = ScanConfig(
                target=target,
                scan_type=ScanType.PASSIVE if settings.require_consent else ScanType.ACTIVE,
                timeout=settings.scan_timeout_seconds,
                rate_limit=settings.rate_limit_requests_per_minute // 60,
                max_depth=settings.max_scan_depth
            )
        else:
            config.target = target
        
        # Create scan job
        scan_job = ScanJob(
            target=target,
            modules=modules,
            config=config,
            metadata=metadata or {}
        )
        
        # Store in active scans
        self.active_scans[scan_job.id] = scan_job
        
        logger.info(f"Created scan job {scan_job.id} for target {target}")
        
        return scan_job
    
    async def execute_scan(self, scan_id: str) -> ScanJob:
        """
        Execute a scan job.
        
        Args:
            scan_id: Scan job ID
            
        Returns:
            Completed ScanJob
        """
        if scan_id not in self.active_scans:
            raise ValueError(f"Scan {scan_id} not found")
        
        scan_job = self.active_scans[scan_id]
        
        # Update status
        scan_job.status = ScanStatus.RUNNING
        scan_job.started_at = datetime.utcnow()
        
        try:
            # Execute modules
            total_modules = len(scan_job.modules)
            completed_modules = 0
            
            # Group modules by scan type for efficient execution
            passive_modules = []
            active_modules = []
            aggressive_modules = []
            
            for module_name in scan_job.modules:
                module = self.modules[module_name]
                if module.scan_type == ScanType.PASSIVE:
                    passive_modules.append(module_name)
                elif module.scan_type == ScanType.ACTIVE:
                    active_modules.append(module_name)
                else:
                    aggressive_modules.append(module_name)
            
            # Execute passive modules concurrently
            if passive_modules:
                await self._execute_module_group(
                    scan_job, passive_modules, "Passive"
                )
                completed_modules += len(passive_modules)
                scan_job.progress = (completed_modules / total_modules) * 100
            
            # Execute active modules with rate limiting
            if active_modules and scan_job.config.scan_type != ScanType.PASSIVE:
                await self._execute_module_group(
                    scan_job, active_modules, "Active", 
                    concurrent_limit=3
                )
                completed_modules += len(active_modules)
                scan_job.progress = (completed_modules / total_modules) * 100
            
            # Execute aggressive modules sequentially
            if aggressive_modules and scan_job.config.scan_type == ScanType.AGGRESSIVE:
                await self._execute_module_group(
                    scan_job, aggressive_modules, "Aggressive",
                    concurrent_limit=1
                )
                completed_modules += len(aggressive_modules)
                scan_job.progress = (completed_modules / total_modules) * 100
            
            # Aggregate vulnerabilities
            self._aggregate_vulnerabilities(scan_job)
            
            # Update status
            scan_job.status = ScanStatus.COMPLETED
            scan_job.completed_at = datetime.utcnow()
            scan_job.progress = 100.0
            
            logger.info(f"Scan {scan_id} completed successfully")
            
        except Exception as e:
            scan_job.status = ScanStatus.FAILED
            scan_job.errors.append(str(e))
            logger.error(f"Scan {scan_id} failed: {str(e)}")
        
        finally:
            # Move to history
            self.scan_history.append(scan_job)
            del self.active_scans[scan_id]
        
        return scan_job
    
    async def _execute_module_group(self, scan_job: ScanJob, 
                                   module_names: List[str],
                                   group_name: str,
                                   concurrent_limit: int = 5):
        """Execute a group of modules."""
        logger.info(f"Executing {group_name} modules for scan {scan_job.id}")
        
        # Create tasks for modules
        tasks = []
        semaphore = asyncio.Semaphore(concurrent_limit)
        
        for module_name in module_names:
            task = self._execute_module_with_limit(
                scan_job, module_name, semaphore
            )
            tasks.append(task)
        
        # Execute tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for module_name, result in zip(module_names, results):
            if isinstance(result, Exception):
                scan_job.errors.append(f"Module {module_name} failed: {str(result)}")
                logger.error(f"Module {module_name} failed: {str(result)}")
            else:
                scan_job.results[module_name] = result
                logger.info(f"Module {module_name} completed for scan {scan_job.id}")
    
    async def _execute_module_with_limit(self, scan_job: ScanJob, 
                                        module_name: str,
                                        semaphore: asyncio.Semaphore) -> ScanResult:
        """Execute a single module with concurrency limit."""
        async with semaphore:
            module = self.modules[module_name]
            
            # Check if module requires auth
            if module.requires_auth() and not scan_job.config.auth:
                logger.warning(f"Module {module_name} requires authentication but none provided")
                return ScanResult(
                    module_name=module_name,
                    success=False,
                    started_at=datetime.utcnow(),
                    completed_at=datetime.utcnow(),
                    errors=["Authentication required but not provided"]
                )
            
            # Execute module
            try:
                result = await module.scan(scan_job.config)
                return result
            except asyncio.TimeoutError:
                logger.error(f"Module {module_name} timed out")
                return ScanResult(
                    module_name=module_name,
                    success=False,
                    started_at=datetime.utcnow(),
                    completed_at=datetime.utcnow(),
                    errors=["Module execution timed out"]
                )
            except Exception as e:
                logger.error(f"Module {module_name} error: {str(e)}")
                return ScanResult(
                    module_name=module_name,
                    success=False,
                    started_at=datetime.utcnow(),
                    completed_at=datetime.utcnow(),
                    errors=[str(e)]
                )
    
    def _aggregate_vulnerabilities(self, scan_job: ScanJob):
        """Aggregate and deduplicate vulnerabilities from all modules."""
        all_vulnerabilities = []
        vulnerability_hashes = set()
        
        for module_name, result in scan_job.results.items():
            if result.success:
                for vuln in result.vulnerabilities:
                    # Create a hash for deduplication
                    vuln_hash = f"{vuln.name}:{vuln.severity.value}:{':'.join(vuln.affected_urls)}"
                    
                    if vuln_hash not in vulnerability_hashes:
                        vulnerability_hashes.add(vuln_hash)
                        all_vulnerabilities.append(vuln)
        
        # Sort by severity
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4
        }
        
        all_vulnerabilities.sort(
            key=lambda v: (severity_order.get(v.severity, 5), v.name)
        )
        
        scan_job.vulnerabilities = all_vulnerabilities
    
    async def cancel_scan(self, scan_id: str) -> bool:
        """
        Cancel a running scan.
        
        Args:
            scan_id: Scan job ID
            
        Returns:
            True if cancelled successfully
        """
        if scan_id not in self.active_scans:
            return False
        
        scan_job = self.active_scans[scan_id]
        
        if scan_job.status == ScanStatus.RUNNING:
            scan_job.status = ScanStatus.CANCELLED
            scan_job.completed_at = datetime.utcnow()
            
            # Move to history
            self.scan_history.append(scan_job)
            del self.active_scans[scan_id]
            
            logger.info(f"Scan {scan_id} cancelled")
            return True
        
        return False
    
    def get_scan_status(self, scan_id: str) -> Optional[ScanJob]:
        """Get the status of a scan job."""
        # Check active scans
        if scan_id in self.active_scans:
            return self.active_scans[scan_id]
        
        # Check history
        for scan in self.scan_history:
            if scan.id == scan_id:
                return scan
        
        return None
    
    def get_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get the results of a completed scan."""
        scan_job = self.get_scan_status(scan_id)
        
        if scan_job and scan_job.status == ScanStatus.COMPLETED:
            return {
                'id': scan_job.id,
                'target': scan_job.target,
                'status': scan_job.status.value,
                'started_at': scan_job.started_at.isoformat() if scan_job.started_at else None,
                'completed_at': scan_job.completed_at.isoformat() if scan_job.completed_at else None,
                'duration': str(scan_job.completed_at - scan_job.started_at) if scan_job.completed_at and scan_job.started_at else None,
                'modules_executed': list(scan_job.results.keys()),
                'total_vulnerabilities': len(scan_job.vulnerabilities),
                'vulnerabilities_by_severity': self._count_vulnerabilities_by_severity(scan_job.vulnerabilities),
                'vulnerabilities': [self._vulnerability_to_dict(v) for v in scan_job.vulnerabilities],
                'module_results': {
                    module: {
                        'success': result.success,
                        'vulnerabilities_found': len(result.vulnerabilities),
                        'errors': result.errors,
                        'warnings': result.warnings,
                        'info': result.info,
                        'statistics': result.statistics
                    }
                    for module, result in scan_job.results.items()
                },
                'errors': scan_job.errors,
                'metadata': scan_job.metadata
            }
        
        return None
    
    def _count_vulnerabilities_by_severity(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by severity level."""
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulnerabilities:
            counts[vuln.severity.value] += 1
        
        return counts
    
    def _vulnerability_to_dict(self, vuln: Vulnerability) -> Dict[str, Any]:
        """Convert vulnerability to dictionary."""
        return {
            'id': vuln.id,
            'module': vuln.module,
            'name': vuln.name,
            'description': vuln.description,
            'severity': vuln.severity.value,
            'confidence': vuln.confidence,
            'cvss_score': vuln.cvss_score,
            'cve_ids': vuln.cve_ids,
            'cwe_ids': vuln.cwe_ids,
            'affected_urls': vuln.affected_urls,
            'evidence': vuln.evidence,
            'remediation': vuln.remediation,
            'references': vuln.references,
            'timestamp': vuln.timestamp.isoformat(),
            'false_positive': vuln.false_positive,
            'metadata': vuln.metadata
        }
    
    def get_active_scans(self) -> List[Dict[str, Any]]:
        """Get list of active scans."""
        active = []
        for scan_id, scan_job in self.active_scans.items():
            active.append({
                'id': scan_id,
                'target': scan_job.target,
                'status': scan_job.status.value,
                'progress': scan_job.progress,
                'modules': scan_job.modules,
                'started_at': scan_job.started_at.isoformat() if scan_job.started_at else None
            })
        return active
    
    def get_scan_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get scan history."""
        history = []
        for scan in self.scan_history[-limit:]:
            history.append({
                'id': scan.id,
                'target': scan.target,
                'status': scan.status.value,
                'modules': scan.modules,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'total_vulnerabilities': len(scan.vulnerabilities),
                'vulnerabilities_by_severity': self._count_vulnerabilities_by_severity(scan.vulnerabilities)
            })
        return history
    
    async def shutdown(self):
        """Shutdown the scanner engine."""
        # Cancel all active scans
        for scan_id in list(self.active_scans.keys()):
            await self.cancel_scan(scan_id)
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        logger.info("Scanner engine shutdown complete")

# Create global engine instance
scanner_engine = ScannerEngine()
